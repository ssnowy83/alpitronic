require("dotenv").config();
const express = require("express");
const path = require("path");
const os = require("os");
const crypto = require("crypto");

const app = express();

const PORT = process.env.PORT || 8080;

const CONFIG = {
  tokenUrl:     process.env.OAUTH_TOKEN_URL || "https://middleware.alpitronic.it/dw/register/oauth/token",
  reportP1Url:  process.env.REPORT_P1_URL   || "https://middleware.alpitronic.it/dw/trigger/getreportP1",
  // P2/P3 URLs follow the same corrected pattern as P1 — still unconfirmed with IT, override via .env if different
  reportP2Url:  process.env.REPORT_P2_URL   || "https://middleware.alpitronic.it/dw/trigger/getreportP2",
  reportP3Url:  process.env.REPORT_P3_URL   || "https://middleware.alpitronic.it/dw/trigger/getreportP3",
  clientId:     process.env.CLIENT_ID,
  clientSecret: process.env.CLIENT_SECRET,
  // AWS Connect queue metrics Lambda — now behind Basic Auth (was public, IT flagged it)
  connectMetricsUrl:  process.env.CONNECT_METRICS_URL || "https://4qubmtly7tigme7baz6qzdzhx40cxoim.lambda-url.eu-north-1.on.aws/",
  connectBasicAuthUser: process.env.CONNECT_BASIC_AUTH_USER,
  connectBasicAuthPass: process.env.CONNECT_BASIC_AUTH_PASS
};

// Server-side cache shared by every browser connected to this relay.
// The dashboard still polls at its normal intervals, but requests received
// while the relevant value is cached are served locally and do not trigger a
// new OAuth/API call. Values can be overridden in .env if needed.
const CACHE_TTL_MS = {
  reportP1: Number(process.env.REPORT_P1_CACHE_SECONDS || 900) * 1000,   // 15 min
  reportP2: Number(process.env.REPORT_P2_CACHE_SECONDS || 3600) * 1000,  // 60 min
  reportP3: Number(process.env.REPORT_P3_CACHE_SECONDS || 14400) * 1000, // 4 h
  connect:  Number(process.env.CONNECT_CACHE_SECONDS  || 20) * 1000     // 20 sec
};

// Diagnostic timeout for OAuth and upstream report calls. Override in .env
// when the middleware needs longer than the default two minutes.
const UPSTREAM_TIMEOUT_MS = Number(process.env.UPSTREAM_TIMEOUT_SECONDS || 120) * 1000;
const LOBSTER_DEBUG_TIMEOUT_MS = Number(process.env.LOBSTER_DEBUG_TIMEOUT_SECONDS || 120) * 1000;

const responseCache = new Map();
let dashboardRevision = 0;
const sseClients = new Set();

function sendSseEvent(res, eventName, payload) {
  if (res.destroyed || res.writableEnded) return false;
  try {
    res.write(`event: ${eventName}\n`);
    res.write(`data: ${JSON.stringify(payload)}\n\n`);
    return true;
  } catch (err) {
    return false;
  }
}

function dashboardCacheState() {
  const cache = {};
  for (const [key, entry] of responseCache.entries()) {
    if (!entry || entry.value === undefined) continue;
    cache[key] = {
      updatedAt: new Date(entry.fetchedAt).toISOString(),
      expiresAt: new Date(entry.expiresAt).toISOString(),
      revision: entry.revision || 0
    };
  }
  return cache;
}

function broadcastDashboardUpdate(key, entry) {
  dashboardRevision += 1;
  const payload = {
    type: "snapshot-updated",
    revision: dashboardRevision,
    key,
    updatedAt: new Date(entry.fetchedAt).toISOString(),
    cacheExpiresAt: new Date(entry.expiresAt).toISOString()
  };

  for (const client of sseClients) {
    if (!sendSseEvent(client, "snapshot-updated", payload)) {
      sseClients.delete(client);
    }
  }
}

/*
   Single-flight cache:
   - A fresh cached value is returned without calling the upstream API.
   - If several browsers request an expired value at the same time, only the
     first request calls upstream; the others wait for the same promise.
*/
async function getCachedValue(key, ttlMs, loader) {
  const existing = responseCache.get(key);
  const now = Date.now();

  // A cache entry is considered fresh only by its absolute expiry time. This
  // makes the decision unambiguous even while another request is refreshing
  // the same key.
  if (existing && existing.value !== undefined && now < existing.expiresAt) {
    return {
      value: existing.value,
      fetchedAt: existing.fetchedAt,
      expiresAt: existing.expiresAt,
      revision: existing.revision || 0,
      fromCache: true
    };
  }

  // Single-flight refresh: every browser that arrives during the same refresh
  // receives the exact same completed snapshot.
  if (existing && existing.inFlight) {
    return existing.inFlight;
  }

  const previousValue = existing && existing.value !== undefined ? existing.value : undefined;
  const previousFetchedAt = existing ? existing.fetchedAt : undefined;

  const inFlight = Promise.resolve()
    .then(loader)
    .then((value) => {
      const fetchedAt = Date.now();
      const expiresAt = fetchedAt + ttlMs;
      const result = { value, fetchedAt, expiresAt, revision: dashboardRevision + 1 };
      responseCache.set(key, result);
      broadcastDashboardUpdate(key, result);
      return { ...result, fromCache: false };
    })
    .catch((err) => {
      // Preserve the previous value for diagnostics, but force the next
      // request to retry instead of treating the stale value as fresh.
      if (previousValue !== undefined) {
        responseCache.set(key, {
          value: previousValue,
          fetchedAt: previousFetchedAt,
          expiresAt: 0,
          revision: existing.revision || 0
        });
      } else {
        responseCache.delete(key);
      }
      throw err;
    });

  responseCache.set(key, {
    ...(existing || {}),
    inFlight
  });

  return inFlight;
}

if (!CONFIG.clientId || !CONFIG.clientSecret) {
  console.warn(
    "[WARN] CLIENT_ID / CLIENT_SECRET are not set. Copy .env.example to .env and fill them in."
  );
}

if (!CONFIG.connectBasicAuthUser || !CONFIG.connectBasicAuthPass) {
  console.warn(
    "[WARN] CONNECT_BASIC_AUTH_USER / CONNECT_BASIC_AUTH_PASS are not set. " +
    "The AWS Connect metrics call will be sent without credentials and will " +
    "get a 401 once the Lambda's Basic Auth is deployed."
  );
}

/* ---------------------------------------------------------
   OAuth: get a fresh token for every call (no caching/reuse —
   requested explicitly, since the API expects a new token per request)
--------------------------------------------------------- */
async function fetchWithTimeout(url, options, timeoutMs) {
  const controller = new AbortController();
  const timer = setTimeout(() => controller.abort(), timeoutMs);

  try {
    return await fetch(url, {
      ...options,
      signal: controller.signal
    });
  } catch (err) {
    if (controller.signal.aborted) {
      const timeoutError = new Error(`Request timed out after ${timeoutMs} ms: ${url}`);
      timeoutError.code = "UPSTREAM_TIMEOUT";
      timeoutError.cause = err;
      throw timeoutError;
    }
    throw err;
  } finally {
    clearTimeout(timer);
  }
}

async function getAccessToken({ timeoutMs = UPSTREAM_TIMEOUT_MS } = {}) {
  const body = new URLSearchParams({
    grant_type: "client_credentials",
    client_id: CONFIG.clientId,
    client_secret: CONFIG.clientSecret
  });

  const res = await fetchWithTimeout(CONFIG.tokenUrl, {
    method: "POST",
    headers: { "Content-Type": "application/x-www-form-urlencoded" },
    body: body.toString()
  }, timeoutMs);

  if (!res.ok) {
    const text = await res.text().catch(() => "");
    throw new Error(`OAuth token request failed: HTTP ${res.status} ${text}`);
  }

  const data = await res.json();
  return data.access_token;
}

/* ---------------------------------------------------------
   Serialize token+report calls. The middleware appears to only allow one
   active token per client credential — issuing a new token invalidates
   the previous one. Since P1/P2/P3 can be requested by the dashboard at
   nearly the same instant, running them concurrently means an earlier
   token can get invalidated by a later one before its report call
   finishes (symptom: some reports 401 "authorization required", one
   succeeds — whichever finished last). This queue guarantees each
   get-token-then-fetch-report sequence fully completes before the next
   one starts, so tokens are never stepped on.
--------------------------------------------------------- */
let authQueue = Promise.resolve();
function runExclusive(fn) {
  const run = authQueue.then(fn, fn);
  authQueue = run.then(() => {}, () => {}); // keep the chain alive even if fn() rejects
  return run;
}

/* ---------------------------------------------------------
   CSV parsing

   Two schemas now, per the API's current shape:

   P1 / P2: CaseNumber, SLA, TargetDate, Account
     -> remaining time is computed here from TargetDate vs "now" (the
        moment the request is served), formatted as "M:00" so the
        front-end's existing minutes-based bucket logic (P1) keeps working
        unchanged. P2 doesn't use that string, it uses the raw targetDate
        directly (to find the oldest case per tier), so it's included too.

   P3: CaseNumber, SLA, Account, CreatedDate, Type
     -> deduplicated by CaseNumber (the source has repeated rows), and
        ageDays is computed here (CreatedDate vs "now") for convenience.
--------------------------------------------------------- */
function normalizeHeaderCell(cell) {
  return (cell || "").toLowerCase().replace(/[^a-z0-9]/g, "");
}

function parseDateSafe(str) {
  if (!str) return null;
  const d = new Date(str);
  return isNaN(d.getTime()) ? null : d;
}

function splitHeaderAndRows(csvText, classifyFn, expectedShapeLabel, reportLabel) {
  const lines = csvText
    .split(/\r?\n/)
    .map((l) => l.trim())
    .filter(Boolean);

  if (!lines.length) return { columnMap: {}, hasHeader: false, dataLines: [] };

  const headerCells = lines[0].split(",").map((h) => h.trim());
  const columnMap = {};

  headerCells.forEach((cell, i) => {
    const field = classifyFn(normalizeHeaderCell(cell));
    if (field && columnMap[field] === undefined) {
      columnMap[field] = i;
    }
  });

  const hasHeader = columnMap.caseNumber !== undefined;

  if (!hasHeader) {
    console.warn(
      `[${reportLabel}] First line doesn't look like a recognizable header ` +
      `(no case-number-like column found) — expected columns: ${expectedShapeLabel}. ` +
      `Check /raw to see the actual response.`
    );
  }

  return { columnMap, hasHeader, dataLines: hasHeader ? lines.slice(1) : lines };
}

// Checked in this order on purpose: "sla" before the generic "case" check,
// since a header like "SMAX_CaseSLA__c" contains "case" too.
function classifyTargetDateHeader(normalized) {
  if (normalized.includes("sla")) return "sla";
  if (normalized.includes("account")) return "accountNumber";
  if (normalized.includes("target") || normalized.includes("date")) return "targetDate";
  if (normalized.includes("case")) return "caseNumber";
  return null;
}

function parseTargetDateCsv(csvText, reportLabel, { excludeNonPositiveRemaining = false } = {}) {
  const { columnMap, hasHeader, dataLines } = splitHeaderAndRows(
    csvText, classifyTargetDateHeader, "CaseNumber, SLA, TargetDate, Account", reportLabel
  );

  const now = Date.now();
  const rows = [];
  let excludedCount = 0;

  for (const line of dataLines) {
    const parts = line.split(",");
    const get = (field, fallbackIdx) => {
      const idx = hasHeader ? columnMap[field] : fallbackIdx;
      return (idx !== undefined ? parts[idx] : "") ?? "";
    };

    const caseNumber = get("caseNumber", 0).trim();
    if (!caseNumber) continue;

    const sla = get("sla", 1).trim();
    const targetDateRaw = get("targetDate", 2).trim();
    const accountNumber = get("accountNumber", 3).trim();

    const targetDate = parseDateSafe(targetDateRaw);
    let rawMinutes = null;
    let timeRemaining = null;

    if (targetDate) {
      rawMinutes = (targetDate.getTime() - now) / 60000;
      const clamped = Math.max(0, Math.round(rawMinutes));
      timeRemaining = `${clamped}:00`;
    }

    // Only skip rows we could actually evaluate (rawMinutes !== null) — an
    // unparseable/missing target date isn't the same as "0 or below", so
    // those still pass through with timeRemaining: null, same as before.
    if (excludeNonPositiveRemaining && rawMinutes !== null && rawMinutes <= 0) {
      excludedCount++;
      continue;
    }

    rows.push({
      caseNumber,
      sla,
      accountNumber,
      targetDate: targetDate ? targetDate.toISOString() : null,
      timeRemaining
    });
  }

  if (excludedCount > 0) {
    console.log(`[${reportLabel}] excluded ${excludedCount} row(s) with time remaining at or below 0`);
  }

  return rows;
}

function classifyBacklogHeader(normalized) {
  if (normalized.includes("sla")) return "sla";
  if (normalized.includes("account")) return "accountNumber";
  if (normalized.includes("created") || normalized.includes("date")) return "createdDate";
  if (normalized.includes("type")) return "type";
  if (normalized.includes("case")) return "caseNumber";
  return null;
}

function parseBacklogCsv(csvText, reportLabel) {
  const { columnMap, hasHeader, dataLines } = splitHeaderAndRows(
    csvText, classifyBacklogHeader, "CaseNumber, SLA, Account, CreatedDate, Type", reportLabel
  );

  const now = Date.now();
  const seenCaseNumbers = new Set();
  const rows = [];
  let duplicateCount = 0;

  for (const line of dataLines) {
    const parts = line.split(",");
    const get = (field, fallbackIdx) => {
      const idx = hasHeader ? columnMap[field] : fallbackIdx;
      return (idx !== undefined ? parts[idx] : "") ?? "";
    };

    const caseNumber = get("caseNumber", 0).trim();
    if (!caseNumber) continue;

    if (seenCaseNumbers.has(caseNumber)) {
      duplicateCount++;
      continue; // dedupe: keep only the first occurrence of each case number
    }
    seenCaseNumbers.add(caseNumber);

    const sla = get("sla", 1).trim();
    const accountNumber = get("accountNumber", 2).trim();
    const createdDateRaw = get("createdDate", 3).trim();
    const type = get("type", 4).trim() || "Other";

    const createdDate = parseDateSafe(createdDateRaw);
    const ageDays = createdDate
      ? Math.round(((now - createdDate.getTime()) / 86400000) * 10) / 10
      : null;

    rows.push({
      caseNumber,
      sla,
      accountNumber,
      createdDate: createdDate ? createdDate.toISOString() : null,
      type,
      ageDays
    });
  }

  if (duplicateCount > 0) {
    console.log(`[${reportLabel}] deduplicated ${duplicateCount} repeated row(s) by case number`);
  }

  return rows;
}

/* ---------------------------------------------------------
   Generic report fetch: get a fresh token, GET the raw CSV text.
   Runs inside runExclusive() so token issuance + its report call
   never overlap with another report's token issuance.
--------------------------------------------------------- */
async function fetchReportResponse(reportUrl, reportLabel, {
  noCache = false,
  timeoutMs = UPSTREAM_TIMEOUT_MS
} = {}) {
  return runExclusive(async () => {
    const startedAtMs = Date.now();
    const diagnostic = {
      reportLabel,
      requestUrl: reportUrl,
      requestStartedAt: new Date(startedAtMs).toISOString(),
      timeoutMs,
      noCache,
      requestHeaders: {
        "Content-Type": "text/csv",
        ...(noCache ? { "Cache-Control": "no-cache", Pragma: "no-cache" } : {})
      }
    };

    try {
      const oauthStartedAtMs = Date.now();
      const token = await getAccessToken({ timeoutMs });
      diagnostic.oauthMs = Date.now() - oauthStartedAtMs;

      const reportStartedAtMs = Date.now();
      const headers = {
        Authorization: `Bearer ${token}`,
        "Content-Type": "text/csv"
      };
      if (noCache) {
        headers["Cache-Control"] = "no-cache";
        headers.Pragma = "no-cache";
      }

      const reportRes = await fetchWithTimeout(reportUrl, { headers }, timeoutMs);
      diagnostic.httpStatus = reportRes.status;
      diagnostic.httpStatusText = reportRes.statusText;
      diagnostic.reportRequestMs = Date.now() - reportStartedAtMs;
      diagnostic.responseHeaders = Object.fromEntries(reportRes.headers.entries());

      const bodyStartedAtMs = Date.now();
      const bodyBuffer = Buffer.from(await reportRes.arrayBuffer());
      const bodyText = bodyBuffer.toString("utf8");
      diagnostic.bodyReadMs = Date.now() - bodyStartedAtMs;
      diagnostic.bodyBytes = bodyBuffer.length;
      diagnostic.bodyCharacters = bodyText.length;
      diagnostic.bodyLineCount = bodyText ? bodyText.split(/\r?\n/).length : 0;
      diagnostic.bodyStartsWith = bodyText.slice(0, 200);
      diagnostic.bodyEndsWith = bodyText.slice(-500);
      diagnostic.bodyEndsWithNewline = /\r?\n$/.test(bodyText);
      diagnostic.bodySha256 = crypto.createHash("sha256").update(bodyBuffer).digest("hex");
      diagnostic.contentLengthHeader = reportRes.headers.get("content-length");
      diagnostic.contentEncoding = reportRes.headers.get("content-encoding");

      const declaredLength = diagnostic.contentLengthHeader
        ? Number(diagnostic.contentLengthHeader)
        : null;
      diagnostic.contentLengthMatches = Number.isFinite(declaredLength) && !diagnostic.contentEncoding
        ? declaredLength === diagnostic.bodyBytes
        : null;
      diagnostic.totalMs = Date.now() - startedAtMs;
      diagnostic.completedAt = new Date().toISOString();

      return {
        ...diagnostic,
        ok: reportRes.ok,
        status: reportRes.status,
        statusText: reportRes.statusText,
        headers: diagnostic.responseHeaders,
        bodyText
      };
    } catch (err) {
      diagnostic.totalMs = Date.now() - startedAtMs;
      diagnostic.completedAt = new Date().toISOString();
      diagnostic.errorCode = err.code || err.name || "UNKNOWN_ERROR";
      diagnostic.errorMessage = err.message;
      err.debug = diagnostic;
      throw err;
    }
  });
}

async function fetchReportCsvText(reportUrl, reportLabel) {
  const report = await fetchReportResponse(reportUrl, reportLabel);
  if (!report.ok) {
    throw new Error(`${reportLabel} request failed: HTTP ${report.status} ${report.bodyText}`);
  }
  return report.bodyText;
}

function reportCacheTtl(reportLabel) {
  return {
    "Report P1": CACHE_TTL_MS.reportP1,
    "Report P2": CACHE_TTL_MS.reportP2,
    "Report P3": CACHE_TTL_MS.reportP3
  }[reportLabel];
}

// Cache one complete report snapshot — raw CSV and parsed rows together — so
// every browser sees identical rows, counts and derived values until the
// server refreshes the upstream report again.
function getReportSnapshot(reportUrl, reportLabel, parseFn) {
  return getCachedValue(
    `report:${reportLabel}`,
    reportCacheTtl(reportLabel),
    async () => {
      const csvText = await fetchReportCsvText(reportUrl, reportLabel);
      return {
        csvText,
        rows: parseFn(csvText, reportLabel)
      };
    }
  );
}

function setNoStoreHeaders(res) {
  res.set({
    "Cache-Control": "no-store, no-cache, must-revalidate, proxy-revalidate",
    "Pragma": "no-cache",
    "Expires": "0"
  });
}

function makeReportRoute(reportUrl, reportLabel, parseFn) {
  return async (req, res) => {
    try {
      const cached = await getReportSnapshot(reportUrl, reportLabel, parseFn);
      const { rows } = cached.value;

      // Quick visibility into what the API is actually sending, without
      // needing a separate request — useful whenever the format changes.
      if (!cached.fromCache) {
        const firstLines = cached.value.csvText.split(/\r?\n/).filter(Boolean).slice(0, 2);
        console.log(`[${reportLabel}] first line(s) of raw response:`, firstLines);
      }

      setNoStoreHeaders(res);
      res.json({
        updatedAt: new Date(cached.fetchedAt).toISOString(),
        cacheExpiresAt: new Date(cached.expiresAt).toISOString(),
        servedAt: new Date().toISOString(),
        snapshotRevision: cached.revision,
        fromCache: cached.fromCache,
        count: rows.length,
        rows
      });
    } catch (err) {
      console.error(`[${reportLabel}]`, err.message);
      if (err.cause) console.error(`[${reportLabel}] cause:`, err.cause);
      res.status(502).json({ error: `Failed to fetch ${reportLabel}. See server logs for details.` });
    }
  };
}

// Debug route: returns the untouched CSV text exactly as the API sent it,
// no parsing applied — open this directly in a browser to inspect the real
// current format (header names, column order, etc.) at a glance.
function makeRawReportRoute(reportUrl, reportLabel, parseFn) {
  return async (req, res) => {
    try {
      const cached = await getReportSnapshot(reportUrl, reportLabel, parseFn);
      setNoStoreHeaders(res);
      res.set("Content-Type", "text/plain; charset=utf-8").send(cached.value.csvText);
    } catch (err) {
      console.error(`[${reportLabel} raw]`, err.message);
      if (err.cause) console.error(`[${reportLabel} raw] cause:`, err.cause);
      res.status(502).send(`Failed to fetch ${reportLabel}. See server logs for details.`);
    }
  };
}

// Live diagnostic route: performs a new OAuth + upstream report request every
// time and returns the untouched CSV body. It deliberately bypasses the
// report cache and does not parse or store the response.
function makeLiveRawReportRoute(reportUrl, reportLabel) {
  return async (req, res) => {
    try {
      const upstream = await fetchReportResponse(reportUrl, reportLabel, {
        noCache: true,
        timeoutMs: LOBSTER_DEBUG_TIMEOUT_MS
      });

      const { bodyText, ...diagnostic } = upstream;
      console.log(`[${reportLabel} live raw] upstream diagnostics:`, diagnostic);

      setNoStoreHeaders(res);
      if (upstream.headers["content-type"]) {
        res.set("Content-Type", upstream.headers["content-type"]);
      } else {
        res.set("Content-Type", "text/plain; charset=utf-8");
      }
      res.status(upstream.status).send(bodyText);
    } catch (err) {
      console.error(`[${reportLabel} live raw]`, err.message);
      if (err.debug) console.error(`[${reportLabel} live raw] debug:`, err.debug);
      if (err.cause) console.error(`[${reportLabel} live raw] cause:`, err.cause);
      setNoStoreHeaders(res);
      res.status(502).json({
        error: `Failed to fetch ${reportLabel}.`,
        details: err.message,
        debug: err.debug || null
      });
    }
  };
}

// JSON diagnostic route: exposes the upstream HTTP response metadata and the
// exact body received from Lobster. Use ?body=0 when only metadata is needed.
function makeLobsterDebugRoute(reportUrl, reportLabel) {
  return async (req, res) => {
    const includeBody = req.query.body !== "0" && req.query.body !== "false";

    try {
      const upstream = await fetchReportResponse(reportUrl, reportLabel, {
        noCache: true,
        timeoutMs: LOBSTER_DEBUG_TIMEOUT_MS
      });

      const { bodyText, ...diagnostic } = upstream;
      console.log(`[${reportLabel} debug] upstream diagnostics:`, diagnostic);

      setNoStoreHeaders(res);
      res.json({
        ok: upstream.ok,
        upstream: diagnostic,
        body: includeBody ? bodyText : undefined
      });
    } catch (err) {
      console.error(`[${reportLabel} debug]`, err.message);
      if (err.debug) console.error(`[${reportLabel} debug] details:`, err.debug);
      if (err.cause) console.error(`[${reportLabel} debug] cause:`, err.cause);

      setNoStoreHeaders(res);
      res.status(502).json({
        ok: false,
        error: err.message,
        upstream: err.debug || null
      });
    }
  };
}

/* ---------------------------------------------------------
   Routes
--------------------------------------------------------- */
// Server-Sent Events channel. Every dashboard screen receives the same
// cache-update notification and can refresh its local widgets together.
app.get("/api/dashboard/events", (req, res) => {
  res.status(200).set({
    "Content-Type": "text/event-stream; charset=utf-8",
    "Cache-Control": "no-cache, no-transform",
    "Connection": "keep-alive",
    "X-Accel-Buffering": "no"
  });
  res.flushHeaders();

  res.write(": dashboard SSE connected\n\n");
  sendSseEvent(res, "dashboard-state", {
    type: "dashboard-state",
    revision: dashboardRevision,
    cache: dashboardCacheState()
  });

  sseClients.add(res);
  const keepAlive = setInterval(() => {
    if (!sendSseEvent(res, "keep-alive", { time: new Date().toISOString() })) {
      clearInterval(keepAlive);
      sseClients.delete(res);
    }
  }, 25000);

  req.on("close", () => {
    clearInterval(keepAlive);
    sseClients.delete(res);
  });
});

app.get("/api/report/p1", makeReportRoute(
  CONFIG.reportP1Url,
  "Report P1",
  (csvText, reportLabel) => parseTargetDateCsv(csvText, reportLabel, { excludeNonPositiveRemaining: true })
));
app.get("/api/report/p2", makeReportRoute(CONFIG.reportP2Url, "Report P2", parseTargetDateCsv));
app.get("/api/report/p3", makeReportRoute(CONFIG.reportP3Url, "Report P3", parseBacklogCsv));

// Debug: raw untouched CSV, no parsing — e.g. http://localhost:8080/api/report/p1/raw
app.get("/api/report/p1/raw", makeRawReportRoute(
  CONFIG.reportP1Url,
  "Report P1",
  (csvText, reportLabel) => parseTargetDateCsv(csvText, reportLabel, { excludeNonPositiveRemaining: true })
));
app.get("/api/report/p2/raw", makeRawReportRoute(CONFIG.reportP2Url, "Report P2", parseTargetDateCsv));
app.get("/api/report/p3/raw", makeRawReportRoute(CONFIG.reportP3Url, "Report P3", parseBacklogCsv));

// Live, uncached, unparsed upstream response for diagnostics.
app.get("/api/report/p3/raw/live", makeLiveRawReportRoute(CONFIG.reportP3Url, "Report P3"));

// Detailed Lobster call diagnostics: status, headers, timings, byte counts,
// SHA-256, previews and the exact received body.
app.get("/api/report/p3/debug/lobster", makeLobsterDebugRoute(CONFIG.reportP3Url, "Report P3"));

app.get("/api/connect/status", async (req, res) => {
  try {
    const cached = await getCachedValue("connect:status", CACHE_TTL_MS.connect, async () => {
      const headers = {};
      if (CONFIG.connectBasicAuthUser && CONFIG.connectBasicAuthPass) {
        const encoded = Buffer.from(`${CONFIG.connectBasicAuthUser}:${CONFIG.connectBasicAuthPass}`).toString("base64");
        headers.Authorization = `Basic ${encoded}`;
      }

      const r = await fetch(CONFIG.connectMetricsUrl, { headers });
      if (!r.ok) {
        const text = await r.text().catch(() => "");
        throw new Error(`AWS Connect metrics request failed: HTTP ${r.status} ${text}`);
      }
      return r.json();
    });

    setNoStoreHeaders(res);
    res.json({
      ...cached.value,
      snapshotRevision: cached.revision,
      relayUpdatedAt: new Date(cached.fetchedAt).toISOString()
    });
  } catch (err) {
    console.error("[AWS Connect metrics]", err.message);
    if (err.cause) console.error("[AWS Connect metrics] cause:", err.cause);
    res.status(502).json({ error: "Failed to fetch AWS Connect metrics. See server logs for details." });
  }
});

app.get("/api/health", (req, res) => {
  res.json({ ok: true, time: new Date().toISOString() });
});

// Serve the dashboard itself, same-origin as the API — avoids CORS entirely
app.use(express.static(path.join(__dirname, "public")));

app.listen(PORT, "127.0.0.1", () => {
  console.log(`Dashboard relay server listening on http://localhost:${PORT}`);

  // Print LAN-reachable addresses too, so it's obvious what URL to use
  // from another PC on the same network (assuming the firewall allows it —
  // see README for the Windows Firewall rule needed).
  const nets = os.networkInterfaces();
  for (const name of Object.keys(nets)) {
    for (const net of nets[name]) {
      if (net.family === "IPv4" && !net.internal) {
        console.log(`  also reachable on this network at: http://${net.address}:${PORT}`);
      }
    }
  }
});
