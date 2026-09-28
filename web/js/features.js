// features.js (v3)
// Parses an uploaded SSH auth-log CSV and turns it into session-level
// feature vectors, mirroring extract_features_v3.py exactly: session-level
// features, IP-level cross-session aggregation, and a cross-IP time-window
// feature -- all computed from whatever rows are in THIS uploaded file, so
// a single self-contained CSV (e.g. one IP's full multi-day campaign) is
// enough to exercise every feature, with no external/persistent state
// needed for a demo upload.
//
// Event vocabulary (v3): "Failed password", "Invalid user",
// "Accepted password", "Accepted publickey".
//
// A real uploaded log has NO Session_ID -- sessions are reconstructed here
// with a time-gap rule per Source_IP, same as v2. The gap threshold is
// adjustable in the UI (no single correct value: too short fragments a
// slow campaign, too long merges unrelated logins from a shared/NAT IP).

const FEATURE_COLUMNS = [
  "fail_ratio", "n_failed", "n_success", "invalid_ratio", "publickey_ratio",
  "n_unique_usernames", "targets_default_username", "ends_after_success",
  "duration_seconds", "std_inter_arrival_s", "attempts_per_minute",
  "ip_session_count", "ip_active_span_days", "ip_sessions_per_day", "ip_total_events",
  "distinct_ips_same_target_15min",
];

const DEFAULT_USERNAMES = new Set([
  "root", "admin", "test", "guest", "pi", "oracle",
  "ubuntu", "mysql", "postgres", "ftpuser",
]);

const MIN_DURATION_FOR_RATE = 5.0; // seconds -- floor for attempts_per_minute
const BOTNET_WINDOW_MINUTES = 15;

// --- minimal RFC4180-ish CSV parser (handles quoted fields, no embedded newlines needed here) ---
function parseCSV(text) {
  const lines = text.replace(/\r\n/g, "\n").replace(/\r/g, "\n").split("\n").filter(l => l.length > 0);
  if (lines.length === 0) return { header: [], rows: [] };
  const splitLine = (line) => {
    const out = [];
    let cur = "", inQuotes = false;
    for (let i = 0; i < line.length; i++) {
      const c = line[i];
      if (inQuotes) {
        if (c === '"' && line[i + 1] === '"') { cur += '"'; i++; }
        else if (c === '"') { inQuotes = false; }
        else { cur += c; }
      } else {
        if (c === '"') inQuotes = true;
        else if (c === ",") { out.push(cur); cur = ""; }
        else cur += c;
      }
    }
    out.push(cur);
    return out;
  };
  const header = splitLine(lines[0]).map(h => h.trim());
  const rows = lines.slice(1).map(splitLine);
  return { header, rows };
}

// Parses "YYYY-MM-DD HH:MM:SS.mmm" (and plain ISO strings) into epoch ms.
function parseTimestamp(s) {
  const iso = s.trim().replace(" ", "T");
  const t = Date.parse(iso.includes("T") ? iso : iso + "T00:00:00");
  if (!isNaN(t)) return t;
  const t2 = Date.parse(s);
  return t2;
}

/**
 * Load a raw log CSV into an array of row objects:
 * { ts, Event, Username, Source_IP, Source_Port }
 * Required columns (case-sensitive, matches the training data): Timestamp,
 * Event, Username, Source_IP, Source_Port. Log_ID/Password are ignored if
 * present (Password especially -- it must never reach the model).
 */
function loadLogRows(csvText) {
  const { header, rows } = parseCSV(csvText);
  const idx = (name) => header.indexOf(name);
  const iTs = idx("Timestamp"), iEvent = idx("Event"), iUser = idx("Username"),
        iIp = idx("Source_IP"), iPort = idx("Source_Port");

  const missing = [];
  if (iTs === -1) missing.push("Timestamp");
  if (iEvent === -1) missing.push("Event");
  if (iUser === -1) missing.push("Username");
  if (iIp === -1) missing.push("Source_IP");
  if (iPort === -1) missing.push("Source_Port");
  if (missing.length) {
    throw new Error("CSV is missing required column(s): " + missing.join(", "));
  }

  return rows.map(r => ({
    ts: parseTimestamp(r[iTs]),
    tsRaw: r[iTs],
    Event: r[iEvent],
    Username: r[iUser],
    Source_IP: r[iIp],
    Source_Port: r[iPort],
  })).filter(r => !isNaN(r.ts));
}

/**
 * Production session segmentation: group by Source_IP, sort by time, start
 * a new session whenever the gap since the previous event from that IP
 * exceeds `gapMinutes`.
 */
function segmentSessions(rows, gapMinutes) {
  const gapMs = gapMinutes * 60 * 1000;
  const byIp = new Map();
  for (const r of rows) {
    if (!byIp.has(r.Source_IP)) byIp.set(r.Source_IP, []);
    byIp.get(r.Source_IP).push(r);
  }

  const sessions = [];
  let sessionCounter = 0;
  for (const [ip, ipRows] of byIp.entries()) {
    ipRows.sort((a, b) => a.ts - b.ts);
    let current = [];
    let lastTs = null;
    for (const r of ipRows) {
      if (lastTs !== null && r.ts - lastTs > gapMs) {
        sessions.push({ id: ++sessionCounter, ip, rows: current });
        current = [];
      }
      current.push(r);
      lastTs = r.ts;
    }
    if (current.length) sessions.push({ id: ++sessionCounter, ip, rows: current });
  }
  return sessions;
}

function mostCommon(values) {
  const counts = new Map();
  for (const v of values) counts.set(v, (counts.get(v) || 0) + 1);
  let best = null, bestCount = -1;
  for (const [v, c] of counts.entries()) {
    if (c > bestCount) { best = v; bestCount = c; }
  }
  return best;
}

/** Session-level features. Mirrors extract_session_features() in extract_features_v3.py. */
function extractSessionFeatures(session) {
  const rows = [...session.rows].sort((a, b) => a.ts - b.ts);
  const n_events = rows.length;
  const n_failed = rows.filter(r => r.Event === "Failed password").length;
  const n_invalid = rows.filter(r => r.Event === "Invalid user").length;
  const n_accepted_pw = rows.filter(r => r.Event === "Accepted password").length;
  const n_accepted_key = rows.filter(r => r.Event === "Accepted publickey").length;
  const n_success = n_accepted_pw + n_accepted_key;

  const fail_ratio = n_failed / n_events;
  const invalid_ratio = n_invalid / n_events;
  const publickey_ratio = n_accepted_key / n_events;

  const userCounts = new Map();
  for (const r of rows) userCounts.set(r.Username, (userCounts.get(r.Username) || 0) + 1);
  const n_unique_usernames = userCounts.size;
  const primary_username = mostCommon(rows.map(r => r.Username));
  const targets_default_username = rows.some(r => DEFAULT_USERNAMES.has(r.Username)) ? 1 : 0;

  const session_start = rows[0].ts;
  const session_end = rows[n_events - 1].ts;
  const duration_seconds = (session_end - session_start) / 1000;

  let std_inter_arrival_s = 0;
  if (n_events > 1) {
    const gaps = [];
    for (let i = 1; i < n_events; i++) gaps.push((rows[i].ts - rows[i - 1].ts) / 1000);
    const mean = gaps.reduce((a, b) => a + b, 0) / gaps.length;
    const variance = gaps.reduce((a, b) => a + (b - mean) ** 2, 0) / gaps.length;
    std_inter_arrival_s = Math.sqrt(variance);
  }

  const rate_duration = Math.max(duration_seconds, MIN_DURATION_FOR_RATE);
  const attempts_per_minute = n_events / (rate_duration / 60);

  const last_event = rows[n_events - 1].Event;
  const ends_after_success = (last_event === "Accepted password" || last_event === "Accepted publickey") ? 1 : 0;

  return {
    n_events, n_failed, n_success,
    fail_ratio, invalid_ratio, publickey_ratio,
    n_unique_usernames, primary_username, targets_default_username,
    duration_seconds, std_inter_arrival_s, attempts_per_minute,
    ends_after_success,
    session_start, session_end,
  };
}

/**
 * IP-level features, aggregated across a Source_IP's ENTIRE history in the
 * uploaded file (not just one session) -- catches persistent_multiday and
 * low-and-slow campaigns where each individual session looks small.
 * Mirrors build_ip_features() in extract_features_v3.py.
 */
function buildIpFeatures(rows, sessionsByIp) {
  const byIp = new Map(); // ip -> {total_events, first_seen, last_seen}
  for (const r of rows) {
    if (!byIp.has(r.Source_IP)) byIp.set(r.Source_IP, { total_events: 0, first_seen: Infinity, last_seen: -Infinity });
    const s = byIp.get(r.Source_IP);
    s.total_events += 1;
    if (r.ts < s.first_seen) s.first_seen = r.ts;
    if (r.ts > s.last_seen) s.last_seen = r.ts;
  }
  const result = new Map();
  for (const [ip, stats] of byIp.entries()) {
    const sessionCount = (sessionsByIp.get(ip) || []).length;
    const activeSpanDays = (stats.last_seen - stats.first_seen) / (1000 * 86400);
    const spanFloor = Math.max(activeSpanDays, 1 / 24);
    result.set(ip, {
      ip_session_count: sessionCount,
      ip_active_span_days: activeSpanDays,
      ip_sessions_per_day: sessionCount / spanFloor,
      ip_total_events: stats.total_events,
    });
  }
  return result;
}

/**
 * Cross-IP time-window feature: for each session, count distinct OTHER
 * Source_IPs that had a session targeting the same primary_username with a
 * start time within +/- windowMinutes. Mirrors build_botnet_window_feature()
 * (two-pointer sliding window per username group).
 */
function buildBotnetWindowFeature(sessionFeats, windowMinutes = BOTNET_WINDOW_MINUTES) {
  const windowMs = windowMinutes * 60 * 1000;
  const byUser = new Map();
  sessionFeats.forEach((sf, i) => {
    if (!byUser.has(sf.primary_username)) byUser.set(sf.primary_username, []);
    byUser.get(sf.primary_username).push(i);
  });

  const result = new Array(sessionFeats.length).fill(0);
  for (const indices of byUser.values()) {
    const sorted = [...indices].sort((a, b) => sessionFeats[a].session_start - sessionFeats[b].session_start);
    let left = 0;
    for (let i = 0; i < sorted.length; i++) {
      const t = sessionFeats[sorted[i]].session_start;
      while (sessionFeats[sorted[left]].session_start < t - windowMs) left++;
      let right = i;
      while (right + 1 < sorted.length && sessionFeats[sorted[right + 1]].session_start <= t + windowMs) right++;
      const windowIps = new Set();
      for (let k = left; k <= right; k++) windowIps.add(sessionFeats[sorted[k]].ip);
      windowIps.delete(sessionFeats[sorted[i]].ip);
      result[sorted[i]] = windowIps.size;
    }
  }
  return result;
}

/**
 * Full pipeline: raw rows + segmented sessions -> one feature object per
 * session, ready to feed to SSHModel.featureVector(). Computes session-level,
 * IP-level, and time-window features together (IP-level and time-window need
 * ALL sessions, not just one, so they can't be done per-session in isolation).
 */
function extractAllFeatures(rows, sessions) {
  const sessionFeats = sessions.map(s => ({ ...extractSessionFeatures(s), ip: s.ip }));

  const sessionsByIp = new Map();
  for (const s of sessions) {
    if (!sessionsByIp.has(s.ip)) sessionsByIp.set(s.ip, []);
    sessionsByIp.get(s.ip).push(s);
  }
  const ipFeats = buildIpFeatures(rows, sessionsByIp);
  const botnetFeats = buildBotnetWindowFeature(sessionFeats);

  return sessionFeats.map((sf, i) => {
    const ipf = ipFeats.get(sf.ip) || {
      ip_session_count: 0, ip_active_span_days: 0, ip_sessions_per_day: 0, ip_total_events: 0,
    };
    return {
      ...sf,
      ...ipf,
      distinct_ips_same_target_15min: botnetFeats[i],
    };
  });
}

// Back-compat single-session entry point (not used for scoring anymore --
// IP-level/time-window features need the whole file -- but kept in case
// something calls it directly for a quick look at one session).
function extractFeatures(session) {
  return extractSessionFeatures(session);
}

window.SSHFeatures = {
  FEATURE_COLUMNS, loadLogRows, segmentSessions,
  extractFeatures, extractAllFeatures,
};
