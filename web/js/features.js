// features.js
// Parses an uploaded SSH auth-log CSV and turns it into session-level
// feature vectors, mirroring extract_session_features() from the training
// notebook exactly (same 14 columns, same math) so the exported forest.json
// model sees the same inputs it was trained on.
//
// A real uploaded log has NO Session_ID -- unlike the labeled training data,
// production sessions must be reconstructed here with a time-gap rule per
// Source_IP (see SEGMENTATION in the README / plan: "ตัด session ตอน
// production"). The gap threshold is adjustable in the UI because there is
// no single correct value -- too short splits one slow campaign into many
// fragments, too long merges unrelated logins from a shared/NAT IP.

const FEATURE_COLUMNS = [
  "n_events", "n_failed", "n_success", "fail_ratio",
  "n_unique_usernames", "username_entropy", "targets_default_username",
  "n_unique_ports", "duration_seconds",
  "mean_inter_arrival_s", "median_inter_arrival_s", "std_inter_arrival_s", "min_inter_arrival_s",
  "attempts_per_minute",
];

const DEFAULT_USERNAMES = new Set([
  "root", "admin", "test", "guest", "pi", "oracle",
  "ubuntu", "mysql", "postgres", "ftpuser",
]);

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

function shannonEntropy(counts) {
  const total = counts.reduce((a, b) => a + b, 0);
  let h = 0;
  for (const c of counts) {
    const p = c / total;
    h -= p * Math.log2(p);
  }
  return h;
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
 * exceeds `gapMinutes`. This is a judgment call, not ground truth -- see
 * the module docstring above.
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

/** Mirrors extract_session_features() from the training notebook exactly. */
function extractFeatures(session) {
  const rows = [...session.rows].sort((a, b) => a.ts - b.ts);
  const n_events = rows.length;
  const n_failed = rows.filter(r => r.Event === "Failed password").length;
  const n_success = rows.filter(r => r.Event === "Accepted password").length;

  const userCounts = new Map();
  for (const r of rows) userCounts.set(r.Username, (userCounts.get(r.Username) || 0) + 1);
  const n_unique_usernames = userCounts.size;
  const username_entropy = shannonEntropy([...userCounts.values()]);
  const targets_default_username = rows.some(r => DEFAULT_USERNAMES.has(r.Username)) ? 1 : 0;

  const ports = new Set(rows.map(r => r.Source_Port));
  const n_unique_ports = ports.size;

  const duration_seconds = n_events > 0 ? (rows[n_events - 1].ts - rows[0].ts) / 1000 : 0;

  let mean_inter_arrival_s = 0, median_inter_arrival_s = 0, std_inter_arrival_s = 0, min_inter_arrival_s = 0;
  if (n_events > 1) {
    const gaps = [];
    for (let i = 1; i < n_events; i++) gaps.push((rows[i].ts - rows[i - 1].ts) / 1000);
    const sum = gaps.reduce((a, b) => a + b, 0);
    mean_inter_arrival_s = sum / gaps.length;
    const sorted = [...gaps].sort((a, b) => a - b);
    const mid = Math.floor(sorted.length / 2);
    median_inter_arrival_s = sorted.length % 2 ? sorted[mid] : (sorted[mid - 1] + sorted[mid]) / 2;
    const variance = gaps.reduce((a, b) => a + (b - mean_inter_arrival_s) ** 2, 0) / gaps.length;
    std_inter_arrival_s = Math.sqrt(variance);
    min_inter_arrival_s = sorted[0];
  }

  const attempts_per_minute = n_events / ((duration_seconds / 60) + 1e-6);

  return {
    n_events, n_failed, n_success,
    fail_ratio: n_failed / n_events,
    n_unique_usernames, username_entropy, targets_default_username,
    n_unique_ports, duration_seconds,
    mean_inter_arrival_s, median_inter_arrival_s, std_inter_arrival_s, min_inter_arrival_s,
    attempts_per_minute,
  };
}

window.SSHFeatures = { FEATURE_COLUMNS, loadLogRows, segmentSessions, extractFeatures };
