// auth-log.js -- converts a raw OpenSSH server log (sshd lines from
// /var/log/auth.log, /var/log/secure, or `journalctl -u ssh`) into the CSV
// the model expects: Log_ID,Timestamp,Event,Username,Source_IP,Source_Port.
// Runs in the browser; in backend mode only the converted CSV is sent.
//
// Supported line prefixes
//   syslog:  "Oct  6 14:03:21 host sshd[1234]: <message>"   (no year -> see YEAR below)
//   ISO:     "2026-10-06T14:03:21.123456+07:00 host sshd[1234]: <message>"
//            (rsyslog high-precision / `journalctl -o short-iso`); "sshd-session" also accepted
// Supported messages -> Event (one row per authentication attempt)
//   "Accepted password for U from IP port P ..."            -> Accepted password
//   "Accepted publickey for U from IP port P ..."           -> Accepted publickey
//   "Failed password for U from IP port P ..."              -> Failed password
//   "Failed password for invalid user U from IP port P ..." -> Invalid user
//   "Invalid user U from IP port P" with no password try   -> Invalid user (a username probe)
//   "message repeated N times: [ <one of the above> ]"      -> expanded N times
// Everything else (Disconnected, Connection closed, pam_unix, ...) is ignored.
//
// "Invalid user" vs "Failed password for invalid user": sshd logs BOTH for
// the same try. Training data has exactly one "Invalid user" row per
// attempt on a non-existent account, so the probe line is only kept when
// no password attempt from that IP+port follows it.
//
// YEAR: syslog lines carry no year. The current year is assumed; if the
// first month is later than the current month the log is taken to start
// last year, and the year advances when the month wraps (Dec -> Jan).

const AuthLog = (() => {
  const MONTHS = { Jan: 0, Feb: 1, Mar: 2, Apr: 3, May: 4, Jun: 5, Jul: 6, Aug: 7, Sep: 8, Oct: 9, Nov: 10, Dec: 11 };
  const SYSLOG = /^(?:<\d+>)?([A-Z][a-z]{2})\s+(\d{1,2})\s+(\d{2}):(\d{2}):(\d{2})(?:\.(\d+))?\s+\S+\s+sshd(?:-session)?(?:\[\d+\])?:\s+(.*)$/;
  const ISO = /^(?:<\d+>)?(\d{4}-\d{2}-\d{2}[T ]\d{2}:\d{2}:\d{2}(?:[.,]\d+)?)(Z|[+-]\d{2}:?\d{2})?\s+\S+\s+sshd(?:-session)?(?:\[\d+\])?:\s+(.*)$/;
  const REPEATED = /^message repeated (\d+) times:\s*\[\s*(.*?)\s*\]\s*$/;
  // keyboard-interactive/pam is password auth through PAM -> treated as password
  const ACCEPTED = /^Accepted (password|publickey|keyboard-interactive\/pam) for (.*?) from (\S+) port (\d+)/;
  const FAILED = /^Failed (?:password|keyboard-interactive\/pam) for (invalid user )?(.*?) from (\S+) port (\d+)/;
  const INVALID = /^Invalid user (.*?) from (\S+)(?: port (\d+))?\s*$/;
  const CSV_HEADER = /^\s*\S*(Timestamp|Event|Source_IP)\S*\s*,/i;
  // any program's line, e.g. "Oct  6 14:03:21 host CRON[12]: ..." -- an auth.log
  // often starts with many CRON/sudo/pam lines before the first sshd line
  const ANY_SYSLOG = /^(?:<\d+>)?(?:[A-Z][a-z]{2}\s+\d{1,2}\s+\d{2}:\d{2}:\d{2}(?:\.\d+)?|\d{4}-\d{2}-\d{2}[T ]\d{2}:\d{2}:\d{2}\S*)\s+\S+\s+[^\s:]+(?:\[\d+\])?:\s/;

  function looksLikeAuthLog(text) {
    const head = text.replace(/^\uFEFF/, "").slice(0, 50000).split(/\r?\n/).filter(l => l.trim());
    if (!head.length || CSV_HEADER.test(head[0])) return false;
    const sample = head.slice(0, 200);
    return sample.filter(l => ANY_SYSLOG.test(l.trim())).length >= Math.ceil(sample.length / 2);
  }

  function pad(n, w = 2) { return String(n).padStart(w, "0"); }
  function fmt(d) {  // local time WITH its offset: readable and unambiguous across DST
    const off = -d.getTimezoneOffset();
    const zone = `${off >= 0 ? "+" : "-"}${pad(Math.floor(Math.abs(off) / 60))}:${pad(Math.abs(off) % 60)}`;
    return `${d.getFullYear()}-${pad(d.getMonth() + 1)}-${pad(d.getDate())} ` +
      `${pad(d.getHours())}:${pad(d.getMinutes())}:${pad(d.getSeconds())}.${pad(d.getMilliseconds(), 3)}${zone}`;
  }
  function csvField(v) {
    const s = String(v);
    return /[",\r\n]/.test(s) ? `"${s.replace(/"/g, '""')}"` : s;
  }

  function parse(text, now = new Date()) {
    const lines = text.replace(/^\uFEFF/, "").split(/\r?\n/);
    const rows = [];
    const pendingProbe = new Map();  // "ip|port" -> probe row awaiting a password try
    let year = null, prevMonth = null;
    let sshdLines = 0, ignored = 0, total = 0;

    for (const raw of lines) {
      const line = raw.trim();
      if (!line) continue;
      total++;
      let date, msg;
      let m = line.match(ISO);
      if (m) {
        let iso = m[1].replace(" ", "T").replace(",", ".");
        // keep millisecond precision only (Date.parse is strict about digits)
        iso = iso.replace(/(\.\d{3})\d+$/, "$1");
        let zone = m[2] || "";
        if (/^[+-]\d{4}$/.test(zone)) zone = zone.slice(0, 3) + ":" + zone.slice(3);
        date = new Date(Date.parse(iso + zone));
        msg = m[3];
      } else if ((m = line.match(SYSLOG))) {
        const month = MONTHS[m[1]];
        if (month === undefined) { ignored++; continue; }
        if (year === null) year = month > now.getMonth() ? now.getFullYear() - 1 : now.getFullYear();
        else if (prevMonth !== null && month < prevMonth - 6) year++;
        prevMonth = month;
        const ms = m[6] ? Math.floor(+("0." + m[6]) * 1000) : 0;
        date = new Date(year, month, +m[2], +m[3], +m[4], +m[5], ms);
        msg = m[7];
      } else { ignored++; continue; }
      if (isNaN(date.getTime())) { ignored++; continue; }
      sshdLines++;

      let repeat = 1;
      const rep = msg.match(REPEATED);
      if (rep) { repeat = Math.min(+rep[1], 10000); msg = rep[2]; }

      let a;
      if ((a = msg.match(ACCEPTED)) || (a = msg.match(FAILED))) {
        const accepted = a[0].startsWith("Accepted");
        const ev = accepted ? (a[1] === "publickey" ? "Accepted publickey" : "Accepted password")
                            : (a[1] ? "Invalid user" : "Failed password");
        const ip = a[3], port = a[4];
        // the "Invalid user ..." probe line for this same try is a duplicate
        const probe = pendingProbe.get(`${ip}|${port}`) ||
          (!accepted && a[1] ? pendingProbe.get(`${ip}|noport|${a[2]}`) : null);
        if (probe) {
          probe.drop = true;
          pendingProbe.delete(`${ip}|${port}`);
          pendingProbe.delete(`${ip}|noport|${a[2]}`);
        }
        for (let i = 0; i < repeat; i++) rows.push({ date, Event: ev, Username: a[2], Source_IP: ip, Source_Port: port });
      } else if ((a = msg.match(INVALID))) {
        // username probe; kept only if no password try follows on the same IP+port
        const port = a[3] || "";
        for (let i = 0; i < repeat; i++) {
          const probe = { date, Event: "Invalid user", Username: a[1], Source_IP: a[2], Source_Port: port };
          rows.push(probe);
          if (i === 0) pendingProbe.set(port ? `${a[2]}|${port}` : `${a[2]}|noport|${a[1]}`, probe);
        }
      } else {
        ignored++;
      }
    }
    const finalRows = rows.filter(r => !r.drop);
    finalRows.sort((x, y) => x.date - y.date);
    return { rows: finalRows, stats: { totalLines: total, sshdLines, ignoredLines: ignored } };
  }

  function toCsv(text, now) {
    const { rows, stats } = parse(text, now);
    const out = ["Log_ID,Timestamp,Event,Username,Source_IP,Source_Port"];
    rows.forEach((r, i) => {
      out.push([`AUTH_${String(i + 1).padStart(6, "0")}`, fmt(r.date), r.Event, r.Username, r.Source_IP, r.Source_Port].map(csvField).join(","));
    });
    return { csv: out.join("\n") + "\n", rows: rows.length, ignoredLines: stats.ignoredLines, sshdLines: stats.sshdLines };
  }

  return { looksLikeAuthLog, parse, toCsv };
})();

window.AuthLog = AuthLog;
