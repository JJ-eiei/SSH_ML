// log-generator.js -- builds a brand-new SSH auth log in the browser, for
// any mix of the 11 behaviours the model knows, plus a hidden answer key.
//
// The behaviour rules are a line-by-line port of the training data
// generator (v3/generate_v3_dataset.py: counts, timing ranges, success
// rates, username pools), so a generated file is "new data from the same
// world" -- every IP, timestamp, port and attempt count is drawn fresh from
// a seeded random generator, and IPs used by the 10 demo test logs are never
// reused. The CSV handed to the model carries NO labels; the answer key is
// kept in memory (and can be downloaded separately) to grade the result.
//
// Not included: the "ambiguous_attack" pattern (an attack generated to look
// exactly like a user mistyping); it is not one of the model's classes.

const SSHLogGen = (() => {
  const DEFAULT_USERNAMES = ["root", "admin", "test", "guest", "pi", "oracle", "ubuntu", "mysql", "postgres", "ftpuser"];
  const REAL_USERNAMES = [
    "jsmith", "k.wong", "a.patel", "m.garcia", "t.nguyen", "s.johnson",
    "r.kim", "l.chen", "d.brown", "n.suarez", "c.taylor", "p.singh",
    "e.martin", "y.tanaka", "b.davis", "f.rossi", "h.mueller", "v.ivanov",
    "j.lee2", "o.dubois",
  ];

  // IPs that appear in web/test_logs/*.csv and sample-log.csv -- never reused
  const RESERVED_IPS = new Set([
    "100.50.25.111", "102.164.221.39", "108.40.132.165", "11.202.109.180", "110.20.89.195",
    "111.156.196.197", "119.157.96.69", "119.209.126.211", "120.35.244.49", "121.167.98.202",
    "128.17.43.126", "130.94.44.162", "132.173.144.47", "136.7.20.103", "147.252.113.235",
    "149.175.41.111", "15.24.22.93", "152.242.27.231", "160.66.190.92", "164.73.161.91",
    "167.83.19.190", "185.102.123.40", "185.50.97.80", "190.4.172.199", "195.118.244.75",
    "196.113.241.127", "203.222.89.43", "205.119.244.135", "205.23.211.15", "222.31.69.117",
    "228.247.119.221", "23.12.153.234", "231.232.119.90", "232.151.148.213", "235.155.122.161",
    "236.202.50.253", "24.18.6.103", "241.226.98.176", "245.221.243.218", "246.13.155.14",
    "247.199.198.25", "35.146.217.206", "35.50.241.233", "36.155.91.98", "36.229.166.5",
    "48.162.186.221", "55.206.28.87", "59.95.247.97", "60.102.206.76", "61.78.27.185",
    "63.21.68.115", "67.142.60.50", "75.4.171.41", "84.161.122.253", "9.128.78.210",
    "90.186.71.124", "90.24.39.28"
  ]);

  // ---------------------------------------------------------- seeded RNG --
  function makeRng(seed) {
    let a = seed >>> 0;
    const next = () => {  // mulberry32
      a = (a + 0x6D2B79F5) >>> 0;
      let t = a;
      t = Math.imul(t ^ (t >>> 15), t | 1);
      t ^= t + Math.imul(t ^ (t >>> 7), t | 61);
      return ((t ^ (t >>> 14)) >>> 0) / 4294967296;
    };
    const r = {
      random: next,
      randint: (lo, hi) => lo + Math.floor(next() * (hi - lo + 1)),  // inclusive, like Python
      uniform: (lo, hi) => lo + next() * (hi - lo),
      choice: (arr) => arr[Math.floor(next() * arr.length)],
      sample: (arr, k) => {
        const copy = [...arr], out = [];
        while (out.length < k && copy.length) out.push(copy.splice(Math.floor(next() * copy.length), 1)[0]);
        return out;
      },
      weighted: (vals, weights) => {
        const total = weights.reduce((s, w) => s + w, 0);
        let x = next() * total;
        for (let i = 0; i < vals.length; i++) { x -= weights[i]; if (x < 0) return vals[i]; }
        return vals[vals.length - 1];
      },
      exponential: () => -Math.log(1 - next()),
    };
    return r;
  }

  // -------------------------------------------------------------- context --
  function makeContext(seed, start, days) {
    const r = makeRng(seed);
    const used = new Set(RESERVED_IPS);
    const ctx = {
      r, start: start.getTime(), span: Math.floor(days * 86400), rows: [],
      ip() {
        for (;;) {
          const ip = [1, 2, 3, 4].map(() => r.randint(1, 254)).join(".");
          if (!used.has(ip)) { used.add(ip); return ip; }
        }
      },
      port: () => r.randint(49152, 65535),
      at: (offsetSeconds) => ctx.start + offsetSeconds * 1000,
      add(t, event, user, ip, scenario, cls) {
        ctx.rows.push({ t, Event: event, Username: user, Source_IP: ip, Source_Port: ctx.port(), scenario, cls });
      },
    };
    return ctx;
  }

  function dictUsername(r) {
    const letters = "abcdefghijklmnopqrstuvwxyz";
    let base = "";
    const n = r.randint(3, 8);
    for (let i = 0; i < n; i++) base += r.choice(letters);
    if (r.random() < 0.3) base += String(r.randint(1, 99));
    return base;
  }

  // --------------------------------------------- behaviour rules (ported) --
  // Each function adds ONE instance of the pattern to ctx.rows.
  const S = 1000; // ms per second
  const PATTERNS = {
    legit_success(c, cls) {
      const { r } = c; const ip = c.ip(); const user = r.choice(REAL_USERNAMES);
      const t = c.at(r.randint(0, c.span));
      c.add(t, r.random() < 0.35 ? "Accepted publickey" : "Accepted password", user, ip, "legit_success", cls);
    },
    legit_multi_ip_roaming(c, cls) {
      const { r } = c; const user = r.choice(REAL_USERNAMES);
      const nIps = r.randint(2, 4); const windowH = r.uniform(1, 10);
      const t0 = c.at(r.randint(0, c.span));
      for (let i = 0; i < nIps; i++) {
        const ip = c.ip(); const t = t0 + r.uniform(0, windowH * 3600) * S;
        c.add(t, r.random() < 0.4 ? "Accepted publickey" : "Accepted password", user, ip, "legit_multi_ip_roaming", cls);
      }
    },
    legit_typo(c, cls) {
      const { r } = c; const ip = c.ip(); const user = r.choice(REAL_USERNAMES);
      const nFail = r.randint(1, 9); const givesUp = r.random() < 0.12;
      let t = c.at(r.randint(0, c.span));
      for (let i = 0; i < nFail; i++) { c.add(t, "Failed password", user, ip, "legit_typo", cls); t += r.uniform(2, 25) * S; }
      if (!givesUp) c.add(t, "Accepted password", user, ip, "legit_typo", cls);
    },
    ambiguous_legit(c, cls) {
      const { r } = c; const ip = c.ip(); const user = r.choice(REAL_USERNAMES);
      const nFail = r.randint(6, 14);
      let t = c.at(r.randint(0, c.span));
      for (let i = 0; i < nFail; i++) { c.add(t, "Failed password", user, ip, "ambiguous_legit", cls); t += r.uniform(3, 40) * S; }
      if (r.random() < 0.85) c.add(t, "Accepted password", user, ip, "ambiguous_legit", cls);
    },
    shared_ip_legit(c, cls) {
      const { r } = c; const ip = c.ip();
      const users = r.sample(REAL_USERNAMES, r.randint(3, 7));
      let t = c.at(r.randint(0, c.span));
      for (const user of users) {
        if (r.random() < 0.15) { c.add(t, "Failed password", user, ip, "shared_ip_legit", cls); t += r.uniform(2, 15) * S; }
        c.add(t, r.random() < 0.3 ? "Accepted publickey" : "Accepted password", user, ip, "shared_ip_legit", cls);
        t += r.uniform(30, 900) * S;
      }
    },
    burst_bruteforce(c, cls) {
      const { r } = c; const ip = c.ip(); const user = r.choice(DEFAULT_USERNAMES.concat(REAL_USERNAMES));
      const nFail = r.randint(15, 45);
      let t = c.at(r.randint(0, c.span));
      for (let i = 0; i < nFail; i++) { c.add(t, "Failed password", user, ip, "burst_bruteforce", cls); t += r.uniform(0.3, 3) * S; }
      if (r.random() < 0.05) c.add(t, "Accepted password", user, ip, "burst_bruteforce", cls);
    },
    focused_bruteforce(c, cls) {
      const { r } = c; const ip = c.ip();
      const user = r.random() < 0.6 ? r.choice(DEFAULT_USERNAMES) : r.choice(REAL_USERNAMES);
      const nFail = r.randint(6, 40);
      let t = c.at(r.randint(0, c.span));
      for (let i = 0; i < nFail; i++) { c.add(t, "Failed password", user, ip, "focused_bruteforce", cls); t += r.uniform(2, 35) * S; }
      if (r.random() < 0.04) c.add(t, "Accepted password", user, ip, "focused_bruteforce", cls);
    },
    low_and_slow(c, cls) {
      const { r } = c; const ip = c.ip();
      const nTargets = r.weighted([1, 2, 3], [0.7, 0.2, 0.1]);
      const pool = r.random() < 0.55 ? DEFAULT_USERNAMES : REAL_USERNAMES;
      const targets = r.sample(pool, Math.min(nTargets, pool.length));
      const n = r.randint(8, 30); const durH = r.uniform(4, 36); const minGap = 180;
      let t = c.at(r.randint(0, Math.max(c.span - 3600, 0)));
      const raw = Array.from({ length: n - 1 }, () => r.exponential());
      const sum = raw.reduce((s, v) => s + v, 0);
      const gaps = raw.map(v => Math.max(v / sum * (durH * 3600 - minGap * (n - 1)), 0) + minGap);
      const succeeds = r.random() < 0.08;
      for (let i = 0; i < n; i++) {
        const user = r.choice(targets);
        const last = i === n - 1;
        c.add(t, last && succeeds ? "Accepted password" : "Failed password", user, ip, "low_and_slow", cls);
        if (!last) t += gaps[i] * S;
      }
    },
    password_spray(c, cls) {
      const { r } = c;
      const multiIp = r.random() < 0.3;
      const ips = multiIp ? Array.from({ length: r.randint(2, 4) }, () => c.ip()) : [c.ip()];
      const nPasswords = r.randint(1, 3);  // generator: sample(COMMON_WEAK_PASSWORDS, randint(1, 3))
      const targets = r.sample(REAL_USERNAMES, r.randint(6, REAL_USERNAMES.length));
      let t = c.at(r.randint(0, c.span));
      const succeedUser = r.random() < 0.15 ? r.choice(targets) : null;
      for (let p = 0; p < nPasswords; p++) {
        for (const user of targets) {
          const ip = r.choice(ips);
          const ok = user === succeedUser && p === nPasswords - 1;
          c.add(t, ok ? "Accepted password" : "Failed password", user, ip, "password_spray", cls);
          t += r.uniform(20, 300) * S;
        }
      }
    },
    large_dictionary_scanner(c, cls) {
      const { r } = c; const ip = c.ip();
      const n = r.randint(150, 600);
      let t = c.at(r.randint(0, c.span));
      for (let i = 0; i < n; i++) {
        const user = dictUsername(r);
        c.add(t, REAL_USERNAMES.includes(user) ? "Failed password" : "Invalid user", user, ip, "large_dictionary_scanner", cls);
        t += r.uniform(0.1, 2) * S;
      }
    },
    credential_stuffing(c, cls) {
      const { r } = c; const ip = c.ip();
      const targets = r.sample(REAL_USERNAMES, Math.min(r.randint(8, 20), REAL_USERNAMES.length));
      const hitRate = r.uniform(0.2, 0.5);
      let t = c.at(r.randint(0, c.span));
      for (const user of targets) {
        if (r.random() < hitRate) {
          if (r.random() < 0.3) { c.add(t, "Failed password", user, ip, "credential_stuffing", cls); t += r.uniform(1, 10) * S; }
          c.add(t, "Accepted password", user, ip, "credential_stuffing", cls);
        } else {
          c.add(t, "Failed password", user, ip, "credential_stuffing", cls);
        }
        t += r.uniform(5, 60) * S;
      }
    },
    persistent_multiday_attacker(c, cls) {
      const { r } = c; const ip = c.ip();
      const user = r.random() < 0.5 ? r.choice(DEFAULT_USERNAMES) : r.choice(REAL_USERNAMES);
      const nSessions = r.randint(15, 50); const activeDays = r.uniform(5, 25);
      for (let s = 0; s < nSessions; s++) {
        let t = c.start + (r.uniform(0, activeDays) * 86400 + r.randint(0, 86400)) * S;
        const nFail = r.randint(3, 10);
        for (let i = 0; i < nFail; i++) { c.add(t, "Failed password", user, ip, "persistent_multiday_attacker", cls); t += r.uniform(1, 20) * S; }
      }
    },
    coordinated_botnet_spike(c, cls) {
      const { r } = c;
      const target = r.random() < 0.75 ? r.choice(DEFAULT_USERNAMES) : r.choice(REAL_USERNAMES);
      const nBots = r.randint(10, 40); const windowMin = r.uniform(3, 15);
      const spike = c.at(r.randint(0, c.span));
      for (let b = 0; b < nBots; b++) {
        const ip = c.ip();
        let t = spike + r.uniform(0, windowMin * 60) * S;
        const nFail = r.randint(2, 6);
        for (let i = 0; i < nFail; i++) { c.add(t, "Failed password", target, ip, "coordinated_botnet_spike", cls); t += r.uniform(0.5, 5) * S; }
      }
    },
  };

  // Model class -> which generator pattern(s), in the SAME proportion as the
  // training data (e.g. 55 of 675 "legit_login" instances are roaming users).
  const CLASS_SOURCES = {
    legit_login: [["legit_success", 620], ["legit_multi_ip_roaming", 55]],
    legit_typo: [["legit_typo", 480], ["ambiguous_legit", 70]],
    shared_ip_legit: [["shared_ip_legit", 1]],
    burst_bruteforce: [["burst_bruteforce", 1]],
    focused_bruteforce: [["focused_bruteforce", 1]],
    large_dictionary_scanner: [["large_dictionary_scanner", 1]],
    low_and_slow: [["low_and_slow", 1]],
    persistent_multiday_attacker: [["persistent_multiday_attacker", 1]],
    coordinated_botnet_spike: [["coordinated_botnet_spike", 1]],
    password_spray: [["password_spray", 1]],
    credential_stuffing: [["credential_stuffing", 1]],
  };

  const MAX_ROWS = 25000;

  function pad(n, w = 2) { return String(n).padStart(w, "0"); }
  function fmt(ms) {
    const d = new Date(ms);
    const off = -d.getTimezoneOffset();  // e.g. +420 for UTC+07:00
    const zone = `${off >= 0 ? "+" : "-"}${pad(Math.floor(Math.abs(off) / 60))}:${pad(Math.abs(off) % 60)}`;
    return `${d.getFullYear()}-${pad(d.getMonth() + 1)}-${pad(d.getDate())} ` +
      `${pad(d.getHours())}:${pad(d.getMinutes())}:${pad(d.getSeconds())}.${pad(d.getMilliseconds(), 3)}${zone}`;
  }
  function csvField(v) {
    const s = String(v);
    return /[",\r\n]/.test(s) ? `"${s.replace(/"/g, '""')}"` : s;
  }

  /**
   * counts: {modelClass: number of instances}
   * Returns {rows, csv, answerCsv, truth: Map(rowKey -> class), stats}
   */
  function generate({ counts, seed, start, days, maxRows = MAX_ROWS }) {
    const c = makeContext(seed, start, days);
    for (const [cls, n] of Object.entries(counts)) {
      const sources = CLASS_SOURCES[cls];
      if (!sources || !(n > 0)) continue;
      const names = sources.map(s => s[0]), weights = sources.map(s => s[1]);
      for (let i = 0; i < n; i++) {
        PATTERNS[c.r.weighted(names, weights)](c, cls);
        if (c.rows.length > maxRows) throw new Error(`log ใหญ่เกิน ${maxRows.toLocaleString()} บรรทัด — ลดจำนวนลง`);
      }
    }
    if (!c.rows.length) throw new Error("ยังไม่ได้เลือกสถานการณ์");
    // sub-millisecond precision is not kept, so round once here and use the
    // SAME value for the CSV text and the answer key
    c.rows.forEach(row => { row.t = Math.round(row.t); });
    c.rows.sort((a, b) => a.t - b.t);

    const header = "Log_ID,Timestamp,Event,Username,Source_IP,Source_Port";
    const lines = [header], answer = ["Log_ID,Timestamp,Source_IP,Source_Port,True_Class,Group,Scenario"];
    const truth = new Map();
    c.rows.forEach((row, i) => {
      const id = `GEN_${pad(i + 1, 6)}`;
      const ts = fmt(row.t);
      lines.push([id, ts, row.Event, row.Username, row.Source_IP, row.Source_Port].map(csvField).join(","));
      const group = (window.describeClass ? describeClass(row.cls).group : "");
      answer.push([id, ts, row.Source_IP, row.Source_Port, row.cls, group, row.scenario].map(csvField).join(","));
      truth.set(`${row.Source_IP}|${row.Source_Port}|${row.t}`, row.cls);
    });
    const ips = new Set(c.rows.map(r => r.Source_IP));
    return {
      rows: c.rows, truth,
      csv: lines.join("\n") + "\n",
      answerCsv: answer.join("\n") + "\n",
      stats: { rows: c.rows.length, ips: ips.size, from: fmt(c.rows[0].t).slice(0, 16), to: fmt(c.rows[c.rows.length - 1].t).slice(0, 16) },
    };
  }

  return { generate, CLASS_SOURCES, RESERVED_IPS, makeRng };
})();

window.SSHLogGen = SSHLogGen;
