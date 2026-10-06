// live-console.js -- "Live Attack Console": a fake SSH terminal the user
// (or a canned preset) types password guesses into, so they can watch the
// model's risk score and behaviour label move in real time. Entirely client-side, entirely
// simulated -- there is no real server, no real authentication, nothing is
// sent anywhere. Every attempt just appends a row to an in-memory log in
// the exact schema the model expects, then re-scores it through the SAME
// SSHFeatures/SSHModel pipeline used for uploaded files.
//
// Two clocks matter here and must not be confused:
//   - the ANIMATION clock (setTimeout delays) -- how fast lines appear on
//     screen, purely for watchability.
//   - the LOGGED timestamp on each row -- the synthetic time the event
//     "really" happened at, which is what feature extraction sees. Preset
//     playback reveals lines fast (90 ms each) but logs them with the SAME
//     inter-arrival ranges, attempt counts and success rates the training
//     generator uses for that pattern (v3/generate_v3_dataset.py), so the
//     model sees a session shaped like the ones it learned from. Logged time
//     costs nothing on screen, so there is no reason to compress it (an
//     earlier version did, which made Spray/Stuffing look unlike anything in
//     training and score as legit).

(() => {
  const HINT_AFTER_FAILS = 8;
  const DEFAULT_USERNAMES = ["root", "admin", "test", "guest", "pi", "oracle", "ubuntu", "mysql", "postgres", "ftpuser"];
  // same lists as the training generator (v3/generate_v3_dataset.py)
  const REAL_USERNAMES = [
    "jsmith", "k.wong", "a.patel", "m.garcia", "t.nguyen", "s.johnson",
    "r.kim", "l.chen", "d.brown", "n.suarez", "c.taylor", "p.singh",
    "e.martin", "y.tanaka", "b.davis", "f.rossi", "h.mueller", "v.ivanov",
    "j.lee2", "o.dubois",
  ];
  const SPRAY_PASSWORDS = ["admin123", "111111", "admin", "system", "qwerty", "123456", "password", "letmein", "welcome1", "123123"];
  const REVEAL_WORDS = ["Summer2026!", "Winter@123", "Spring#456", "Autumn$789", "Ocean-Blue7", "River-Gold3"];

  let els = {};
  let state = null; // set by resetSession()

  function randomIp() {
    return [1, 2, 3, 4].map(() => 1 + Math.floor(Math.random() * 253)).join(".");
  }
  function randomPort() {
    return 49152 + Math.floor(Math.random() * (65535 - 49152));
  }
  function pick(arr) { return arr[Math.floor(Math.random() * arr.length)]; }
  function sample(arr, n) {
    const copy = [...arr];
    const out = [];
    while (out.length < n && copy.length) out.push(copy.splice(Math.floor(Math.random() * copy.length), 1)[0]);
    return out;
  }
  function uniform(a, b) { return a + Math.random() * (b - a); }
  function padLog(i) { return "LOG_" + String(i + 1).padStart(5, "0"); }

  // -------------------------------------------------------------- terminal UI --
  function termPrint(text, cls = "") {
    const line = document.createElement("div");
    line.className = "term-line" + (cls ? " " + cls : "");
    line.textContent = text;
    els.body.appendChild(line);
    els.body.scrollTop = els.body.scrollHeight;
  }

  function setPrompt(label, isPassword) {
    els.promptLabel.textContent = label;
    els.input.type = isPassword ? "password" : "text";
    els.input.value = "";
    els.input.disabled = false;
    els.input.focus();
  }

  function lockInput(disabledPromptText) {
    els.input.disabled = true;
    if (disabledPromptText) els.promptLabel.textContent = disabledPromptText;
  }

  // ----------------------------------------------------------- session state --
  function resetSession() {
    state = {
      ip: randomIp(),
      port: randomPort(),
      secret: pick(REVEAL_WORDS),
      rows: [],          // {ts (ms epoch), Event, Username, Source_Port}
      failCount: 0,
      hintShown: false,
      stage: "username",  // "username" | "password" | "done"
      currentUsername: null,
      playing: false,
    };
    els.body.innerHTML = "";
    els.terminalIp.textContent = `${state.ip}:${state.port}`;
    els.downloadBtn.disabled = true;
    document.querySelectorAll(".btn-preset").forEach(b => b.disabled = false);
    termPrint(`Connecting to simulated-host (${state.ip})...`);
    termPrint(`Connection established. This is a SIMULATION -- no real server, nothing leaves your browser.`, "term-note");
    termPrint("");
    setPrompt("login as:", false);
    updateGauge([]);
    updateFeatureChips(null);
  }

  function appendRow(event, username) {
    // real wall-clock time -- this is a HUMAN typing, so inter-arrival gaps
    // here are genuinely the user's own typing speed (usually seconds),
    // unlike preset playback below, which logs the generator's timing.
    state.rows.push({ ts: Date.now(), Event: event, Username: username, Source_Port: state.port });
  }

  // ------------------------------------------------------------- live scoring --
  function computeFeatures(rows) {
    if (rows.length === 0) return null;
    const asFeatureRows = rows.map(r => ({ ts: r.ts, Event: r.Event, Username: r.Username, Source_IP: state.ip, Source_Port: r.Source_Port }));
    const session = { id: 1, ip: state.ip, rows: asFeatureRows };
    const feats = SSHFeatures.extractAllFeatures(asFeatureRows, [session])[0];
    return feats;
  }

  async function updateGauge(rows) {
    if (rows.length === 0) {
      els.gaugeFill.style.width = "0%";
      els.gaugeFill.style.background = "var(--panel-border)";
      els.gaugeValue.textContent = "0%";
      els.gaugeVerdict.textContent = "รอข้อมูล...";
      els.gaugeVerdict.className = "gauge-verdict";
      els.typeLine.hidden = true;
      return;
    }
    try {
      await SSHModel.load();
      const feats = computeFeatures(rows);
      // same model + decision rule as the results table, at the model's own
      // threshold (chosen by cross-validation on the training set)
      const d = SSHModel.classify(feats);
      const pct = Math.round(d.risk * 100);
      els.gaugeFill.style.width = pct + "%";
      els.gaugeFill.style.background = d.isAttack ? "var(--danger)" : "var(--safe)";
      els.gaugeValue.textContent = pct + "%";
      els.gaugeVerdict.textContent = d.isAttack ? "🚨 ตรวจพบว่าเป็น Attack" : "ปกติ (ยังไม่ถึงเกณฑ์)";
      els.gaugeVerdict.className = "gauge-verdict " + (d.isAttack ? "verdict-attack" : "verdict-safe");
      updateTypeLine(d);
      updateFeatureChips(feats);
    } catch (err) {
      els.gaugeVerdict.textContent = "โหลดโมเดลไม่สำเร็จ: " + err.message;
      console.error(err);
    }
  }

  // Which behaviour this looks like (attack type or legit behaviour).
  // The console simulates ONE IP in ONE session, so classes that need IP
  // history or other IPs (persistent multi-day, botnet) cannot appear here;
  // test logs 09 and 10 and the log generator show those.
  function updateTypeLine(d) {
    const info = describeClass(d.label);
    const pct = Math.round(d.confidence * 100);
    const kind = d.isAttack ? "type-attack" : "type-legit";
    const tail = d.isAttack ? `${info.th} · ${info.mitre} · ${pct}%` : `${info.th} · ${pct}%`;
    els.typeLine.innerHTML = d.lowConfidence
      ? `<span class="type-label">ลักษณะ:</span> <span class="type-badge type-low">ไม่แน่ใจ</span>
         <span class="type-sub">ใกล้เคียง ${info.name} (${pct}%)</span>`
      : `<span class="type-label">ลักษณะ:</span> <span class="type-badge ${kind}">${info.name}</span>
         <span class="type-sub">${tail}</span>
         <span class="type-signal">${info.signal}</span>`;
    els.typeLine.hidden = false;
  }

  function updateFeatureChips(feats) {
    if (!feats) { els.featuresBox.innerHTML = ""; return; }
    const rows = [
      ["n_failed", feats.n_failed], ["n_success", feats.n_success],
      ["fail_ratio", feats.fail_ratio.toFixed(2)],
      ["attempts_per_minute", feats.attempts_per_minute.toFixed(1)],
      ["duration_s", feats.duration_seconds.toFixed(1)],
      ["n_unique_usernames", feats.n_unique_usernames],
    ];
    els.featuresBox.innerHTML = rows.map(([k, v]) =>
      `<div class="feat-chip"><span class="feat-k">${k}</span><span class="feat-v">${v}</span></div>`
    ).join("");
  }

  // ------------------------------------------------------------- manual input --
  function handleSubmit(e) {
    e.preventDefault();
    if (!els.input.value.trim() && state.stage === "username") return;
    if (state.stage === "username") {
      state.currentUsername = els.input.value.trim();
      termPrint(`login as: ${state.currentUsername}`);
      state.stage = "password";
      setPrompt("Password:", true);
      return;
    }
    if (state.stage === "password") {
      const guess = els.input.value;
      termPrint(`Password: ${"*".repeat(guess.length)}`);
      if (guess === state.secret) {
        appendRow("Accepted password", state.currentUsername);
        termPrint(`Authentication succeeded.`, "term-success");
        termPrint(`Welcome to simulated-host, ${state.currentUsername}!`, "term-success");
        state.stage = "done";
        lockInput("session จบแล้ว -- กด \"เริ่มใหม่\" เพื่อลองอีกครั้ง");
        els.downloadBtn.disabled = false;
      } else {
        appendRow("Failed password", state.currentUsername);
        state.failCount++;
        termPrint(`Permission denied, please try again.`, "term-fail");
        if (state.failCount >= HINT_AFTER_FAILS && !state.hintShown) {
          state.hintShown = true;
          termPrint(`[hint] ลองพิมพ์รหัสผ่านนี้ดูว่าจะเกิดอะไรขึ้นตอน login สำเร็จ: ${state.secret}`, "term-note");
        }
        els.downloadBtn.disabled = false;
        setPrompt("Password:", true);
      }
      updateGauge(state.rows);
    }
  }

  // -------------------------------------------------------------- presets --
  function buildPresetRows(type) {
    // Counts / gaps / success rates mirror v3/generate_v3_dataset.py
    // (gen_burst_bruteforce, gen_focused_bruteforce, gen_password_spray,
    // gen_credential_stuffing). Seconds below are LOGGED time, not animation.
    const now = Date.now();
    const rows = [];
    let t = now;
    const add = (event, user) => rows.push({ ts: t, Event: event, Username: user, Source_Port: randomPort() });

    if (type === "burst") {
      // 15-45 fails, 0.3-3 s apart, 5% chance of a final success
      const user = state.currentUsername || pick(DEFAULT_USERNAMES.concat(REAL_USERNAMES));
      const nFail = Math.round(uniform(15, 45));
      for (let i = 0; i < nFail; i++) { add("Failed password", user); t += uniform(300, 3000); }
      if (Math.random() < 0.05) add("Accepted password", user);
    }

    if (type === "focused") {
      // one account (60% default names), 15-30 fails, 2-35 s apart. The
      // generator goes down to 6 fails; below ~13 fails on a real-looking
      // account the model can't tell this from a user mistyping (by design,
      // that range overlaps legit_typo), so the preset starts at 15 to show
      // the pattern rather than the overlap. Type a few wrong passwords by
      // hand to see the overlap instead.
      const user = state.currentUsername || (Math.random() < 0.6 ? pick(DEFAULT_USERNAMES) : pick(REAL_USERNAMES));
      const nFail = Math.round(uniform(15, 30));
      for (let i = 0; i < nFail; i++) { add("Failed password", user); t += uniform(2000, 35000); }
    }

    if (type === "spray") {
      // 2 common passwords x 8 real accounts, 20-300 s apart, 15% chance one account falls
      const targets = sample(REAL_USERNAMES, 8);
      const passwords = sample(SPRAY_PASSWORDS, 2);
      const succeedUser = Math.random() < 0.15 ? pick(targets) : null;
      for (const pw of passwords) {
        const isLast = pw === passwords[passwords.length - 1];
        for (const user of targets) {
          add(user === succeedUser && isLast ? "Accepted password" : "Failed password", user);
          t += uniform(20000, 300000);
        }
      }
    }

    if (type === "stuffing") {
      // 12 accounts, one leaked pair each; 20-50% of pairs are correct
      // (30% of hits after one stale guess), 5-60 s apart
      const targets = sample(REAL_USERNAMES, 12);
      const hitRate = uniform(0.2, 0.5);
      for (const user of targets) {
        if (Math.random() < hitRate) {
          if (Math.random() < 0.3) { add("Failed password", user); t += uniform(1000, 10000); }
          add("Accepted password", user);
        } else {
          add("Failed password", user);
        }
        t += uniform(5000, 60000);
      }
    }

    return rows;
  }

  const PRESET_LABELS = {
    burst: "Burst Brute Force", focused: "Focused Brute Force",
    spray: "Password Spray", stuffing: "Credential Stuffing",
  };

  async function playPreset(type) {
    if (state.playing) return;
    state.playing = true;
    document.querySelectorAll(".btn-preset").forEach(b => b.disabled = true);
    lockInput(`กำลังจำลอง ${PRESET_LABELS[type]}...`);
    termPrint("");
    termPrint(`>>> จำลอง ${PRESET_LABELS[type]} จาก ${state.ip} <<<`, "term-note");

    const rows = buildPresetRows(type);
    for (const r of rows) {
      state.rows.push(r);
      const masked = r.Event === "Accepted password" ? "Accepted password" : "Failed password";
      termPrint(`login as: ${r.Username}`);
      termPrint(`Password: ${"*".repeat(6 + Math.floor(Math.random() * 5))}`);
      termPrint(masked === "Accepted password" ? "Authentication succeeded." : "Permission denied, please try again.",
                masked === "Accepted password" ? "term-success" : "term-fail");
      updateGauge(state.rows);
      els.downloadBtn.disabled = false;
      await new Promise(res => setTimeout(res, 90));
    }

    termPrint(`>>> จบการจำลอง (${rows.length} attempts) <<<`, "term-note");
    state.playing = false;
    document.querySelectorAll(".btn-preset").forEach(b => b.disabled = false);
    if (state.stage !== "done") lockInput("กด \"เริ่มใหม่\" เพื่อลองพิมพ์เอง หรือกด preset อื่น");
  }

  // -------------------------------------------------------------- download --
  function downloadLog() {
    const header = "Log_ID,Timestamp,Event,Username,Source_IP,Source_Port,Password";
    const lines = state.rows.map((r, i) => {
      const iso = new Date(r.ts).toISOString().replace("T", " ").replace("Z", "");
      const pw = r.Event === "Accepted password" ? "***HIDDEN***" : "***GUESS***";
      return [padLog(i), iso, r.Event, r.Username, state.ip, r.Source_Port, pw].join(",");
    });
    const csv = [header, ...lines].join("\n");
    const blob = new Blob([csv], { type: "text/csv" });
    const url = URL.createObjectURL(blob);
    const a = document.createElement("a");
    a.href = url;
    a.download = `live_console_session_${state.ip.replace(/\./g, "-")}.csv`;
    a.click();
    URL.revokeObjectURL(url);
  }

  // ------------------------------------------------------------------ init --
  function init() {
    els = {
      body: document.getElementById("terminal-body"),
      input: document.getElementById("terminal-input"),
      promptLabel: document.getElementById("terminal-prompt-label"),
      form: document.getElementById("terminal-input-row"),
      terminalIp: document.getElementById("terminal-ip"),
      gaugeFill: document.getElementById("live-gauge-fill"),
      gaugeValue: document.getElementById("live-gauge-value"),
      gaugeVerdict: document.getElementById("live-gauge-verdict"),
      featuresBox: document.getElementById("live-features"),
      typeLine: document.getElementById("live-type"),
      resetBtn: document.getElementById("live-reset-btn"),
      downloadBtn: document.getElementById("live-download-btn"),
    };
    if (!els.body) return; // section not present on this page

    els.form.addEventListener("submit", handleSubmit);
    els.resetBtn.addEventListener("click", resetSession);
    els.downloadBtn.addEventListener("click", downloadLog);
    document.querySelectorAll(".btn-preset").forEach(btn => {
      btn.addEventListener("click", () => playPreset(btn.dataset.preset));
    });

    resetSession();
  }

  document.addEventListener("DOMContentLoaded", init);
})();
