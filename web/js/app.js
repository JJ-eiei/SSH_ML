// app.js -- wires a log file (CSV or raw sshd auth.log) -> session
// segmentation -> feature extraction -> ONE multiclass model (risk score +
// which behaviour) -> results table.
// Runs entirely in the browser when config.js leaves API_BASE_URL empty;
// otherwise the CSV is sent to the FastAPI backend, which runs the same
// model and returns the same fields (raw auth.log is always converted to
// CSV in the browser first).

(() => {
  const $ = (id) => document.getElementById(id);
  const fileInput = $("file-input");
  const fileDrop = $("file-drop");
  const fileDropLabel = $("file-drop-label");
  const loadSampleBtn = $("load-sample-btn");
  const gapInput = $("gap-input");
  const thresholdInput = $("threshold-input");
  const thresholdValue = $("threshold-value");
  const statusLine = $("status-line");
  const statusSpinner = $("status-spinner");
  const statusText = $("status-text");
  const summaryPanel = $("summary-panel");
  const resultsPanel = $("results-panel");
  const resultsTbody = $("results-tbody");
  const attackOnlyToggle = $("attack-only-toggle");
  const statSessions = $("stat-sessions");
  const statAttack = $("stat-attack");
  const statLegit = $("stat-legit");
  const statIps = $("stat-ips");
  const typeBreakdown = $("type-breakdown");
  const checkPanel = $("check-panel");

  let currentResults = [];   // [{session, features, classProba, risk}]
  let currentMeta = null;    // {attackClasses, legitClasses, lowConfidence, threshold}
  let currentTruth = null;   // Map rowKey -> true class (only for generated logs)
  let lastRawText = null;
  let lastLabel = null;
  let lastTruth = null;
  let thresholdTouched = false;
  let runSeq = 0;            // newest analysis wins; older in-flight results are dropped
  let sortState = { key: "risk", dir: -1 };

  // ------------------------------------------------------------ helpers --
  function setStatus(msg, isError = false) {
    statusText.textContent = msg;
    statusLine.classList.toggle("error", isError);
  }
  function setLoading(isLoading) { statusSpinner.classList.toggle("hidden", !isLoading); }

  // Values from an uploaded file must never be inserted as HTML.
  function esc(v) {
    return String(v ?? "").replace(/[&<>"']/g, c => ({ "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;", "'": "&#39;" }[c]));
  }

  function formatDuration(seconds) {
    if (seconds < 60) return seconds.toFixed(1) + "s";
    if (seconds < 3600) return (seconds / 60).toFixed(1) + "m";
    if (seconds < 86400) return (seconds / 3600).toFixed(1) + "h";
    return (seconds / 86400).toFixed(1) + "d";
  }

  // Timestamps without a zone are read as the viewer's local time, so they
  // are shown back in local time too (not UTC).
  function formatTime(ms) {
    const d = new Date(ms);
    const p = (n) => String(n).padStart(2, "0");
    return `${d.getFullYear()}-${p(d.getMonth() + 1)}-${p(d.getDate())} ${p(d.getHours())}:${p(d.getMinutes())}:${p(d.getSeconds())}`;
  }

  // key that identifies one log line in both pipeline modes (generator answer key)
  function rowKey(ip, port, ms) { return `${ip}|${String(port).trim()}|${ms}`; }

  function revealResults() {
    summaryPanel.classList.remove("hidden");
    resultsPanel.classList.remove("hidden");
    [summaryPanel, resultsPanel].forEach(panel => {
      panel.classList.remove("reveal");
      void panel.offsetWidth; // restart the CSS animation
      panel.classList.add("reveal");
    });
    requestAnimationFrame(() => summaryPanel.scrollIntoView({ behavior: "smooth", block: "start" }));
  }

  function buildEvidence(session, features) {
    const bits = [];
    bits.push(`${features.n_failed} failed / ${features.n_success} success`);
    if (features.n_unique_usernames > 1) {
      const users = [...new Set(session.rows.map(r => r.Username))];
      bits.push(`${features.n_unique_usernames} usernames: ${users.slice(0, 6).map(esc).join(", ")}${users.length > 6 ? "…" : ""}`);
    } else {
      bits.push(`username: ${esc(session.rows[0].Username)}`);
    }
    if (features.targets_default_username) bits.push("default/service account targeted");
    if (features.ip_session_count > 1) bits.push(`IP seen in ${features.ip_session_count} sessions over ${features.ip_active_span_days.toFixed(1)}d`);
    if (features.distinct_ips_same_target_15min > 0) bits.push(`${features.distinct_ips_same_target_15min} other IP(s) hit same user within 15min`);
    return bits.join(" · ");
  }

  function classCellHtml(d) {
    const info = describeClass(d.label);
    const pct = Math.round(d.confidence * 100);
    const kind = d.isAttack ? "type-attack" : "type-legit";
    if (d.lowConfidence) {
      return `<span class="type-badge type-low" title="${esc(info.signal)}">ไม่แน่ใจ</span>
        <span class="type-sub">ใกล้เคียง: ${esc(info.name)} (${pct}%)</span>`;
    }
    const tail = d.isAttack ? `${esc(info.th)} · ${esc(info.mitre)} · ${pct}%` : `${esc(info.th)} · ${pct}%`;
    return `<span class="type-badge ${kind}" title="${esc(info.signal)}">${esc(info.name)}</span>
      <span class="type-sub">${tail}</span>`;
  }

  function apiBaseUrl() {
    return (window.SSHML_CONFIG && window.SSHML_CONFIG.API_BASE_URL) || "";
  }

  // ----------------------------------------------------------- pipeline --
  async function runPipelineViaBackend(csvText, gapMinutes) {
    const formData = new FormData();
    formData.append("file", new Blob([csvText], { type: "text/csv" }), "log.csv");
    const res = await fetch(`${apiBaseUrl()}/predict?gap_minutes=${gapMinutes}`, { method: "POST", body: formData });
    if (!res.ok) {
      let detail = await res.text().catch(() => "");
      try { detail = JSON.parse(detail).detail || detail; } catch (_) { /* not JSON */ }
      throw new Error(`Backend ตอบผิดพลาด (${res.status}): ${String(detail).slice(0, 200)}`);
    }
    const data = await res.json();
    if (!data.classes) throw new Error("Backend ยังเป็นเวอร์ชันเก่า (ไม่มีข้อมูลคลาส) — รอ deploy ใหม่");
    const meta = {
      attackClasses: data.attack_classes, legitClasses: data.legit_classes,
      lowConfidence: 0.6, threshold: data.threshold,
    };
    const results = data.sessions.map(s => ({
      session: {
        ip: s.ip,
        rows: s.rows.map(r => ({
          ts: SSHFeatures.parseTimestamp(r.ts), tsRaw: r.ts,
          Event: r.event, Username: r.username, Source_Port: r.port, Source_IP: s.ip,
        })),
      },
      features: s.features,
      classProba: s.class_proba,
      risk: s.proba,
    }));
    return { nRows: data.n_rows, results, meta };
  }

  async function runPipelineLocally(csvText, gapMinutes) {
    if (!SSHModel.featureColumns) {
      setStatus("กำลังโหลดโมเดล...");
      await SSHModel.load();
    }
    const rows = SSHFeatures.loadLogRows(csvText);
    if (rows.length === 0) throw new Error("ไม่พบแถวข้อมูลที่อ่านได้ในไฟล์นี้");
    const sessions = SSHFeatures.segmentSessions(rows, gapMinutes);
    // IP-level and time-window features need the WHOLE file's sessions at
    // once, so features are computed for all sessions together.
    const allFeatures = SSHFeatures.extractAllFeatures(rows, sessions);
    const results = sessions.map((session, i) => {
      const features = allFeatures[i];
      const classProba = SSHModel.predictClassProba(SSHModel.featureVector(features));
      const risk = Math.round(SSHModel.meta().attackClasses.reduce((s, c) => s + classProba[c], 0) * 1e9) / 1e9;
      return { session, features, classProba, risk };
    });
    return { nRows: rows.length, results, meta: SSHModel.meta() };
  }

  // ------------------------------------------------------------- render --
  function render() {
    const threshold = parseFloat(thresholdInput.value);
    thresholdValue.textContent = threshold.toFixed(2);
    if (!currentMeta) return;

    for (const r of currentResults) r.d = decideClass(r.classProba, threshold, currentMeta);

    let rowsToShow = currentResults;
    if (attackOnlyToggle.checked) rowsToShow = rowsToShow.filter(r => r.d.isAttack);

    const sorted = [...rowsToShow].sort((a, b) => {
      const key = sortState.key;
      if (key === "type") {
        // attacks first, then legit; within a group by class name
        if (a.d.isAttack !== b.d.isAttack) return a.d.isAttack ? -1 : 1;
        const ta = describeClass(a.d.label).name, tb = describeClass(b.d.label).name;
        return ta === tb ? b.risk - a.risk : (ta < tb ? -1 : 1) * -sortState.dir;
      }
      let av, bv;
      if (key === "risk") { av = a.risk; bv = b.risk; }
      else if (key === "ip") { av = a.session.ip; bv = b.session.ip; }
      else if (key === "start") { av = a.session.rows[0].ts; bv = b.session.rows[0].ts; }
      else if (key === "duration") { av = a.features.duration_seconds; bv = b.features.duration_seconds; }
      else { av = a.features[key]; bv = b.features[key]; }
      if (av < bv) return -1 * sortState.dir;
      if (av > bv) return 1 * sortState.dir;
      return 0;
    });

    const frag = document.createDocumentFragment();
    for (const r of sorted) {
      const isAttack = r.d.isAttack;
      const tr = document.createElement("tr");
      tr.className = "session-row";
      tr.innerHTML = `
        <td><span class="risk-badge ${isAttack ? "attack" : "legit"}">${isAttack ? "ATTACK" : "legit"} ${(r.risk * 100).toFixed(0)}%</span></td>
        <td class="mono">${esc(r.session.ip)}</td>
        <td class="mono">${formatTime(r.session.rows[0].ts)}</td>
        <td>${formatDuration(r.features.duration_seconds)}</td>
        <td>${r.features.n_events}</td>
        <td>${r.features.n_failed}</td>
        <td>${r.features.n_unique_usernames}</td>
        <td class="type-cell">${classCellHtml(r.d)}</td>
        <td class="evidence">${buildEvidence(r.session, r.features)}</td>
      `;
      const detailTr = document.createElement("tr");
      detailTr.className = "detail-row";
      detailTr.style.display = "none";
      const logLines = r.session.rows.map(row => {
        const ev = String(row.Event);
        const cls = ev.startsWith("Accepted") ? "success" : "fail";
        return `<div class="${cls}">${esc(row.tsRaw)}  ${esc(ev.padEnd(18))}  user=${esc(row.Username)}  port=${esc(row.Source_Port)}</div>`;
      }).join("");
      detailTr.innerHTML = `<td colspan="9"><div class="log-lines">${logLines}</div></td>`;
      tr.addEventListener("click", () => {
        detailTr.style.display = detailTr.style.display === "none" ? "table-row" : "none";
      });
      frag.appendChild(tr);
      frag.appendChild(detailTr);
    }
    resultsTbody.innerHTML = "";
    resultsTbody.appendChild(frag);

    const attackCount = currentResults.filter(r => r.d.isAttack).length;
    statSessions.textContent = currentResults.length;
    statAttack.textContent = attackCount;
    statLegit.textContent = currentResults.length - attackCount;
    statIps.textContent = new Set(currentResults.map(r => r.session.ip)).size;

    renderBreakdown();
    renderCheck();
  }

  function renderBreakdown() {
    const counts = { attack: new Map(), legit: new Map() };
    for (const r of currentResults) {
      const key = r.d.lowConfidence ? "uncertain" : r.d.label;
      const g = r.d.isAttack ? counts.attack : counts.legit;
      g.set(key, (g.get(key) || 0) + 1);
    }
    const chips = (map, kind) => [...map.entries()].sort((a, b) => b[1] - a[1]).map(([key, n]) => {
      const info = describeClass(key);
      const label = key === "uncertain" ? "ไม่แน่ใจประเภท" : (info.mitre ? `${info.name} (${info.mitre})` : info.name);
      return `<span class="type-chip ${kind}">${esc(label)} <b>×${n}</b></span>`;
    }).join("");
    let html = "";
    if (counts.attack.size) html += `<div class="type-breakdown-row"><span class="type-breakdown-label">การโจมตีที่พบ:</span>${chips(counts.attack, "chip-attack")}</div>`;
    if (counts.legit.size) html += `<div class="type-breakdown-row"><span class="type-breakdown-label">พฤติกรรมปกติ:</span>${chips(counts.legit, "chip-legit")}</div>`;
    typeBreakdown.innerHTML = html;
    typeBreakdown.hidden = !html;
  }

  // Compare against the answer key of a generated log (if any).
  function renderCheck() {
    if (!currentTruth) { checkPanel.hidden = true; checkPanel.innerHTML = ""; return; }
    const byClass = new Map();
    let n = 0, groupOk = 0, classOk = 0;
    for (const r of currentResults) {
      const votes = new Map();
      for (const row of r.session.rows) {
        const t = currentTruth.get(rowKey(row.Source_IP ?? r.session.ip, row.Source_Port, row.ts));
        if (t) votes.set(t, (votes.get(t) || 0) + 1);
      }
      if (!votes.size) continue;
      const truth = [...votes.entries()].sort((a, b) => b[1] - a[1])[0][0];
      const truthAttack = describeClass(truth).group === "attack";
      const g = r.d.isAttack === truthAttack;
      const c = g && r.d.label === truth;
      const s = byClass.get(truth) || { n: 0, g: 0, c: 0 };
      s.n++; s.g += g; s.c += c; byClass.set(truth, s);
      n++; groupOk += g; classOk += c;
    }
    if (!n) { checkPanel.hidden = true; return; }
    const pct = (a, b) => `${(100 * a / b).toFixed(1)}%`;
    const order = Object.keys(CLASS_INFO);
    const rows = [...byClass.entries()].sort((a, b) => order.indexOf(a[0]) - order.indexOf(b[0])).map(([cls, s]) => {
      const info = describeClass(cls);
      return `<tr><td><span class="type-badge ${info.group === "attack" ? "type-attack" : "type-legit"}">${esc(info.name)}</span></td>
        <td>${info.group === "attack" ? "โจมตี" : "ปกติ"}</td><td>${s.n}</td>
        <td class="${s.g === s.n ? "ok" : "warn"}">${s.g}/${s.n} (${pct(s.g, s.n)})</td>
        <td class="${s.c === s.n ? "ok" : "warn"}">${s.c}/${s.n} (${pct(s.c, s.n)})</td></tr>`;
    }).join("");
    checkPanel.innerHTML = `
      <h2>ตรวจคำตอบเทียบเฉลยของ log ที่สร้าง</h2>
      <p class="check-total">ทั้งหมด ${n} session · แยกโจมตี/ปกติถูก <b>${pct(groupOk, n)}</b> · ระบุประเภทถูก <b>${pct(classOk, n)}</b>
        <span class="hint">(ที่ threshold ${parseFloat(thresholdInput.value).toFixed(2)})</span></p>
      <div class="table-scroll"><table class="check-table">
        <thead><tr><th>ประเภทจริง</th><th>กลุ่ม</th><th>Sessions</th><th>แยกโจมตี/ปกติถูก</th><th>ระบุประเภทถูก</th></tr></thead>
        <tbody>${rows}</tbody></table></div>
      <p class="hint">เฉลยไม่ได้อยู่ในไฟล์ CSV ที่ส่งให้โมเดล — เว็บเก็บไว้แยกแล้วนำมาเทียบหลังวิเคราะห์เสร็จ</p>`;
    checkPanel.hidden = false;
  }

  // --------------------------------------------------------------- load --
  async function handleFile(text, label, truth = null) {
    const myRun = ++runSeq;
    setLoading(true);
    try {
      let csvText = text;
      let convertNote = "";
      if (window.AuthLog && AuthLog.looksLikeAuthLog(text)) {
        const conv = AuthLog.toCsv(text);
        if (conv.rows === 0) throw new Error("ไฟล์นี้ดูเหมือน auth.log แต่ไม่พบบรรทัด sshd ที่รองรับ (ดูรูปแบบในกล่อง \"รูปแบบไฟล์ที่รองรับ\")");
        csvText = conv.csv;
        convertNote = ` · แปลงจาก auth.log: ใช้ ${conv.rows} เหตุการณ์ (ข้าม ${conv.ignoredLines} บรรทัดที่ไม่เกี่ยวกับการ login)`;
      }
      const usingBackend = !!apiBaseUrl();
      setStatus(`กำลังประมวลผล ${label}${usingBackend ? " ผ่าน backend..." : " ในเบราว์เซอร์..."}`);
      lastRawText = text; lastLabel = label; lastTruth = truth;
      const gapMinutes = parseFloat(gapInput.value) || 10;
      const { nRows, results, meta } = usingBackend
        ? await runPipelineViaBackend(csvText, gapMinutes)
        : await runPipelineLocally(csvText, gapMinutes);
      if (myRun !== runSeq) return;  // a newer file/generation was started meanwhile
      currentResults = results;
      currentMeta = meta;
      currentTruth = truth;
      if (!thresholdTouched && meta.threshold != null) thresholdInput.value = meta.threshold;
      const modeNote = usingBackend ? "ประมวลผลบน backend" : "ประมวลผลในเบราว์เซอร์ทั้งหมด";
      setStatus(`อ่านได้ ${nRows} แถว log แบ่งได้ ${results.length} session (จาก ${label}, session gap ${gapMinutes} นาที) — ${modeNote}${convertNote}`);
      render();
      revealResults();
    } catch (err) {
      if (myRun !== runSeq) return;
      setStatus("เกิดข้อผิดพลาด: " + err.message, true);
      console.error(err);
    } finally {
      if (myRun === runSeq) setLoading(false);
    }
  }

  function readAndHandle(file) {
    fileDropLabel.textContent = file.name;
    const reader = new FileReader();
    reader.onload = () => handleFile(reader.result, file.name);
    reader.onerror = () => setStatus("อ่านไฟล์ไม่สำเร็จ", true);
    reader.readAsText(file);
  }

  fileInput.addEventListener("change", () => {
    const file = fileInput.files[0];
    if (file) readAndHandle(file);
    fileInput.value = "";  // allow re-selecting the same file
  });

  ["dragover", "dragenter"].forEach(evt =>
    fileDrop.addEventListener(evt, (e) => { e.preventDefault(); fileDrop.classList.add("drag-over"); }));
  ["dragleave", "drop"].forEach(evt =>
    fileDrop.addEventListener(evt, (e) => { e.preventDefault(); fileDrop.classList.remove("drag-over"); }));
  fileDrop.addEventListener("drop", (e) => {
    const file = e.dataTransfer.files[0];
    if (file) { readAndHandle(file); return; }
    const url = e.dataTransfer.getData("text/plain");  // internal test-card drag
    if (url && url.startsWith("test_logs/")) loadFromUrl(url, url.split("/").pop());
  });

  async function loadFromUrl(url, name) {
    setStatus(`กำลังโหลด ${name}...`);
    try {
      const res = await fetch(url);
      if (!res.ok) throw new Error(`โหลด ${name} ไม่สำเร็จ (${res.status})`);
      fileDropLabel.textContent = name;
      handleFile(await res.text(), name);
    } catch (err) {
      setStatus("เกิดข้อผิดพลาด: " + err.message, true);
    }
  }

  document.querySelectorAll(".btn-load").forEach(btn => {
    btn.addEventListener("click", () => loadFromUrl(btn.dataset.file, btn.dataset.name));
  });
  document.querySelectorAll(".test-card").forEach(card => {
    card.addEventListener("dragstart", (e) => {
      e.dataTransfer.setData("text/plain", card.dataset.file);
      e.dataTransfer.effectAllowed = "copy";
      card.classList.add("dragging");
    });
    card.addEventListener("dragend", () => card.classList.remove("dragging"));
  });
  loadSampleBtn.addEventListener("click", () => loadFromUrl("sample-log.csv", "sample-log.csv"));

  // Changing the gap re-segments the last file (features change).
  gapInput.addEventListener("change", () => {
    if (lastRawText !== null) handleFile(lastRawText, lastLabel, lastTruth);
  });
  // Changing the threshold only re-applies the decision rule.
  thresholdInput.addEventListener("input", () => { thresholdTouched = true; render(); });
  attackOnlyToggle.addEventListener("change", render);

  document.querySelectorAll("#results-table thead th[data-sort]").forEach(th => {
    th.addEventListener("click", () => {
      const key = th.dataset.sort;
      if (sortState.key === key) sortState.dir *= -1;
      else { sortState.key = key; sortState.dir = -1; }
      render();
    });
  });

  // used by the log generator panel
  window.SSHApp = {
    analyze(text, label, truth) {
      fileDropLabel.textContent = label;
      return handleFile(text, label, truth);
    },
    rowKey,
  };
})();
