// app.js -- wires file upload -> session segmentation -> feature extraction
// -> model inference (stage 1: Attack/Legit, stage 2: attack type) -> table.
// Runs entirely in the browser when config.js leaves API_BASE_URL empty;
// otherwise the CSV is sent to the FastAPI backend, which runs the same
// two models and returns the same fields.

(() => {
  const fileInput = document.getElementById("file-input");
  const fileDrop = document.getElementById("file-drop");
  const fileDropLabel = document.getElementById("file-drop-label");
  const loadSampleBtn = document.getElementById("load-sample-btn");
  const gapInput = document.getElementById("gap-input");
  const thresholdInput = document.getElementById("threshold-input");
  const thresholdValue = document.getElementById("threshold-value");
  const statusLine = document.getElementById("status-line");
  const statusSpinner = document.getElementById("status-spinner");
  const statusText = document.getElementById("status-text");
  const summaryPanel = document.getElementById("summary-panel");
  const resultsPanel = document.getElementById("results-panel");
  const resultsTbody = document.getElementById("results-tbody");
  const attackOnlyToggle = document.getElementById("attack-only-toggle");
  const statSessions = document.getElementById("stat-sessions");
  const statAttack = document.getElementById("stat-attack");
  const statLegit = document.getElementById("stat-legit");
  const statIps = document.getElementById("stat-ips");
  const typeBreakdown = document.getElementById("type-breakdown");

  let currentResults = [];       // [{session, features, proba, attackType}]
  let lastRawText = null;        // raw CSV text of the last loaded file
  let lastLabel = null;          // display name of the last loaded file
  let sortState = { key: "risk", dir: -1 };

  function setStatus(msg, isError = false) {
    statusText.textContent = msg;
    statusLine.classList.toggle("error", isError);
  }

  function setLoading(isLoading) {
    statusSpinner.classList.toggle("hidden", !isLoading);
  }

  function revealResults() {
    summaryPanel.classList.remove("hidden");
    resultsPanel.classList.remove("hidden");
    [summaryPanel, resultsPanel].forEach(panel => {
      panel.classList.remove("reveal");
      // eslint-disable-next-line no-unused-expressions -- restart the CSS animation
      void panel.offsetWidth;
      panel.classList.add("reveal");
    });
    requestAnimationFrame(() => {
      summaryPanel.scrollIntoView({ behavior: "smooth", block: "start" });
    });
  }

  async function ensureModelLoaded() {
    if (!SSHModel.featureColumns) {
      setStatus("กำลังโหลดโมเดล...");
      await SSHModel.load("model/forest.json");
    }
    // stage 2 is optional: if it fails to load, the page still scores Attack/Legit
    if (!SSHTypeModel.featureColumns) {
      try { await SSHTypeModel.load("model/forest_type.json"); }
      catch (err) { console.warn("attack-type model not loaded:", err); }
    }
  }

  // Stage-2 result for one session -> table cell. Only shown for sessions that
  // stage 1 flags at the CURRENT threshold (type is meaningless for legit ones).
  function typeCellHtml(attackType, isAttack) {
    if (!isAttack) return `<span class="type-none">—</span>`;
    if (!attackType) return `<span class="type-none">ไม่มีข้อมูลประเภท</span>`;
    const info = describeAttackType(attackType.type);
    const pct = Math.round(attackType.confidence * 100);
    if (attackType.lowConfidence) {
      return `<span class="type-badge type-low" title="${info.signal}">ไม่แน่ใจ</span>
        <span class="type-sub">ใกล้เคียง: ${info.name} (${pct}%)</span>`;
    }
    return `<span class="type-badge" title="${info.signal}">${info.name}</span>
      <span class="type-sub">${info.th} · ${info.mitre} · ${pct}%</span>`;
  }

  function typeOf(attackType) {
    if (!attackType) return null;
    return attackType.lowConfidence ? "uncertain" : attackType.type;
  }

  // CSV values (usernames, IPs, events...) come from an uploaded file and
  // must never be inserted as HTML.
  function esc(v) {
    return String(v).replace(/[&<>"']/g, c => ({ "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;", "'": "&#39;" }[c]));
  }

  function formatDuration(seconds) {
    if (seconds < 60) return seconds.toFixed(1) + "s";
    if (seconds < 3600) return (seconds / 60).toFixed(1) + "m";
    if (seconds < 86400) return (seconds / 3600).toFixed(1) + "h";
    return (seconds / 86400).toFixed(1) + "d";
  }

  function formatTime(ms) {
    const d = new Date(ms);
    return d.toISOString().replace("T", " ").slice(0, 19);
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

  function apiBaseUrl() {
    return (window.SSHML_CONFIG && window.SSHML_CONFIG.API_BASE_URL) || "";
  }

  async function runPipelineViaBackend(csvText, gapMinutes) {
    const formData = new FormData();
    formData.append("file", new Blob([csvText], { type: "text/csv" }), "log.csv");
    const res = await fetch(`${apiBaseUrl()}/predict?gap_minutes=${gapMinutes}`, { method: "POST", body: formData });
    if (!res.ok) {
      const text = await res.text().catch(() => "");
      throw new Error(`Backend ตอบผิดพลาด (${res.status}): ${text.slice(0, 200)}`);
    }
    const data = await res.json();
    const results = data.sessions.map(s => ({
      session: {
        ip: s.ip,
        rows: s.rows.map(r => ({
          ts: Date.parse(r.ts), tsRaw: r.ts,
          Event: r.event, Username: r.username, Source_Port: r.port,
        })),
      },
      features: s.features,
      proba: s.proba,
      attackType: s.attack_type ? {
        type: s.attack_type.type,
        confidence: s.attack_type.confidence,
        lowConfidence: s.attack_type.low_confidence,
        ranked: s.attack_type.ranked,
      } : null,
    }));
    return { nRows: data.n_rows, results };
  }

  function runPipelineLocally(csvText, gapMinutes) {
    const rows = SSHFeatures.loadLogRows(csvText);
    if (rows.length === 0) throw new Error("ไม่พบแถวข้อมูลที่อ่านได้ในไฟล์นี้");
    const sessions = SSHFeatures.segmentSessions(rows, gapMinutes);
    // IP-level and time-window features need the WHOLE file's sessions at
    // once (not just one session in isolation), so features are computed
    // for all sessions together, then scored one at a time.
    const allFeatures = SSHFeatures.extractAllFeatures(rows, sessions);
    const results = sessions.map((session, i) => {
      const features = allFeatures[i];
      const x = SSHModel.featureVector(features);
      const proba = SSHModel.predictProba(x);
      const attackType = SSHTypeModel.featureColumns ? SSHTypeModel.predictType(features) : null;
      return { session, features, proba, attackType };
    });
    return { nRows: rows.length, results };
  }

  async function runPipeline(csvText, gapMinutes) {
    return apiBaseUrl()
      ? runPipelineViaBackend(csvText, gapMinutes)
      : runPipelineLocally(csvText, gapMinutes);
  }

  function render() {
    const threshold = parseFloat(thresholdInput.value);
    thresholdValue.textContent = threshold.toFixed(2);

    let rowsToShow = currentResults;
    if (attackOnlyToggle.checked) {
      rowsToShow = rowsToShow.filter(r => r.proba >= threshold);
    }

    const sorted = [...rowsToShow].sort((a, b) => {
      const key = sortState.key;
      if (key === "type") {
        // flagged rows sorted by type name; unflagged ("—") always last
        const fa = a.proba >= threshold, fb = b.proba >= threshold;
        if (fa !== fb) return fa ? -1 : 1;
        if (!fa) return b.proba - a.proba;
        const ta = typeOf(a.attackType) || "", tb = typeOf(b.attackType) || "";
        return ta === tb ? b.proba - a.proba : (ta < tb ? -1 : 1) * -sortState.dir;
      }
      let av, bv;
      if (key === "risk") { av = a.proba; bv = b.proba; }
      else if (key === "ip") { av = a.session.ip; bv = b.session.ip; }
      else if (key === "start") { av = a.session.rows[0].ts; bv = b.session.rows[0].ts; }
      else if (key === "duration") { av = a.features.duration_seconds; bv = b.features.duration_seconds; }
      else { av = a.features[key]; bv = b.features[key]; }
      if (av < bv) return -1 * sortState.dir;
      if (av > bv) return 1 * sortState.dir;
      return 0;
    });

    resultsTbody.innerHTML = "";
    for (const r of sorted) {
      const isAttack = r.proba >= threshold;
      const tr = document.createElement("tr");
      tr.className = "session-row";
      tr.innerHTML = `
        <td><span class="risk-badge ${isAttack ? "attack" : "legit"}">${isAttack ? "ATTACK" : "legit"} ${(r.proba * 100).toFixed(0)}%</span></td>
        <td class="mono">${esc(r.session.ip)}</td>
        <td class="mono">${formatTime(r.session.rows[0].ts)}</td>
        <td>${formatDuration(r.features.duration_seconds)}</td>
        <td>${r.features.n_events}</td>
        <td>${r.features.n_failed}</td>
        <td>${r.features.n_unique_usernames}</td>
        <td class="type-cell">${typeCellHtml(r.attackType, isAttack)}</td>
        <td class="evidence">${buildEvidence(r.session, r.features)}</td>
      `;
      const detailTr = document.createElement("tr");
      detailTr.className = "detail-row";
      detailTr.style.display = "none";
      const logLines = r.session.rows.map(row => {
        const cls = row.Event === "Failed password" ? "fail" : "success";
        return `<div class="${cls}">${esc(row.tsRaw)}  ${esc(String(row.Event).padEnd(18))}  user=${esc(row.Username)}  port=${esc(row.Source_Port)}</div>`;
      }).join("");
      detailTr.innerHTML = `<td colspan="9"><div class="log-lines">${logLines}</div></td>`;

      tr.addEventListener("click", () => {
        detailTr.style.display = detailTr.style.display === "none" ? "table-row" : "none";
      });

      resultsTbody.appendChild(tr);
      resultsTbody.appendChild(detailTr);
    }

    const attackCount = currentResults.filter(r => r.proba >= threshold).length;
    statSessions.textContent = currentResults.length;
    statAttack.textContent = attackCount;
    statLegit.textContent = currentResults.length - attackCount;
    statIps.textContent = new Set(currentResults.map(r => r.session.ip)).size;

    // which attack types were found among flagged sessions
    const counts = new Map();
    for (const r of currentResults) {
      if (r.proba < threshold) continue;
      const key = typeOf(r.attackType);
      if (key) counts.set(key, (counts.get(key) || 0) + 1);
    }
    if (counts.size === 0) {
      typeBreakdown.hidden = true;
      typeBreakdown.innerHTML = "";
    } else {
      const chips = [...counts.entries()].sort((a, b) => b[1] - a[1]).map(([key, n]) => {
        const label = key === "uncertain" ? "ไม่แน่ใจประเภท" : `${describeAttackType(key).name} (${describeAttackType(key).mitre})`;
        return `<span class="type-chip">${label} <b>×${n}</b></span>`;
      }).join("");
      typeBreakdown.innerHTML = `<span class="type-breakdown-label">ประเภทที่พบ:</span>${chips}`;
      typeBreakdown.hidden = false;
    }
  }

  async function handleFile(text, label) {
    setLoading(true);
    try {
      const usingBackend = !!apiBaseUrl();
      if (!usingBackend) await ensureModelLoaded();
      setStatus(`กำลังประมวลผล ${label}${usingBackend ? " ผ่าน backend..." : " ในเบราว์เซอร์..."}`);
      lastRawText = text;
      lastLabel = label;
      const gapMinutes = parseFloat(gapInput.value) || 30;
      const { nRows, results } = await runPipeline(text, gapMinutes);
      currentResults = results;
      const modeNote = usingBackend ? "ประมวลผลบน backend" : "ประมวลผลในเบราว์เซอร์ทั้งหมด";
      setStatus(`อ่านได้ ${nRows} แถว log แบ่งได้ ${results.length} session (จาก ${label}, gap threshold ${gapMinutes} นาที) — ${modeNote}`);
      render();
      revealResults();
    } catch (err) {
      setStatus("เกิดข้อผิดพลาด: " + err.message, true);
      console.error(err);
    } finally {
      setLoading(false);
    }
  }

  function readAndHandle(file) {
    fileDropLabel.textContent = file.name;
    const reader = new FileReader();
    reader.onload = () => handleFile(reader.result, file.name);
    reader.readAsText(file);
  }

  fileInput.addEventListener("change", () => {
    const file = fileInput.files[0];
    if (file) readAndHandle(file);
  });

  ["dragover", "dragenter"].forEach(evt =>
    fileDrop.addEventListener(evt, (e) => { e.preventDefault(); fileDrop.classList.add("drag-over"); })
  );
  ["dragleave", "drop"].forEach(evt =>
    fileDrop.addEventListener(evt, (e) => { e.preventDefault(); fileDrop.classList.remove("drag-over"); })
  );
  fileDrop.addEventListener("drop", (e) => {
    const file = e.dataTransfer.files[0];
    if (file) { readAndHandle(file); return; }
    // not a real OS file drop -- check for an internal test-suite card drag
    const url = e.dataTransfer.getData("text/plain");
    if (url && url.startsWith("test_logs/")) {
      const name = url.split("/").pop();
      loadFromUrl(url, name);
    }
  });

  async function loadFromUrl(url, name) {
    setStatus(`กำลังโหลด ${name}...`);
    try {
      const res = await fetch(url);
      if (!res.ok) throw new Error(`โหลด ${name} ไม่สำเร็จ (${res.status})`);
      const text = await res.text();
      fileDropLabel.textContent = name;
      handleFile(text, name);
    } catch (err) {
      setStatus("เกิดข้อผิดพลาด: " + err.message, true);
    }
  }

  // test-suite cards: click "load" button (auto-runs it through the model),
  // click "download" (native <a download>, no JS needed), or drag the whole
  // card onto the upload dropzone above (native HTML5 drag-and-drop -- see
  // fileDrop "drop" handler, which reads the URL back out of dataTransfer).
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

  loadSampleBtn.addEventListener("click", async () => {
    setStatus("กำลังโหลดไฟล์ตัวอย่าง...");
    try {
      const res = await fetch("sample-log.csv");
      if (!res.ok) throw new Error("โหลด sample-log.csv ไม่สำเร็จ (" + res.status + ")");
      const text = await res.text();
      fileDropLabel.textContent = "sample-log.csv";
      handleFile(text, "sample-log.csv");
    } catch (err) {
      setStatus("เกิดข้อผิดพลาด: " + err.message, true);
    }
  });

  // Changing the gap threshold re-segments the LAST loaded file from scratch
  // (session boundaries change, so features and predictions must be redone).
  gapInput.addEventListener("change", () => {
    if (lastRawText !== null) handleFile(lastRawText, lastLabel);
  });

  // Changing the decision threshold only re-labels already-computed
  // probabilities -- no need to re-run the model.
  thresholdInput.addEventListener("input", render);
  attackOnlyToggle.addEventListener("change", render);

  document.querySelectorAll("#results-table thead th[data-sort]").forEach(th => {
    th.addEventListener("click", () => {
      const key = th.dataset.sort;
      if (sortState.key === key) sortState.dir *= -1;
      else { sortState.key = key; sortState.dir = -1; }
      render();
    });
  });
})();
