// app.js -- wires file upload -> session segmentation -> feature extraction
// -> model inference -> table rendering. Everything runs in the browser;
// nothing is uploaded anywhere.

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

  let currentResults = [];       // [{session, features, proba}]
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
      resultsPanel.scrollIntoView({ behavior: "smooth", block: "start" });
    });
  }

  async function ensureModelLoaded() {
    if (SSHModel.featureColumns) return;
    setStatus("กำลังโหลดโมเดล...");
    await SSHModel.load("model/forest.json");
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
      bits.push(`${features.n_unique_usernames} usernames: ${users.slice(0, 6).join(", ")}${users.length > 6 ? "…" : ""}`);
    } else {
      bits.push(`username: ${session.rows[0].Username}`);
    }
    if (features.targets_default_username) bits.push("default/service account targeted");
    bits.push(`${features.n_unique_ports} port(s)`);
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
    }));
    return { nRows: data.n_rows, results };
  }

  function runPipelineLocally(csvText, gapMinutes) {
    const rows = SSHFeatures.loadLogRows(csvText);
    if (rows.length === 0) throw new Error("ไม่พบแถวข้อมูลที่อ่านได้ในไฟล์นี้");
    const sessions = SSHFeatures.segmentSessions(rows, gapMinutes);
    const results = sessions.map(session => {
      const features = SSHFeatures.extractFeatures(session);
      const x = SSHModel.featureVector(features);
      const proba = SSHModel.predictProba(x);
      return { session, features, proba };
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
        <td class="mono">${r.session.ip}</td>
        <td class="mono">${formatTime(r.session.rows[0].ts)}</td>
        <td>${formatDuration(r.features.duration_seconds)}</td>
        <td>${r.features.n_events}</td>
        <td>${r.features.n_failed}</td>
        <td>${r.features.n_unique_usernames}</td>
        <td class="evidence">${buildEvidence(r.session, r.features)}</td>
      `;
      const detailTr = document.createElement("tr");
      detailTr.className = "detail-row";
      detailTr.style.display = "none";
      const logLines = r.session.rows.map(row => {
        const cls = row.Event === "Failed password" ? "fail" : "success";
        return `<div class="${cls}">${row.tsRaw}  ${row.Event.padEnd(18)}  user=${row.Username}  port=${row.Source_Port}</div>`;
      }).join("");
      detailTr.innerHTML = `<td colspan="8"><div class="log-lines">${logLines}</div></td>`;

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

  // test-suite cards: click "load" button, or drag the whole card onto the
  // upload dropzone above (native HTML5 drag-and-drop -- see fileDrop "drop"
  // handler, which reads the URL back out of dataTransfer).
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
