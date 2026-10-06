// generator-ui.js -- the "สร้าง log ทดสอบใหม่" panel: pick behaviours and
// counts, generate a fresh log (SSHLogGen), analyse it through the normal
// upload pipeline (SSHApp.analyze), and grade it against the answer key.

(() => {
  const grid = document.getElementById("gen-grid");
  if (!grid) return;
  const startInput = document.getElementById("gen-start");
  const daysInput = document.getElementById("gen-days");
  const seedInput = document.getElementById("gen-seed");
  const runBtn = document.getElementById("gen-run");
  const dlBtn = document.getElementById("gen-download");
  const ansBtn = document.getElementById("gen-answer");
  const status = document.getElementById("gen-status");

  // [class, unit shown to the user, max]
  const ITEMS = [
    ["legit_login", "ครั้ง", 200],
    ["legit_typo", "ครั้ง", 200],
    ["shared_ip_legit", "ออฟฟิศ (IP)", 50],
    ["burst_bruteforce", "IP", 50],
    ["focused_bruteforce", "IP", 50],
    ["large_dictionary_scanner", "IP (150–600 ชื่อ/IP)", 10],
    ["low_and_slow", "IP", 50],
    ["persistent_multiday_attacker", "IP (15–50 session)", 10],
    ["coordinated_botnet_spike", "แคมเปญ (10–40 IP)", 10],
    ["password_spray", "แคมเปญ", 50],
    ["credential_stuffing", "IP", 50],
  ];
  const PRESETS = {
    mixed: { legit_login: 25, legit_typo: 12, shared_ip_legit: 3, burst_bruteforce: 4, focused_bruteforce: 3,
      large_dictionary_scanner: 1, low_and_slow: 3, persistent_multiday_attacker: 1, coordinated_botnet_spike: 1,
      password_spray: 2, credential_stuffing: 2 },
    attacks: { burst_bruteforce: 2, focused_bruteforce: 2, large_dictionary_scanner: 1, low_and_slow: 2,
      persistent_multiday_attacker: 1, coordinated_botnet_spike: 1, password_spray: 2, credential_stuffing: 2 },
    normal: { legit_login: 30, legit_typo: 15, shared_ip_legit: 4 },
  };

  const inputs = {};
  for (const [cls, unit, max] of ITEMS) {
    const info = describeClass(cls);
    const cell = document.createElement("label");
    cell.className = "gen-item " + (info.group === "attack" ? "gen-attack" : "gen-legit");
    cell.innerHTML = `
      <span class="gen-name">${info.name}${info.mitre ? ` <small>${info.mitre}</small>` : ""}</span>
      <span class="gen-desc">${info.th}</span>
      <span class="gen-input"><input type="number" min="0" max="${max}" value="0" data-cls="${cls}"> <small>${unit}</small></span>`;
    grid.appendChild(cell);
    inputs[cls] = cell.querySelector("input");
  }

  function newSeed() { return 1 + Math.floor(Math.random() * 2147483646); }
  function pad(n) { return String(n).padStart(2, "0"); }
  function dateValue(d) { return `${d.getFullYear()}-${pad(d.getMonth() + 1)}-${pad(d.getDate())}`; }

  function applyPreset(name) {
    for (const [cls, , max] of ITEMS) {
      let v = 0;
      if (name === "random") {
        const cap = max <= 10 ? 2 : 6;
        v = Math.floor(Math.random() * (cap + 1));
      } else if (PRESETS[name]) {
        v = PRESETS[name][cls] || 0;
      }
      inputs[cls].value = v;
    }
    if (name === "random" && ITEMS.every(([cls]) => +inputs[cls].value === 0)) inputs.burst_bruteforce.value = 1;
  }

  // default window: the last 30 days, but never overlapping the demo test
  // logs (which run up to 2026-09-26)
  const earliest = new Date(2026, 8, 27);
  const defStart = new Date(); defStart.setHours(0, 0, 0, 0); defStart.setDate(defStart.getDate() - 30);
  startInput.value = dateValue(defStart < earliest ? earliest : defStart);
  seedInput.value = newSeed();
  applyPreset("mixed");

  document.querySelectorAll("[data-gen-preset]").forEach(btn =>
    btn.addEventListener("click", () => applyPreset(btn.dataset.genPreset)));
  document.getElementById("gen-reseed").addEventListener("click", () => { seedInput.value = newSeed(); });

  let last = null;

  function download(text, filename) {
    const url = URL.createObjectURL(new Blob([text], { type: "text/csv" }));
    const a = document.createElement("a");
    a.href = url; a.download = filename;
    document.body.appendChild(a); a.click(); a.remove();
    setTimeout(() => URL.revokeObjectURL(url), 1000);
  }

  runBtn.addEventListener("click", async () => {
    const counts = {};
    for (const [cls, , max] of ITEMS) counts[cls] = Math.max(0, Math.min(max, Math.floor(+inputs[cls].value || 0)));
    const seed = Math.floor(+seedInput.value) || newSeed();
    const days = Math.max(1, Math.min(60, Math.floor(+daysInput.value) || 30));
    const [y, m, d] = (startInput.value || dateValue(new Date())).split("-").map(Number);
    try {
      const g = SSHLogGen.generate({ counts, seed, start: new Date(y, m - 1, d), days });
      last = { ...g, seed };
      dlBtn.disabled = false; ansBtn.disabled = false;
      status.classList.remove("error");
      status.textContent = `สร้างแล้ว ${g.stats.rows.toLocaleString()} บรรทัด จาก ${g.stats.ips.toLocaleString()} IP · ` +
        `${g.stats.from.slice(0, 16)} ถึง ${g.stats.to.slice(0, 16)} · seed ${seed} (ใส่ seed เดิมเพื่อสร้างไฟล์เดิมซ้ำ)`;
      seedInput.value = newSeed();  // next click gives a different log
      await SSHApp.analyze(g.csv, `generated_seed${seed}.csv`, g.truth);
    } catch (err) {
      status.classList.add("error");
      status.textContent = "สร้าง log ไม่สำเร็จ: " + err.message;
    }
  });

  dlBtn.addEventListener("click", () => { if (last) download(last.csv, `ssh_generated_seed${last.seed}.csv`); });
  ansBtn.addEventListener("click", () => { if (last) download(last.answerCsv, `ssh_generated_seed${last.seed}_answer_key.csv`); });
})();
