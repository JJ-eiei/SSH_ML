// class-info.js -- display text for the 11 classes of the multiclass model.
// Keys must match "classes" in model/forest.json (and CLASS_MAP in
// v3/train_multiclass_model.py). Attack types map to MITRE ATT&CK Brute
// Force (T1110).

const CLASS_INFO = {
  // ---- legit behaviours ----
  legit_login: {
    group: "legit", name: "Login ปกติ", th: "ผู้ใช้เข้าระบบสำเร็จตามปกติ",
    signal: "สำเร็จทันที ไม่มีการลองผิด",
  },
  legit_typo: {
    group: "legit", name: "ผู้ใช้พิมพ์รหัสผิด", th: "ลองผิดไม่กี่ครั้ง แบบคนพิมพ์ (มักเข้าได้ในที่สุด)",
    signal: "ผิดไม่กี่ครั้ง จังหวะแบบคนพิมพ์ แล้วจบด้วยสำเร็จ",
  },
  shared_ip_legit: {
    group: "legit", name: "หลายคนใช้ IP ร่วม", th: "ออฟฟิศ/NAT หลายบัญชี login สำเร็จ",
    signal: "หลายชื่อผู้ใช้จาก IP เดียว แต่เกือบทั้งหมดสำเร็จ",
  },
  // ---- attack types ----
  burst_bruteforce: {
    group: "attack", name: "Burst brute force", th: "ยิงรัวใส่บัญชีเดียว", mitre: "T1110.001",
    signal: "ล้มติดกันจำนวนมากในเวลาสั้น (attempts_per_minute สูง)",
  },
  focused_bruteforce: {
    group: "attack", name: "Focused brute force", th: "เดารหัสเจาะจงบัญชีเดียว", mitre: "T1110.001",
    signal: "ล้มซ้ำบัญชีเดียว ช้ากว่า burst แต่ไม่หยุด",
  },
  large_dictionary_scanner: {
    group: "attack", name: "Dictionary scanner", th: "ไล่ชื่อผู้ใช้จำนวนมาก", mitre: "T1110.001",
    signal: "ชื่อผู้ใช้หลากหลายมาก ส่วนใหญ่ไม่มีในระบบ (invalid_ratio สูง)",
  },
  low_and_slow: {
    group: "attack", name: "Low-and-slow", th: "ยิงช้าเพื่อหลบการตรวจจับ", mitre: "T1110.001",
    signal: "แต่ละครั้งห่างกันนาน กระจายเป็นหลาย session",
  },
  persistent_multiday_attacker: {
    group: "attack", name: "Persistent multi-day", th: "IP เดิมกลับมาโจมตีหลายวัน", mitre: "T1110.001",
    signal: "ประวัติ IP: หลาย session กระจายหลายวัน (ip_active_span_days)",
  },
  coordinated_botnet_spike: {
    group: "attack", name: "Botnet spike", th: "หลาย IP ยิงเป้าเดียวพร้อมกัน", mitre: "T1110",
    signal: "IP อื่นยิงบัญชีเดียวกันในกรอบ 15 นาที (distinct_ips_same_target_15min)",
  },
  password_spray: {
    group: "attack", name: "Password spraying", th: "ใช้รหัสยอดฮิตลองกับหลายบัญชี", mitre: "T1110.003",
    signal: "หลายบัญชี บัญชีละไม่กี่ครั้ง ยิงช้า เลี่ยงการล็อกบัญชี",
  },
  credential_stuffing: {
    group: "attack", name: "Credential stuffing", th: "ใช้ user:password ที่หลุดมา", mitre: "T1110.004",
    signal: "หลายบัญชี บัญชีละครั้งเดียว มี login สำเร็จปนอยู่",
  },
};

function describeClass(key) {
  return CLASS_INFO[key] || { group: "attack", name: key, th: "", signal: "" };
}

window.CLASS_INFO = CLASS_INFO;
window.describeClass = describeClass;
