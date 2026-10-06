// attack-types.js -- display text for the stage-2 attack-type model.
// Keys must match the classes in model/forest_type.json (and TYPE_INFO in
// v3/train_type_model.py). MITRE ATT&CK technique: Brute Force (T1110).

const ATTACK_TYPES = {
  burst_bruteforce: {
    name: "Burst brute force",
    th: "ยิงรัวใส่บัญชีเดียว",
    mitre: "T1110.001",
    signal: "ล้มติดกันจำนวนมากในเวลาสั้น (attempts_per_minute สูง)",
  },
  focused_bruteforce: {
    name: "Focused brute force",
    th: "เดารหัสเจาะจงบัญชีเดียว",
    mitre: "T1110.001",
    signal: "ล้มซ้ำบัญชีเดียว ช้ากว่า burst แต่ไม่หยุด",
  },
  large_dictionary_scanner: {
    name: "Dictionary scanner",
    th: "ไล่ชื่อผู้ใช้จำนวนมาก",
    mitre: "T1110.001",
    signal: "ชื่อผู้ใช้หลากหลายมาก ส่วนใหญ่ไม่มีในระบบ (invalid_ratio สูง)",
  },
  low_and_slow: {
    name: "Low-and-slow",
    th: "ยิงช้าเพื่อหลบการตรวจจับ",
    mitre: "T1110.001",
    signal: "แต่ละครั้งห่างกันนาน กระจายเป็นหลาย session",
  },
  persistent_multiday_attacker: {
    name: "Persistent multi-day",
    th: "IP เดิมกลับมาโจมตีหลายวัน",
    mitre: "T1110.001",
    signal: "ประวัติ IP: หลาย session กระจายหลายวัน (ip_active_span_days)",
  },
  coordinated_botnet_spike: {
    name: "Botnet spike",
    th: "หลาย IP ยิงเป้าเดียวพร้อมกัน",
    mitre: "T1110",
    signal: "IP อื่นยิงบัญชีเดียวกันในกรอบ 15 นาที (distinct_ips_same_target_15min)",
  },
  password_spray: {
    name: "Password spraying",
    th: "ใช้รหัสยอดฮิตลองกับหลายบัญชี",
    mitre: "T1110.003",
    signal: "หลายบัญชี บัญชีละไม่กี่ครั้ง ยิงช้า เลี่ยงการล็อกบัญชี",
  },
  credential_stuffing: {
    name: "Credential stuffing",
    th: "ใช้ user:password ที่หลุดมา",
    mitre: "T1110.004",
    signal: "หลายบัญชี บัญชีละครั้งเดียว มี login สำเร็จปนอยู่",
  },
};

function describeAttackType(key) {
  return ATTACK_TYPES[key] || { name: key, th: "", mitre: "T1110", signal: "" };
}

window.ATTACK_TYPES = ATTACK_TYPES;
window.describeAttackType = describeAttackType;
