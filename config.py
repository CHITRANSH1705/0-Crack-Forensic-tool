import hashlib

# ─── PASSWORD ─────────────────────────────────────────────────────────────────
# Password is never stored in plaintext.
# To change it: hashlib.sha256("NewPassword".encode()).hexdigest()
PASSWORD_HASH = hashlib.sha256("Chitransh@123".encode()).hexdigest()

def verify_password(pwd: str) -> bool:
    return hashlib.sha256(pwd.encode()).hexdigest() == PASSWORD_HASH

# ─── FILE PATHS ───────────────────────────────────────────────────────────────
KEY_FILE       = "forensic_key.key"
ENCRYPTED_FILE = "advanced_forensic_report.enc"
LOG_FILE       = "forensic_run.log"

# ─── COLLECTION SETTINGS ──────────────────────────────────────────────────────
RECENT_FILES_HOURS = 48
MAX_PROCESSES      = 10
MAX_CONNECTIONS    = 10
MAX_HISTORY_ROWS   = 20
REPORT_VERSION     = "2.0"

# ─── ANALYSIS SETTINGS ────────────────────────────────────────────────────────
KNOWN_USB_VENDORS = {
    "sandisk", "kingston", "samsung", "logitech", "microsoft",
    "apple", "seagate", "western digital", "wd", "toshiba"
}

SUSPICIOUS_PATH_KEYWORDS  = ["temp", "appdata", "tmp", "roaming", "local\\temp"]
SUSPICIOUS_SITE_KEYWORDS  = ["malware", "hack", "torrent", "darkweb", "exploit", "crack"]
SUSPICIOUS_TASK_KEYWORDS  = ["malware", "hack", "temp", "\\appdata\\", "\\temp\\"]
PRIVATE_IP_PREFIXES       = ("192.", "10.", "172.", "127.", "::1", "0.0.0.0")
SHUTDOWN_ANOMALY_KEYWORDS = ["unexpected", "crash", "failed", "error", "critical"]
