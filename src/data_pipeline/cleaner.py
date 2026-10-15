"""Data Sanitization, Secret Scrubbing, and Security Metadata Extraction."""

import re
from typing import Dict, Any, List, Tuple

# Regex patterns for secret scrubbing
SECRET_PATTERNS = [
    (r'(?i)(AKIA[0-9A-Z]{16})', '<REDACTED_AWS_KEY>'),
    (r'(?i)(password|passwd|pwd|secret)\s*[:=]\s*["\']([^"\']{4,})["\']', r'\1="<REDACTED_SECRET>"'),
    (r'(?i)(api[_-]?key|access[_-]?token|bearer)\s*[:=]\s*["\']([^"\']{8,})["\']', r'\1="<REDACTED_API_KEY>"'),
    (r'-----BEGIN [A-Z ]+ PRIVATE KEY-----[\s\S]+?-----END [A-Z ]+ PRIVATE KEY-----', '<REDACTED_PRIVATE_KEY>'),
    (r'\b(192\.168\.\d{1,3}\.\d{1,3}|10\.\d{1,3}\.\d{1,3}\.\d{1,3}|172\.(?:1[6-9]|2[0-9]|3[01])\.\d{1,3}\.\d{1,3}|169\.254\.169\.254)\b', '<INTERNAL_IP>'),
]

# Patterns for extracting security entities
CVE_PATTERN = re.compile(r'\bCVE-\d{4}-\d{4,7}\b', re.IGNORECASE)
CWE_PATTERN = re.compile(r'\bCWE-\d{1,4}\b', re.IGNORECASE)
CVSS_PATTERN = re.compile(r'\b(?:CVSS(?::|/|\s+score:?|\s+v[234]:?)?\s*)(10(?:\.0)?|[0-9]\.[0-9])\b', re.IGNORECASE)

CATEGORY_KEYWORDS = {
    "SQL Injection": ["sql injection", "sqli", "union select", "prepared statement"],
    "Cross-Site Scripting (XSS)": ["cross-site scripting", "xss", "dompurify", "csp header"],
    "OS Command Injection": ["command injection", "os injection", "subprocess.run", "os.system"],
    "Server-Side Request Forgery (SSRF)": ["ssrf", "server-side request forgery", "169.254.169.254"],
    "Insecure Deserialization": ["deserialization", "pickle.loads", "objectinputstream", "unserialize"],
    "Path Traversal": ["path traversal", "directory traversal", "../", "lfi"],
    "Hardcoded Credentials": ["hardcoded", "hard-coded", "credentials", "exposed secret"],
    "Authentication Bypass": ["auth bypass", "improper authentication", "jwt bypass", "mfa"],
}


def sanitize_secrets(text: str) -> str:
    """Detect and replace passwords, API keys, private keys, and internal IPs with safe placeholders."""
    cleaned = text
    for pattern, replacement in SECRET_PATTERNS:
        cleaned = re.sub(pattern, replacement, cleaned)
    return cleaned


def clean_text(text: str) -> str:
    """Normalize whitespace, remove carriage returns, and strip broken formatting."""
    # Replace non-breaking spaces and tabs
    normalized = text.replace('\r\n', '\n').replace('\r', '\n').replace('\xa0', ' ')
    # Remove excessive blank lines (more than 2 consecutive)
    normalized = re.sub(r'\n{3,}', '\n\n', normalized)
    # Remove trailing/leading whitespaces on each line
    lines = [l.strip() for l in normalized.split('\n')]
    return '\n'.join(lines).strip()


def extract_security_metadata(text: str) -> Dict[str, Any]:
    """Extract CVEs, CWEs, CVSS scores, categories, and severity ratings from text."""
    cves = sorted(list(set(CVE_PATTERN.findall(text))))
    cwes = sorted(list(set(CWE_PATTERN.findall(text))))
    
    cvss_matches = CVSS_PATTERN.findall(text)
    cvss_score = float(cvss_matches[0]) if cvss_matches else None

    # Detect category
    text_lower = text.lower()
    categories = []
    for cat, kws in CATEGORY_KEYWORDS.items():
        if any(kw in text_lower for kw in kws):
            categories.append(cat)
    category = categories[0] if categories else "General Security"

    # Assess severity
    severity = "MEDIUM"
    if cvss_score:
        if cvss_score >= 9.0:
            severity = "CRITICAL"
        elif cvss_score >= 7.0:
            severity = "HIGH"
        elif cvss_score >= 4.0:
            severity = "MEDIUM"
        else:
            severity = "LOW"
    elif "critical" in text_lower:
        severity = "CRITICAL"
    elif "high" in text_lower:
        severity = "HIGH"

    return {
        "cve_ids": [c.upper() for c in cves],
        "cwe_ids": [c.upper() for c in cwes],
        "cvss_score": cvss_score,
        "category": category,
        "severity": severity,
    }


def process_and_sanitize(raw_text: str) -> Tuple[str, Dict[str, Any]]:
    """Clean text, scrub secrets, and extract structured metadata."""
    cleaned = clean_text(raw_text)
    sanitized = sanitize_secrets(cleaned)
    metadata = extract_security_metadata(sanitized)
    return sanitized, metadata
