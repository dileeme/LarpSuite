"""
Static code analyzer for local source directories.

Checks performed:
  - File/directory counts, lines of code per language
  - API placeholder detection (TODO, hardcoded keys, localhost URLs, etc.)
  - Memory leak indicators (unclosed resources, missing free/close calls)
  - Buffer/integer overflow patterns
  - SQL injection, XSS, command injection sinks
  - Hardcoded credentials / secrets
  - Insecure crypto usage
  - Path traversal patterns
  - Dangerous eval/exec usage
"""

import os
import re
from dataclasses import dataclass, field
from pathlib import Path

# ── Language mapping ──────────────────────────────────────────────────────────

LANG_MAP: dict[str, str] = {
    ".py":   "Python",
    ".js":   "JavaScript",
    ".ts":   "TypeScript",
    ".tsx":  "TypeScript/React",
    ".jsx":  "JavaScript/React",
    ".java": "Java",
    ".cs":   "C#",
    ".cpp":  "C++",
    ".cc":   "C++",
    ".c":    "C",
    ".h":    "C/C++ Header",
    ".hpp":  "C++ Header",
    ".go":   "Go",
    ".rs":   "Rust",
    ".php":  "PHP",
    ".rb":   "Ruby",
    ".kt":   "Kotlin",
    ".swift":"Swift",
    ".html": "HTML",
    ".css":  "CSS",
    ".sql":  "SQL",
    ".sh":   "Shell",
    ".bat":  "Batch",
    ".ps1":  "PowerShell",
    ".yaml": "YAML",
    ".yml":  "YAML",
    ".json": "JSON",
    ".xml":  "XML",
    ".md":   "Markdown",
    ".env":  "Env file",
}

SKIP_DIRS = {".git", "__pycache__", "node_modules", ".venv", "venv", "dist", "build", ".idea", ".vscode"}

# ── Finding dataclass ─────────────────────────────────────────────────────────

@dataclass
class Finding:
    severity: str        # CRITICAL / HIGH / MEDIUM / LOW / INFO
    category: str        # e.g. "Memory Leak", "SQL Injection"
    file:     str
    line:     int
    snippet:  str
    detail:   str


# ── Check registry ────────────────────────────────────────────────────────────

# Each rule: (severity, category, regex_pattern, detail_template)
_RULES: list[tuple[str, str, re.Pattern, str]] = []

def _rule(severity: str, category: str, pattern: str, detail: str, flags=re.I):
    _RULES.append((severity, category, re.compile(pattern, flags), detail))

# -- API Placeholders --
_rule("MEDIUM", "API Placeholder",
      r"(TODO|FIXME|HACK|XXX|PLACEHOLDER|YOUR[_\-]?API[_\-]?KEY|INSERT[_\-]?KEY[_\-]?HERE)",
      "Unresolved placeholder found — review before deployment")
_rule("HIGH", "API Placeholder",
      r"(api[_\-]?key|apikey|api[_\-]?secret)\s*=\s*[\"'][^\"']{6,}[\"']",
      "Hardcoded API key assignment")
_rule("HIGH", "Hardcoded Secret",
      r"(password|passwd|pwd|secret|token|auth[_\-]?token)\s*=\s*[\"'][^\"']{4,}[\"']",
      "Hardcoded credential — move to environment variable or secrets manager")
_rule("CRITICAL", "Hardcoded Secret",
      r"(AKIA[0-9A-Z]{16})",
      "AWS Access Key ID found in source")
_rule("CRITICAL", "Hardcoded Secret",
      r"-----BEGIN (RSA |EC |OPENSSH )?PRIVATE KEY-----",
      "Private key embedded in source")
_rule("HIGH", "Hardcoded Secret",
      r"ghp_[A-Za-z0-9]{36}",
      "GitHub personal access token found")
_rule("HIGH", "Hardcoded Secret",
      r"(xox[baprs]-[0-9A-Za-z\-]{10,})",
      "Slack token found in source")

# -- Localhost / dev URLs --
_rule("LOW", "API Placeholder",
      r"(https?://(localhost|127\.0\.0\.1|0\.0\.0\.0)(:\d+)?[/\w]*)",
      "Hardcoded localhost URL — likely a development placeholder")
_rule("LOW", "API Placeholder",
      r"(https?://[a-z0-9\-]+\.(example|test|staging|dev)\.[a-z]{2,})",
      "Dev/staging URL hardcoded in source")

# -- Memory leaks (Python / Java / C++) --
_rule("HIGH", "Memory Leak",
      r"\bopen\s*\([^)]+\)\s*(?!.*\bwith\b)",
      "File opened without 'with' context manager — may not be closed on error (Python)")
_rule("MEDIUM", "Memory Leak",
      r"\bnew\s+\w+\s*\([^)]*\)\s*;(?!\s*/\*.*free|delete)",
      "Heap allocation without visible free/delete nearby (C++/Java)")
_rule("MEDIUM", "Memory Leak",
      r"malloc\s*\(|calloc\s*\(|realloc\s*\(",
      "Manual memory allocation — verify corresponding free()")
_rule("MEDIUM", "Memory Leak",
      r"(getInputStream|getOutputStream|openConnection)\s*\(",
      "I/O stream opened — ensure it is closed in a finally block (Java)")
_rule("MEDIUM", "Memory Leak",
      r"(createConnection|pool\.connect)\s*\(",
      "DB connection acquired — verify release/close on all paths")

# -- Buffer / Integer Overflow --
_rule("HIGH", "Buffer Overflow",
      r"\bgets\s*\(",
      "gets() is unsafe — use fgets() instead (C/C++)")
_rule("HIGH", "Buffer Overflow",
      r"\bsprintf\s*\(",
      "sprintf() without length limit — use snprintf()")
_rule("HIGH", "Buffer Overflow",
      r"\bstrcpy\s*\(",
      "strcpy() without bounds check — use strncpy() or strlcpy()")
_rule("MEDIUM", "Buffer Overflow",
      r"\bstrcat\s*\(",
      "strcat() without bounds check — use strncat()")
_rule("MEDIUM", "Integer Overflow",
      r"\(int\)\s*strlen|\(int\)\s*sizeof",
      "Casting size_t to int may overflow on large inputs")

# -- SQL Injection --
_rule("HIGH", "SQL Injection",
      r'(execute|query|raw|cursor\.execute)\s*\(\s*[f"\'](SELECT|INSERT|UPDATE|DELETE|DROP)',
      "SQL query built with string formatting — use parameterised queries")
_rule("HIGH", "SQL Injection",
      r'["\']\s*\+\s*(user|input|param|request|query|data)\b',
      "String concatenation into query — potential SQL injection sink")
_rule("MEDIUM", "SQL Injection",
      r'\.format\s*\([^)]*\)\s*(?=.*(?:SELECT|INSERT|UPDATE|DELETE))',
      ".format() used near SQL keyword — parameterise the query")

# -- XSS --
_rule("HIGH", "XSS",
      r'innerHTML\s*=\s*(?!["\']\s*["\'"])',
      "innerHTML assignment — may allow XSS if value is user-controlled")
_rule("HIGH", "XSS",
      r'document\.write\s*\(',
      "document.write() — XSS risk if argument contains user input")
_rule("MEDIUM", "XSS",
      r'\.html\s*\(\s*[^"\')]',
      "jQuery .html() with dynamic argument — potential XSS")

# -- Command Injection --
_rule("CRITICAL", "Command Injection",
      r'(os\.system|subprocess\.(call|run|Popen|check_output))\s*\(\s*[f"\']',
      "Shell command built with f-string/concatenation — potential command injection")
_rule("HIGH", "Command Injection",
      r'shell\s*=\s*True',
      "subprocess called with shell=True — avoid or sanitize input rigorously")
_rule("HIGH", "Command Injection",
      r'(exec|eval|execfile)\s*\(',
      "Dynamic code execution — dangerous if input is user-controlled")
_rule("HIGH", "Command Injection",
      r'Runtime\.getRuntime\(\)\.exec\s*\(',
      "Java Runtime.exec() — potential command injection")

# -- Path Traversal --
_rule("HIGH", "Path Traversal",
      r'\.\./|\.\.\\\\',
      "Path traversal sequence '../' — validate and sanitise file paths")
_rule("MEDIUM", "Path Traversal",
      r'open\s*\([^)]*request|open\s*\([^)]*param|open\s*\([^)]*user',
      "File open with user-controlled path — validate against an allowlist")

# -- Insecure Crypto --
_rule("HIGH", "Insecure Crypto",
      r'\b(MD5|SHA1|SHA-1|DES|RC4|3DES|Triple DES)\b',
      "Weak or deprecated cryptographic algorithm")
_rule("MEDIUM", "Insecure Crypto",
      r'random\.(random|randint|choice)\s*\(',
      "Non-cryptographic PRNG used — use secrets module for security-sensitive values")
_rule("HIGH", "Insecure Crypto",
      r'ssl\._create_unverified_context|verify\s*=\s*False',
      "TLS certificate verification disabled")

# -- Sensitive data exposure --
_rule("MEDIUM", "Sensitive Data",
      r'(print|console\.log|System\.out\.print|logger\.(debug|info))\s*\(.*\b(password|token|secret|key)\b',
      "Sensitive value may be logged — review log statement")
_rule("INFO", "Sensitive Data",
      r'#\s*(noqa|nosec|type:\s*ignore)',
      "Security/linting suppression comment — verify suppression is intentional")


# ── Core analysis function ────────────────────────────────────────────────────

@dataclass
class AnalysisResult:
    root: str
    total_files:    int = 0
    total_dirs:     int = 0
    total_lines:    int = 0
    blank_lines:    int = 0
    comment_lines:  int = 0
    lines_by_lang:  dict = field(default_factory=dict)
    files_by_lang:  dict = field(default_factory=dict)
    findings:       list = field(default_factory=list)
    errors:         list = field(default_factory=list)   # (file, message)


def analyse_directory(root: str, progress_cb=None) -> AnalysisResult:
    """
    Walk `root` recursively and run all checks.
    `progress_cb(current_file: str, scanned: int, total: int)` is called for each file.
    """
    result = AnalysisResult(root=root)
    root_path = Path(root)

    # Collect all files first so we can report progress
    all_files: list[Path] = []
    for dirpath, dirnames, filenames in os.walk(root):
        dirnames[:] = [d for d in dirnames if d not in SKIP_DIRS]
        result.total_dirs += len(dirnames)
        for fname in filenames:
            all_files.append(Path(dirpath) / fname)

    result.total_files = len(all_files)

    for idx, fpath in enumerate(all_files):
        if progress_cb:
            progress_cb(str(fpath), idx + 1, result.total_files)

        ext = fpath.suffix.lower()
        lang = LANG_MAP.get(ext, "Other")

        # Count files per language
        result.files_by_lang[lang] = result.files_by_lang.get(lang, 0) + 1

        # Skip binary / non-text files
        if ext not in LANG_MAP or ext in (".png", ".jpg", ".jpeg", ".gif", ".ico",
                                           ".woff", ".woff2", ".ttf", ".eot",
                                           ".zip", ".tar", ".gz", ".bin"):
            continue

        try:
            text = fpath.read_text(encoding="utf-8", errors="replace")
        except Exception as exc:
            result.errors.append((str(fpath), str(exc)))
            continue

        lines = text.splitlines()
        line_count = len(lines)
        result.total_lines += line_count
        result.lines_by_lang[lang] = result.lines_by_lang.get(lang, 0) + line_count

        blank   = sum(1 for l in lines if l.strip() == "")
        comment = sum(1 for l in lines if re.match(r"^\s*(#|//|/\*|\*|<!--|--|;)", l))
        result.blank_lines   += blank
        result.comment_lines += comment

        # Run each rule over every line
        rel = str(fpath.relative_to(root_path))
        for lineno, line in enumerate(lines, start=1):
            for severity, category, pattern, detail in _RULES:
                if pattern.search(line):
                    result.findings.append(Finding(
                        severity=severity,
                        category=category,
                        file=rel,
                        line=lineno,
                        snippet=line.strip()[:200],
                        detail=detail,
                    ))
                    break  # one finding per line per pass (avoid duplicates on same line)

    return result
