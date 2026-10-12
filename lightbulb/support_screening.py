"""Conservative local screening; authenticated intake and DLP remain platform duties."""
from __future__ import annotations

from collections import Counter
import math
import re
import unicodedata
from typing import Sequence

NEVER_AUTO = {
    "auth": r"auth|p[4a@]ss[ -]?w[0o]rd|passw|credential|secret|token|log(?:g(?:ed|ing))?[ _-]?(?:in|on|out)|sign(?:ed|ing)?[ _-]?(?:in|on|out)|mfa|2fa|otp|two[ -]factor|locked out|oauth|sso|session|api[ _-]?key",
    "billing": r"\bbill(?:ing|ed)?\b|invoice|pay|paid|price|coupon|charge|refund|subscription|\bplan\b|checkout|credit card|stripe",
    "data_deletion": r"delet|remov|purge|archiv|eras|destroy|truncate|drop table|wip|disappear",
    "security_boundaries": r"permission|admin|role|access|other (?:customer|user)|another customer|someone else|private (?:order|record|data)|tenant|cross[ -]company|leak|gdpr|privacy|breach|hack|vulnerab|inject|xss|csrf|security|sandbox|firewall|exploit|unauthori|malware",
    "migrations": r"schema|migrat|database|export|import|flyway|alembic|alter table|sql|table.{0,30}column",
}
SECRET_CATEGORIES = frozenset(("private_key", "authorization", "secret_assignment", "key", "jwt", "url_credentials", "entropy"))
_CONFUSABLES = str.maketrans(dict(zip("аесорухіјѕкмтνοαρχει", "aecopyxijskmtvoapxei")))
_MARKER = re.compile(r"(\[REDACTED [a-z_ ]+\])")
# A block or quoted value may contain newlines and marker-looking reporter text.
# Consume it before splitting around existing redaction markers. For YAML blocks,
# redact through the end of the field: without a YAML document/schema we cannot
# safely distinguish secret continuation lines from unrelated indented evidence.
_ASSIGNMENT = re.compile(r'''(?<![\w.-])["']?(?P<key>[\w.-]{1,128}(?:[ \t]+phrase)?)["']?[ \t]*[:=][ \t]*''', re.I)
_SECRET_SUFFIXES = ("password", "passwd", "pwd", "pass", "pw", "passphrase", "passcode", "secret", "secretphrase", "token", "key", "auth", "authorization", "credential", "credentials", "private", "cookie")


def _redact_assignments(text: str) -> tuple[str, int]:
    pieces, end, count = [], 0, 0
    for match in _ASSIGNMENT.finditer(text):
        if match.start() < end:
            continue
        label = match["key"]
        key = re.sub(r"[\W_]", "", label).casefold()
        # Credential names commonly carry version numbers or qualifiers after
        # the sensitive token. Bound the assignment name before tokenizing it;
        # do not reintroduce the unbounded prefix/suffix regex search.
        words = re.sub(r"([a-z0-9])([A-Z])", r"\1_\2", label)
        tokens = re.split(r"[\W_]+", words.casefold())
        if not (key.rstrip("0123456789").endswith(_SECRET_SUFFIXES)
                or any(token.rstrip("0123456789") in _SECRET_SUFFIXES for token in tokens)):
            continue
        start = match.end()
        if start == len(text):
            continue
        if text[start] in "|>":
            stop = len(text)
        elif text[start] in "\"'":
            quote, stop = text[start], start + 1
            while stop < len(text):
                if text[stop] == "\\":
                    stop += 2
                elif text[stop] == quote:
                    stop += 1
                    if quote == "'" and text[stop:stop + 1] == quote:
                        stop += 1
                        continue
                    break
                else:
                    stop += 1
        else:
            # Unquoted prose/env values can contain spaces. Keep none of a
            # detected value, even if that conservatively consumes the line.
            stop = text.find("\n", start)
            if stop < 0:
                stop = len(text)
        pieces.extend((text[end:match.start()], "[REDACTED secret_assignment]"))
        end, count = min(stop, len(text)), count + 1
    return "".join((*pieces, text[end:])), count


def normalized(text: str) -> str:
    text = unicodedata.normalize("NFKC", text).casefold().translate(_CONFUSABLES)
    text = "".join(c for c in unicodedata.normalize("NFKD", text) if not unicodedata.category(c).startswith(("M", "C")) or c in "\n\t")
    return " ".join(text.split())


def screen(text: str) -> tuple[tuple[str, ...], tuple[str, ...]]:
    words = normalized(text)
    classes = tuple(key for key, pattern in NEVER_AUTO.items() if re.search(pattern, words))
    flags = []
    if any(c.isalpha() and not c.isascii() for c in words):
        flags.append("ambiguous_unicode")
    if re.search(r"\b(?:ign[0o]r|disregard|overrid|bypass|forget|execut|debug)|\bi g n o r e\b|\b(sudo|curl|agent|assistant|system|developer|codex|copilot|claude|llm|ai|backdoor|kindly)\b|\bcoding model\b|\b(route|endpoint|network|webhook)|\b(merge|deploy|git push)\b|\bplease\b", words):
        flags.append("agent_directive")
    if re.search(r"breach|vulnerab|exploit|unauthori|hack|malware|ransom|(?:other (?:customer|user)s?|someone else|another tenant).{0,45}(report|record|data|order)|(?:data|record|credential|password).{0,25}leak|leak.{0,25}(?:data|record|credential|password)", words):
        flags.append("security_report_signal")
    if re.search(r"\b(?:billed|charged|paid|payment|invoice|refund|subscription)\b.{0,60}\b(?:twice|duplicate|wrong|incorrect|missing|unauthori\w*)\b|\b(?:duplicate|wrong|incorrect|missing|unauthori\w*)\b.{0,60}\b(?:bill|charge|payment|invoice|refund)\b", words):
        flags.append("billing_report_signal")
    return classes, tuple(flags)


_PATTERNS = (
    ("private_key", re.compile(r"-----BEGIN (?:[A-Z ]*PRIVATE KEY|PGP PRIVATE KEY BLOCK)-----.*?(?:-----END (?:[A-Z ]*PRIVATE KEY|PGP PRIVATE KEY BLOCK)-----|\Z)", re.S)),
    ("authorization", re.compile(r"\b(?:Bearer|Basic)\s+[A-Za-z0-9._~+/=-]+", re.I)),
    ("url_credentials", re.compile(r"\b[a-z][a-z0-9+.-]*://[^\s/?#@]*@[^\s<>]+", re.I)),
    ("secret_assignment", re.compile(r"\b(?:password|passwd|passphrase|passcode|secret|token|api key)\s+(?:is|was)\s+[^\n]+", re.I)),
    ("secret_assignment", re.compile(r"(?<!\S)(?:--(?:password|passwd|passphrase|passcode)(?:[ =]+)|-p(?=\S)|-u[ \t]+[^\s:]+:)[^\n]+", re.I)),
    ("key", re.compile(r"\b(?:[sr]k[-_](?:live_|test_|proj-)?[A-Za-z0-9_-]{8,}|whsec_[A-Za-z0-9_-]{8,}|(?:AKIA|ASIA)[0-9A-Z]{16}|AIza[A-Za-z0-9_-]{16,}|gh[pousr]_[A-Za-z0-9]{12,}|github_pat_[A-Za-z0-9_]{12,}|glpat-[A-Za-z0-9_-]{8,}|xox[a-z]-[A-Za-z0-9-]{8,})\b")),
    ("key", re.compile(r"(?<!\w)[a-fA-F0-9]{32,64}(?!\w)")),
    ("jwt", re.compile(r"\beyJ[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+\b")),
    ("url", re.compile(r"\b(?:https?|wss?)://[^\s<>]+", re.I)),
    ("email", re.compile(r"(?<![\w.+-])[\w.+-]+@[\w.-]+\.[A-Za-z]{2,}\b")),
    ("personal_field", re.compile(r"\b(?:full[ _-]?name|name|address|date[ _-]?of[ _-]?birth|dob|sin|ssn|tfn|passport)\s*[:=]\s*[^\n;]+", re.I)),
    ("ip", re.compile(r"\b(?:\d{1,3}\.){3}\d{1,3}\b")),
    ("home_path", re.compile(r"(?:[A-Za-z]:\\Users\\|/(?:Users|home)/)[^\s/\\]+", re.I)),
)


def _luhn(digits: str) -> bool:
    values = [int(c) for c in digits[::-1]]
    return sum(n if i % 2 == 0 else (n * 2 - 9 if n > 4 else n * 2) for i, n in enumerate(values)) % 10 == 0


def redact_text(text: str, *, sensitive_values: Sequence[str] = ()) -> tuple[str, dict[str, int]]:
    if not isinstance(text, str) or len(text) > 20000:
        raise ValueError("SUPPORT_TEXT_INVALID")
    clean = unicodedata.normalize("NFKC", text)
    clean = "".join(c for c in clean if c in "\n\t" or not unicodedata.category(c).startswith("C"))
    counts: Counter[str] = Counter()
    def replace(pattern, category, accept=lambda _: True):
        nonlocal clean
        def sub(match):
            if not accept(match.group()):
                return match.group()
            counts[category] += 1
            return f"[REDACTED {category}]"
        # Never consume an existing marker, including markers from this pass.
        clean = "".join(part if _MARKER.fullmatch(part) else pattern.sub(sub, part) for part in _MARKER.split(clean))
    explicit = []
    for value in sensitive_values:
        if not isinstance(value, str) or not value.strip() or len(value) > 1000:
            raise ValueError("SUPPORT_REDACTION_VALUE_INVALID")
        explicit.append(re.compile(re.escape(unicodedata.normalize("NFKC", value)), re.I))
    def entropy(s):
        distribution = Counter(s)
        return -sum((n / len(s)) * math.log2(n / len(s)) for n in distribution.values()) >= 3.5 and any(c.isdigit() for c in s) and any(c.isalpha() for c in s)
    # Replacements can expose boundaries for earlier rules (an IP immediately
    # followed by a home path, for example). Never return an unstable result.
    for _ in range(8):
        before = clean
        clean, count = _redact_assignments(clean)
        if count:
            counts["secret_assignment"] += count
        for pattern in sorted(explicit, key=lambda p: len(p.pattern), reverse=True):
            replace(pattern, "personal_value")
        # Cards may use punctuation/whitespace separators; ISO dates remain dates.
        replace(re.compile(r"(?<!\w)\d(?:[\W_]*\d){12,18}(?!\w)"), "card", lambda s: _luhn(re.sub(r"\D", "", s)))
        for category, pattern in _PATTERNS:
            replace(pattern, category)
        replace(re.compile(r"(?<!\w)\+?\d[\d ()-]{6,}\d(?!\w)"), "number",
                lambda s: not re.fullmatch(r"\d{4}-\d{2}-\d{2}", s.strip()))
        replace(re.compile(r"(?<![\w])[A-Za-z0-9_+/=-]{24,}(?![\w])"), "entropy", entropy)
        clean = clean.strip()
        if clean == before:
            return clean, dict(counts)
    raise ValueError("SUPPORT_REDACTION_DID_NOT_STABILIZE")
