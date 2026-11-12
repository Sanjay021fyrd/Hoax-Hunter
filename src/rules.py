"""Rule-based red-flag detection.

Each rule looks for one well-known scam tactic. A rule that fires produces a
`Flag` with a weight and the exact text that triggered it, so the UI can
explain *why* a message looks suspicious (and highlight it).

The rule score is the sum of the weights of the flags that fired, capped at 100.
"""

from __future__ import annotations

import re
from dataclasses import dataclass
from urllib.parse import urlparse

MAX_TEXT_LEN = 5000
_MAX_EVIDENCE = 5

# --------------------------------------------------------------------------- #
# Data classes
# --------------------------------------------------------------------------- #


@dataclass(frozen=True)
class Flag:
    id: str
    title: str
    explanation: str
    weight: int
    evidence: tuple[str, ...]
    spans: tuple[tuple[int, int], ...]
    # Critical = something no legitimate sender ever does (e.g. asking you to
    # share your OTP, or a fake bank website). One is enough for "Likely Scam".
    critical: bool = False


@dataclass(frozen=True)
class RuleResult:
    score: int  # 0-100
    flags: tuple[Flag, ...]

    @property
    def critical(self) -> bool:
        return any(f.critical for f in self.flags)


# --------------------------------------------------------------------------- #
# URL detection and analysis
# --------------------------------------------------------------------------- #

_TLDS = (
    "com|in|net|org|co|xyz|top|click|link|info|icu|buzz|cc|tk|ml|ga|cf|gq|work|"
    "loan|online|site|shop|live|me|ly|gl|ink|page|app|io|us|uk|biz|vip|club|"
    "fun|cn|ru|sbs|cyou|rest|monster|apk"
)
URL_RE = re.compile(
    rf"""(?ix)
    \bhttps?://[^\s<>"']+
    | \bwww\.[^\s<>"']+
    | (?<![@\w.\-/])(?:[a-z0-9\-]+\.)+(?:{_TLDS})\b(?![a-z0-9\-])(?:/[^\s<>"']*)?
    """
)

URL_SHORTENERS = {
    "bit.ly",
    "tinyurl.com",
    "t.co",
    "goo.gl",
    "is.gd",
    "cutt.ly",
    "rb.gy",
    "shorturl.at",
    "ow.ly",
    "tiny.cc",
    "buff.ly",
    "rebrand.ly",
    "t.ly",
    "s.id",
}
SUSPICIOUS_TLDS = {
    "xyz",
    "top",
    "click",
    "link",
    "icu",
    "buzz",
    "cc",
    "tk",
    "ml",
    "ga",
    "cf",
    "gq",
    "work",
    "loan",
    "sbs",
    "cyou",
    "rest",
    "monster",
    "vip",
    "online",
    "site",
    "shop",
    "club",
    "info",
    "apk",
}
# brand keyword -> domains that really belong to that brand
OFFICIAL_DOMAINS = {
    "sbi": ["sbi.co.in", "onlinesbi.sbi", "sbicard.com", "sbi.bank.in"],
    "hdfc": ["hdfcbank.com", "hdfc.com", "hdfcbank.net"],
    "icici": ["icicibank.com", "icici.com", "icicidirect.com"],
    "axis": ["axisbank.com"],
    "kotak": ["kotak.com"],
    "pnb": ["pnbindia.in"],
    "paytm": ["paytm.com"],
    "phonepe": ["phonepe.com"],
    "gpay": ["pay.google.com"],
    "amazon": ["amazon.in", "amazon.com"],
    "flipkart": ["flipkart.com"],
    "netflix": ["netflix.com"],
    "irctc": ["irctc.co.in"],
    "fedex": ["fedex.com"],
    "dhl": ["dhl.com"],
    "dtdc": ["dtdc.in", "dtdc.com"],
    "indiapost": ["indiapost.gov.in"],
    "airtel": ["airtel.in"],
    "jio": ["jio.com"],
    "whatsapp": ["whatsapp.com", "wa.me"],
    "instagram": ["instagram.com"],
    "lic": ["licindia.in"],
}


def find_urls(text: str) -> list[tuple[str, int, int]]:
    """Return (url, start, end) for every link in the text."""
    found = []
    for m in URL_RE.finditer(text):
        raw = m.group(0)
        url = raw.rstrip(".,;:!?)]}\"'")
        if url:
            found.append((url, m.start(), m.start() + len(url)))
    return found


def _host(url: str) -> str:
    candidate = url if re.match(r"(?i)https?://", url) else "http://" + url
    try:
        host = urlparse(candidate).hostname or ""
    except ValueError:
        return ""
    return host.lower().rstrip(".")


def _domain_matches(host: str, domain: str) -> bool:
    return host == domain or host.endswith("." + domain)


def _is_official(host: str) -> bool:
    if host.endswith(".gov.in") or host.endswith(".nic.in"):
        return True
    return any(_domain_matches(host, d) for ds in OFFICIAL_DOMAINS.values() for d in ds)


def is_official_url(url: str) -> bool:
    """True if the link points to a known genuine domain (brand or .gov.in)."""
    host = _host(url)
    return bool(host) and _is_official(host)


def _lookalike_brand(host: str) -> str | None:
    """Brand name used in a domain that does not belong to that brand."""
    tokens = re.split(r"[.\-_]", host)
    for brand, domains in OFFICIAL_DOMAINS.items():
        if any(t.startswith(brand) for t in tokens) and not any(
            _domain_matches(host, d) for d in domains
        ):
            return brand
    return None


def _url_flags(text: str) -> list[Flag]:
    urls = find_urls(text)
    if not urls:
        return []

    buckets: dict[str, list[tuple[str, int, int]]] = {
        "has_link": [],
        "shortened_link": [],
        "suspicious_domain": [],
        "ip_link": [],
        "lookalike_domain": [],
        "obfuscated_link": [],
    }
    for url, start, end in urls:
        host = _host(url)
        item = (url, start, end)
        if not host:
            buckets["obfuscated_link"].append(item)
            continue
        if _is_official(host):
            continue
        buckets["has_link"].append(item)
        if host in URL_SHORTENERS:
            buckets["shortened_link"].append(item)
        if host.rsplit(".", 1)[-1] in SUSPICIOUS_TLDS:
            buckets["suspicious_domain"].append(item)
        if re.fullmatch(r"\d{1,3}(?:\.\d{1,3}){3}", host):
            buckets["ip_link"].append(item)
        if _lookalike_brand(host):
            buckets["lookalike_domain"].append(item)
        netloc = url.split("//")[-1].split("/")[0]
        if "@" in netloc or "xn--" in host or host.count("-") >= 3:
            buckets["obfuscated_link"].append(item)

    meta = {
        "has_link": (
            "Contains a link",
            "Scam messages usually push you to click a link.",
            8,
        ),
        "shortened_link": (
            "Shortened link",
            "Link shorteners hide the real destination site.",
            20,
        ),
        "suspicious_domain": (
            "Suspicious website ending",
            "This domain ending (.xyz, .top, .click ...) is cheap and heavily used for scam sites.",
            20,
        ),
        "ip_link": (
            "Link points to a raw IP address",
            "Real companies use proper domain names, not numeric addresses.",
            25,
        ),
        "lookalike_domain": (
            "Fake lookalike website",
            "The link uses a well-known brand name but is NOT that brand's real website.",
            30,
        ),
        "obfuscated_link": (
            "Disguised link",
            "The link uses tricks (many hyphens, '@', odd characters) to look legitimate.",
            20,
        ),
    }
    flags = []
    for fid, items in buckets.items():
        if items:
            title, expl, weight = meta[fid]
            flags.append(
                Flag(
                    fid,
                    title,
                    expl,
                    weight,
                    tuple(dict.fromkeys(u for u, _, _ in items))[:_MAX_EVIDENCE],
                    tuple((s, e) for _, s, e in items),
                    critical=(fid == "lookalike_domain"),
                )
            )
    return flags


# --------------------------------------------------------------------------- #
# Keyword / pattern rules
# --------------------------------------------------------------------------- #

_SENSITIVE = (
    r"(?:otp|pin|upi pin|cvv|password|passcode|aadhaar|aadhar|pan|card number|"
    r"card details|bank details|account details|account number|login details|"
    r"date of birth|dob)"
)
_THREAT_SUBJECT = (
    r"(?:account|a/c|kyc|card|sim|wallet|upi|connection|electricity|power|"
    r"services?|aadhaar|aadhar|pan|policy|subscription|membership|gas|whatsapp|"
    r"supply|meter)"
)
_THREAT_ACTION = (
    r"(?:blocked?|suspended?|suspension|deactivated?|deactivation|expired?|"
    r"expiring|expires|disconnected?|disconnection|closed?|closure|frozen|"
    r"freeze|locked?|terminated?|cancell?ed|lapse[sd]?|restricted|on hold|"
    r"deleted|banned|flagged|discontinued|cut(?: off)?)"
)

# Phrases like "do not share your OTP" are warnings, not requests: mask them
# (same length, so match positions stay valid) before checking for requests.
_NEGATED_RE = re.compile(
    r"(?i)\b(?:do not|don't|dont|never|not)\s+(?:\w+\s+){0,2}?"
    r"(?:share|disclose|give|reveal|tell)\b[^.!?\n]*"
)


@dataclass(frozen=True)
class _Rule:
    id: str
    title: str
    explanation: str
    weight: int
    pattern: re.Pattern
    mask_negation: bool = False
    critical: bool = False


def _rule(id, title, explanation, weight, pattern, mask_negation=False, critical=False):
    return _Rule(
        id,
        title,
        explanation,
        weight,
        re.compile(pattern, re.I),
        mask_negation,
        critical,
    )


RULES: tuple[_Rule, ...] = (
    _rule(
        "urgency",
        "Pressure / urgency",
        "Scammers rush you so you act before thinking.",
        15,
        r"\b(?:urgent(?:ly)?|immediate(?:ly)?|right now|act now|asap|last chance|"
        r"hurry|expires? (?:today|soon|tonight|in \d+)|"
        r"within \d+ ?(?:hours?|hrs?|mins?|minutes?)|today only|"
        r"final (?:notice|warning|reminder)|limited (?:time|stock|slots?|offer)|"
        r"at once|without delay|before it'?s too late)\b",
    ),
    _rule(
        "prize_bait",
        "Prize / reward bait",
        "Unexpected prizes, lotteries and cashback are a classic hook.",
        25,
        r"\b(?:you(?:'ve| have)? won|you are (?:a |the )?(?:winner|selected)|"
        r"selected for|winner|lottery|lucky draw|jackpot|prize|congratulations|"
        r"congrats|claim (?:your|the)|gift card|free (?:gift|iphone|recharge|"
        r"entry|diamonds|cash)|cashback|reward points?|giveaway)\b",
    ),
    _rule(
        "credential_request",
        "Asks you to share your OTP / PIN / ID details",
        "Banks and genuine companies NEVER ask you to share or send your OTP, "
        "PIN, CVV, password or ID details by message.",
        35,
        rf"\b(?:share|send|provide|give|forward|reply with|tell)\b"
        # (?!my\b): "send you MY account number" is someone offering their own details
        rf"(?:\W+(?!my\b)\w+){{0,5}}?\W+{_SENSITIVE}\b"
        r"|\b(?:collect request|approve the request|enter your upi pin to)\b",
        mask_negation=True,
        critical=True,
    ),
    _rule(
        "credential_entry",
        "Asks you to enter / confirm personal details",
        "Be careful about entering OTP, PIN or ID details because a message told you to.",
        20,
        rf"\b(?:enter|confirm|verify|update|submit|fill)\b"
        rf"(?:\W+(?!my\b)\w+){{0,5}}?\W+{_SENSITIVE}\b",
        mask_negation=True,
    ),
    _rule(
        "security_alarm",
        "Fake security alarm",
        "Scammers claim your account was hacked or has 'unusual activity' to scare you.",
        15,
        r"\b(?:compromised|hacked|unauthori[sz]ed (?:login|access|transaction)|"
        r"suspicious (?:activity|login|transaction)|unusual (?:login|activity|sign-?in)|"
        r"security alert)\b",
    ),
    _rule(
        "account_threat",
        "Threat to your account / service",
        "Fake 'your account will be blocked' warnings are used to panic you "
        "into clicking or calling.",
        25,
        rf"\b{_THREAT_SUBJECT}\b(?:\W+\w+){{0,8}}?\W+"
        rf"(?:will be |is |has been |been |are |gets? )?{_THREAT_ACTION}\b"
        r"|\b(?:update|complete|verify|re-?verify|link|renew)\b(?:\W+\w+){0,3}?"
        r"\W+(?:kyc|e-?kyc|pan|aadhaar|aadhar)\b",
    ),
    _rule(
        "authority_threat",
        "Fake authority / legal threat",
        "Police, tax and court threats are used to frighten victims into paying.",
        20,
        r"\b(?:arrest(?:ed)?|warrant|legal action|court (?:case|notice)|"
        r"case (?:is |has been )?registered|face (?:arrest|action)|"
        r"pay (?:a |the )?(?:fine|penalty)|fine of rs|police (?:will )?visit|"
        r"unpaid challan|pending (?:traffic )?challan)\b",
    ),
    _rule(
        "fee_payment",
        "Asks for an upfront fee",
        "Genuine prizes, loans and refunds never require you to pay first.",
        20,
        r"\b(?:(?:processing|registration|clearance|release|insurance|activation|"
        r"verification|documentation|file|gst|handling|booking|unlock|re-?delivery)"
        r"\s(?:fee|charges?)|customs (?:fee|duty)|duty payment|small fee|"
        r"advance payment|security deposit|pay advance|token amount|refundable)\b",
    ),
    _rule(
        "loan_bait",
        "Too-good-to-be-true loan offer",
        "Instant loans with no documents are used to collect 'fees' or steal your details.",
        20,
        r"\b(?:instant loan|loan (?:approved|offer|sanctioned)|pre-?approved|"
        r"(?:zero|no|without) (?:documents?|income proof|paperwork|cibil))\b",
    ),
    _rule(
        "money_request",
        "Asks you to send money",
        "Be careful with any message asking you to send or pay an amount.",
        15,
        r"\b(?:send|transfer|pay|deposit|remit)\b(?:\W+\w+){0,4}?\W*"
        r"(?:rs\.?|₹|inr|usd|\$)\s?\d[\d,]*"
        r"|\b(?:need|require)\b(?:\W+\w+){0,2}?\W*(?:rs\.?|₹|inr)\s?\d[\d,]*",
    ),
    _rule(
        "job_investment",
        "Job / investment scheme",
        "'Easy money' jobs and guaranteed-return investments are common scams.",
        25,
        r"\b(?:work from home|part[- ]?time (?:job|work)|data entry|typing job|"
        r"daily income|earn\b(?:\W+\w+){0,5}?\W+(?:daily|weekly|monthly|"
        r"per (?:day|week|hour|month|review|task|click|like|video)|a (?:day|week))|"
        r"withdraw (?:daily|anytime|instantly)|no investment|zero investment|"
        r"product reviewer|guaranteed (?:returns?|profit)|"
        r"double your money|investment (?:plan|scheme)|"
        r"trading (?:group|platform|tips)|crypto|\d{2,4}% returns?|no risk|"
        r"no experience|like (?:and|&) share|youtube videos)\b",
    ),
    _rule(
        "delivery_scam",
        "Fake delivery problem",
        "'Your parcel is stuck, pay a fee' is a very common phishing lure.",
        20,
        r"\b(?:parcel|package|courier|delivery|shipment|consignment)\b"
        r"(?:\W+\w+){0,12}?\W+(?:held|stuck|pending|failed|undelivered|"
        r"could not be delivered|customs|returned|re-?schedule|re-?delivery|"
        r"unable to deliver|missed)\b",
    ),
    _rule(
        "contact_push",
        "Pushes you to chat or call off-platform",
        "Scammers move you to WhatsApp, Telegram or a phone call where "
        "they are harder to trace.",
        10,
        r"\b(?:whatsapp|telegram|dm)\b(?:\W+\w+){0,4}\W+(?:us|me|now|on|group|channel|number)\b"
        r"|\b(?:call|dial|contact)\b(?:\W+\w+){0,5}?\W+(?:\+?91[\s-]?)?\d[\dxX\s-]{8,}[\dxX]"
        r"|\bt\.me/|\bwa\.me/",
    ),
    _rule(
        "new_number_ploy",
        "'New number / in trouble' story",
        "Fake messages from 'family' with a new number or an emergency are used "
        "to get money quickly.",
        15,
        r"\b(?:new number|changed my number|lost my phone|phone (?:is )?(?:broken|"
        r"lost|damaged|not working)|my phone (?:broke|got stolen)|"
        r"(?:i )?broke my phone|(?:friend|brother|cousin)'?s (?:phone|number)|"
        r"i'?m in trouble|"
        r"i am in trouble|in an emergency)\b",
    ),
    _rule(
        "impersonation",
        "Claims to be a bank, company or authority",
        "Scammers pretend to be banks, couriers, telecom or government bodies.",
        10,
        r"\b(?:sbi|hdfc|icici|axis bank|kotak|pnb|bank of baroda|paytm|phonepe|"
        r"gpay|google pay|amazon|flipkart|netflix|jio|airtel|income tax|rbi|trai|"
        r"customs|fedex|dhl|dtdc|india post|police|cbi|cyber cell|customer care|"
        r"support team|irctc|lic|epfo|pm kisan|narcotics|court)\b",
    ),
    _rule(
        "generic_greeting",
        "Generic greeting",
        "Real providers usually address you by name, not 'Dear customer'.",
        5,
        r"\bdear (?:customer|user|sir|madam|sir/madam|valued|account holder|"
        r"winner|beneficiary|client|member|student)\b",
    ),
)


def _snippet(s: str) -> str:
    s = " ".join(s.split())
    return s if len(s) <= 60 else s[:57] + "..."


def _regex_flag(rule: _Rule, text: str, masked: str) -> Flag | None:
    haystack = masked if rule.mask_negation else text
    matches = list(rule.pattern.finditer(haystack))
    if not matches:
        return None
    return Flag(
        rule.id,
        rule.title,
        rule.explanation,
        rule.weight,
        tuple(dict.fromkeys(_snippet(text[m.start() : m.end()]) for m in matches))[
            :_MAX_EVIDENCE
        ],
        tuple((m.start(), m.end()) for m in matches),
        critical=rule.critical,
    )


def _style_flag(text: str) -> Flag | None:
    letters = [c for c in text if c.isalpha()]
    shouting = (
        len(letters) >= 20 and sum(c.isupper() for c in letters) / len(letters) > 0.6
    )
    if shouting or text.count("!") >= 3:
        return Flag(
            "shouting",
            "Shouting / excessive punctuation",
            "ALL CAPS and lots of exclamation marks are used to create excitement or panic.",
            5,
            (),
            (),
        )
    return None


# --------------------------------------------------------------------------- #
# Public API
# --------------------------------------------------------------------------- #


def analyze_rules(text: str) -> RuleResult:
    """Run every rule on the text and return the total score and the flags."""
    text = text[:MAX_TEXT_LEN]
    masked = _NEGATED_RE.sub(lambda m: " " * len(m.group(0)), text)

    flags: list[Flag] = []
    for rule in RULES:
        flag = _regex_flag(rule, text, masked)
        if flag:
            flags.append(flag)
    flags.extend(_url_flags(text))
    style = _style_flag(text)
    if style:
        flags.append(style)

    flags.sort(key=lambda f: f.weight, reverse=True)
    return RuleResult(score=min(100, sum(f.weight for f in flags)), flags=tuple(flags))
