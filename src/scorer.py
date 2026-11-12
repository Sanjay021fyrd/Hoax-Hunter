"""Combine the rule engine and the ML model into one verdict."""

from __future__ import annotations

import json
import logging
from dataclasses import dataclass
from functools import lru_cache

from src.model import METRICS_PATH, load_model, predict_scam_probability
from src.rules import MAX_TEXT_LEN, URL_RE, Flag, analyze_rules

log = logging.getLogger(__name__)

SAFE = "Safe"
SUSPICIOUS = "Suspicious"
SCAM = "Likely Scam"
# Not a rating: the message is mostly in a script the tool cannot read (e.g.
# Devanagari). Saying "Safe" there would be false reassurance.
UNSURE = "Can't judge"

UNREADABLE_SHARE = 0.4  # this share of non-Latin letters -> text is "unreadable"
_MIN_LETTERS = 5

ML_WEIGHT = 0.6
RULE_WEIGHT = 0.4
SUSPICIOUS_FROM = 35  # score >= this  -> Suspicious
SCAM_FROM = 65  # score >= this  -> Likely Scam
STRONG_RULE = 75  # rules alone this high -> at least 85% of that as the score
STRONG_ML = 92  # model alone this sure (%) -> at least 80% of that as the score

ADVICE = {
    SCAM: (
        "Do NOT click any link, call any number, or reply.",
        "Never share your OTP, PIN, CVV or passwords. Real banks never ask for them.",
        "Block the sender and delete the message.",
        "Report it: call 1930 (National Cyber Crime Helpline) or visit "
        "cybercrime.gov.in. You can also report via Chakshu on sancharsaathi.gov.in.",
        "If you already paid or shared details, call 1930 immediately and inform your bank.",
    ),
    SUSPICIOUS: (
        "Don't click the link or call numbers given in the message.",
        "Check by opening the official app or typing the company's website yourself.",
        "Call the number printed on your card or the official site to confirm.",
        "When in doubt, ask a family member or report it at cybercrime.gov.in.",
    ),
    SAFE: (
        "No major scam signs found, but no tool is perfect.",
        "Still never share your OTP, PIN or passwords with anyone.",
    ),
    UNSURE: (
        "Hoax Hunter cannot read this script yet, so it has no opinion on the wording.",
        "Do not click links, call numbers or share OTP, PIN or passwords because of this message.",
        "Ask someone you trust who reads this language, or confirm with the sender "
        "through the official app or website.",
        "If it looks like fraud, report it at cybercrime.gov.in or call 1930.",
    ),
}


@dataclass(frozen=True)
class Analysis:
    text: str  # the cleaned text that was analysed (spans refer to this)
    score: int  # 0-100 overall risk
    verdict: str  # Safe / Suspicious / Likely Scam / Can't judge
    rule_score: int  # 0-100
    ml_probability: float | None  # None: model missing, or text not readable
    flags: tuple[Flag, ...]
    advice: tuple[str, ...]
    unreadable: bool = False  # mostly non-Latin script (the model never saw any)


@lru_cache(maxsize=1)
def model_available() -> bool:
    """True if the ML model can be used (it is trained on the fly if needed)."""
    try:
        load_model()
        return True
    except Exception:
        log.warning("ML model unavailable, using rules only.", exc_info=True)
        return False


def load_metrics() -> dict | None:
    try:
        return json.loads(METRICS_PATH.read_text())
    except (OSError, ValueError):
        return None


def combine(
    ml_probability: float | None, rule_score: int, critical: bool = False
) -> int:
    """Blend the two signals into a single 0-100 risk score.

    - Normal case: 60% ML probability + 40% rule score.
    - A very strong rule score or a very confident model is not diluted by the
      other (weaker) signal.
    - A critical flag (e.g. "share your OTP") always means Likely Scam.
    """
    if ml_probability is None:  # rules-only fallback
        score = float(rule_score)
    else:
        ml = ml_probability * 100
        score = ML_WEIGHT * ml + RULE_WEIGHT * rule_score
        if ml >= STRONG_ML:
            score = max(score, ml * 0.8)
    if rule_score >= STRONG_RULE:
        score = max(score, rule_score * 0.85)
    if critical:
        score = max(score, SCAM_FROM)
    return round(min(100, score))


def is_unreadable(text: str) -> bool:
    """True when most letters are outside the Latin alphabets (e.g. Devanagari).

    Hoax Hunter's wording rules and model only know English. Links, phone
    numbers and amounts are still checked for any text.
    """
    # links are not prose: "sbi-kyc-update.xyz" must not make Hindi text look Latin
    letters = [c for c in URL_RE.sub(" ", text) if c.isalpha()]
    if len(letters) < _MIN_LETTERS:
        return False
    non_latin = sum(ord(c) > 0x24F for c in letters)  # beyond Latin Extended-B
    return non_latin / len(letters) >= UNREADABLE_SHARE


def verdict_for(score: int) -> str:
    if score >= SCAM_FROM:
        return SCAM
    if score >= SUSPICIOUS_FROM:
        return SUSPICIOUS
    return SAFE


def analyze(text: str) -> Analysis:
    """Analyse one message. Raises ValueError if the message is empty."""
    text = (text or "").strip()[:MAX_TEXT_LEN]
    if not text:
        raise ValueError("Message is empty.")

    rules = analyze_rules(text)
    unreadable = is_unreadable(text)
    use_model = model_available() and not unreadable
    ml_probability = predict_scam_probability(text) if use_model else None
    score = combine(ml_probability, rules.score, rules.critical)
    verdict = verdict_for(score)
    if unreadable and verdict == SAFE:
        verdict = UNSURE  # never reassure about text we cannot read
    return Analysis(
        text=text,
        score=score,
        verdict=verdict,
        rule_score=rules.score,
        ml_probability=ml_probability,
        flags=rules.flags,
        advice=ADVICE[verdict],
        unreadable=unreadable,
    )
