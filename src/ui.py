"""HTML building blocks for the Hoax Hunter interface.

Every piece of text that can come from the analysed message is HTML-escaped
here, and the result is rendered with `st.html` (which does no Markdown
processing and sanitises the HTML), so a malicious message cannot inject
links, scripts or styling into the page.
"""

from __future__ import annotations

import html

from src.highlight import highlight_html
from src.rules import Flag
from src.scorer import SAFE, SCAM, SUSPICIOUS, UNSURE, Analysis

# verdict -> (css tone, headline, one-line summary)
TONES = {
    SAFE: (
        "safe",
        "Looks safe",
        "No significant scam signals were found in this message.",
    ),
    SUSPICIOUS: (
        "warn",
        "Be careful",
        "This message shows several warning signs. Verify it before you act.",
    ),
    SCAM: (
        "danger",
        "Likely a scam",
        "This matches how scammers typically operate. Do not respond or click.",
    ),
    UNSURE: (
        "neutral",
        "Can't judge this one",
        "Most of this message is in a script Hoax Hunter can't read yet. "
        "Links and numbers were still checked. Treat it with care.",
    ),
}


def esc(value: object) -> str:
    return html.escape(str(value), quote=True)


def hero() -> str:
    return (
        '<div class="hero">'
        '<div class="eyebrow">Scam intelligence</div>'
        '<div class="hero__title">Hoax Hunter</div>'
        '<div class="hero__rule"></div>'
        '<div class="hero__tag">Paste any suspicious message. '
        "Know in seconds whether to trust it, and exactly why.</div>"
        "</div>"
    )


def section(title: str) -> str:
    return f'<div class="section"><span>{esc(title)}</span></div>'


def micro_label(text: str) -> str:
    return f'<div class="micro">{esc(text)}</div>'


def gauge(score: int, rated: bool = True) -> str:
    """Circular risk meter drawn with CSS only (st.html strips <svg>)."""
    score = max(0, min(100, int(score)))
    if not rated:  # no opinion: empty ring and a question mark
        return (
            '<div class="gauge" role="img" aria-label="Not rated" style="--p:0">'
            '<div class="gauge__ring"></div>'
            '<div class="gauge__label"><div class="gauge__num">?</div>'
            '<div class="gauge__sub">Not rated</div></div>'
            "</div>"
        )
    return (
        f'<div class="gauge" role="img" aria-label="Risk score {score} out of 100" '
        f'style="--p:{score}">'
        '<div class="gauge__ring"></div>'
        f'<div class="gauge__label"><div class="gauge__num">{score}</div>'
        '<div class="gauge__sub">Risk / 100</div></div>'
        "</div>"
    )


def _stat(label: str, value: str, unit: str = "") -> str:
    small = f"<small>{esc(unit)}</small>" if unit else ""
    return (
        f'<div class="stat"><div class="stat__label">{esc(label)}</div>'
        f'<div class="stat__value">{esc(value)}{small}</div></div>'
    )


def verdict_card(a: Analysis) -> str:
    tone, headline, summary = TONES[a.verdict]
    ml = "n/a" if a.ml_probability is None else f"{a.ml_probability:.0%}"
    stats = (
        _stat("AI model", ml)
        + _stat("Rule engine", str(a.rule_score), "/ 100")
        + _stat("Red flags", str(len(a.flags)))
    )
    return (
        f'<div class="verdict verdict--{tone}">'
        f"<div>{gauge(a.score, rated=a.verdict != UNSURE)}</div>"
        "<div>"
        '<div class="eyebrow" style="color:var(--tone)">Verdict</div>'
        f'<div class="verdict__title">{esc(headline)}</div>'
        f'<div class="verdict__text">{esc(summary)}</div>'
        f'<div class="stats">{stats}</div>'
        "</div></div>"
    )


def _flag_card(flag: Flag) -> str:
    critical = " flag--critical" if flag.critical else ""
    badge = '<span class="badge">Critical</span>' if flag.critical else ""
    unique = {e.casefold(): e for e in reversed(flag.evidence)}  # "Kotak" == "kotak"
    chips = "".join(
        f'<code class="chip">{esc(e)}</code>' for e in reversed(list(unique.values()))
    )
    chips = f'<div class="chips">{chips}</div>' if chips else ""
    return (
        f'<div class="flag{critical}">'
        '<div class="flag__head">'
        f'<span class="flag__title">{esc(flag.title)}</span>'
        f'<span class="flag__meta">{badge}<span class="pill">+{flag.weight}</span></span>'
        "</div>"
        f'<p class="flag__text">{esc(flag.explanation)}</p>'
        f"{chips}</div>"
    )


def evidence(flags: tuple[Flag, ...], unreadable: bool = False) -> str:
    if not flags and unreadable:
        return (
            '<div class="empty">No links, numbers or other checkable signals were '
            "flagged. The wording itself could not be checked.</div>"
        )
    if not flags:
        return (
            '<div class="empty">No known scam signals were found in this message.</div>'
        )
    return "".join(_flag_card(f) for f in flags)


def annotated_message(a: Analysis) -> str:
    spans = [span for flag in a.flags for span in flag.spans]
    tone = TONES[a.verdict][0]
    return f'<div class="message message--{tone}">{highlight_html(a.text, spans)}</div>'


def advice(a: Analysis) -> str:
    items = "".join(f"<li><span>{esc(tip)}</span></li>" for tip in a.advice)
    return f'<ol class="advice">{items}</ol>'


def sidebar(metrics: dict | None) -> str:
    steps = (
        (
            "Red-flag rules",
            "Spot pressure tactics, fake links, and requests for your OTP or PIN.",
        ),
        (
            "Learning model",
            "Compares the text with thousands of known scam and genuine messages.",
        ),
        (
            "One clear score",
            "Both signals are blended into a single 0 to 100 risk score.",
        ),
    )
    numerals = ("I", "II", "III")
    steps_html = "".join(
        f'<li data-n="{numerals[i]}"><div><b>{esc(t)}</b>{esc(d)}</div></li>'
        for i, (t, d) in enumerate(steps)
    )
    out = (
        '<div class="side__title">How it works</div>'
        f'<ol class="steps">{steps_html}</ol>'
    )
    if metrics:
        out += (
            '<div class="side__title">Model quality</div>'
            f'<div class="qrow">Accuracy<b>{metrics["accuracy"]:.1%}</b></div>'
            f'<div class="qrow">Scams caught<b>{metrics["scam_recall"]:.1%}</b></div>'
            f'<div class="qrow">Precision<b>{metrics["scam_precision"]:.1%}</b></div>'
            f'<div class="side__note">Measured on {metrics["test_size"]} messages '
            "held back for testing.</div>"
        )
    out += (
        '<div class="side__title">Good to know</div>'
        '<ul class="limits">'
        "<li>Made for English messages.</li>"
        "<li>Text in other scripts (Hindi, Tamil, ...) is not rated.</li>"
        "<li>New scam styles can slip through.</li>"
        "<li>Links are analysed, never opened.</li>"
        "</ul>"
    )
    return out


def footnote() -> str:
    return (
        '<div class="footnote">Hoax Hunter is a screening aid, not a guarantee. '
        "If you have lost money, call <b>1930</b> (National Cyber Crime Helpline) "
        "straight away.</div>"
    )
