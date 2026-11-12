import html
from pathlib import Path

from src import ui
from src.rules import Flag, analyze_rules
from src import scorer
from src.scorer import SAFE, SCAM, SUSPICIOUS, Analysis, analyze

CSS = Path(__file__).resolve().parent.parent / "assets" / "style.css"


def make_analysis(**overrides) -> Analysis:
    base = dict(
        text="hello",
        score=50,
        verdict=SUSPICIOUS,
        rule_score=40,
        ml_probability=0.5,
        flags=(),
        advice=("Be careful.",),
    )
    base.update(overrides)
    return Analysis(**base)


def test_stylesheet_has_no_angle_brackets():
    """Streamlit's HTML sanitiser drops a whole <style> block if it contains '<'."""
    assert "<" not in CSS.read_text(encoding="utf-8")


def test_all_verdicts_have_a_look():
    for verdict in (SAFE, SUSPICIOUS, SCAM):
        tone, headline, summary = ui.TONES[verdict]
        assert tone and headline and summary


def test_verdict_card_shows_score_and_tone():
    card = ui.verdict_card(make_analysis(score=87, verdict=SCAM))
    assert "verdict--danger" in card
    assert "Likely a scam" in card
    assert 'style="--p:87"' in card


def test_meter_score_is_clamped():
    assert "--p:100" in ui.meter(250)
    assert "--p:0" in ui.meter(-5)


def test_verdict_card_without_model_says_n_a():
    assert "n/a" in ui.verdict_card(make_analysis(ml_probability=None))


def test_html_builders_are_single_lines():
    """A blank line would end the HTML block, so builders must never emit newlines."""
    a = analyze("URGENT\n\nShare your OTP at http://sbi-kyc.xyz\r\n\r\nnow")
    for html_text in (
        ui.hero(),
        ui.verdict_card(a),
        ui.evidence(a.flags),
        ui.annotated_message(a),
        ui.advice(a),
        ui.sidebar(None),
        ui.footnote(),
    ):
        assert "\n" not in html_text
        assert "\r" not in html_text


def test_text_from_the_message_is_escaped_everywhere():
    nasty = '<img src=x onerror=alert(1)> "quoted" & <script>boom()</script>'
    flag = Flag("x", nasty, nasty, 10, (nasty,), ())
    out = ui.evidence((flag,))
    assert "<img" not in out
    assert "<script>" not in out
    assert "&lt;script&gt;" in out

    msg = ui.annotated_message(make_analysis(text=nasty))
    assert "<img" not in msg
    assert "<script>" not in msg


def test_evidence_lists_critical_flags_and_empty_state():
    result = analyze_rules("Share the OTP right now")
    html_text = ui.evidence(result.flags)
    assert "flag--critical" in html_text
    assert "Critical" in html_text
    assert "No known scam signals" in ui.evidence(())


def test_sidebar_shows_metrics_only_when_available():
    metrics = {
        "accuracy": 0.99,
        "scam_recall": 0.97,
        "scam_precision": 0.95,
        "test_size": 1000,
    }
    assert "How accurate is it?" in ui.sidebar(metrics)
    assert "How accurate is it?" not in ui.sidebar(None)


def test_cant_judge_card_has_no_score_and_says_not_rated():
    card = ui.verdict_card(
        make_analysis(verdict=scorer.UNSURE, score=4, unreadable=True)
    )
    assert "verdict--neutral" in card
    assert "Can't judge" in html.unescape(card)  # the apostrophe is HTML-escaped
    assert "Not rated" in card
    assert "Risk score" not in card  # we must not show a fake score
    assert "--p:" not in card  # and no bar


def test_cant_judge_advice_and_tone_exist():
    assert scorer.UNSURE in ui.TONES
    assert scorer.ADVICE[scorer.UNSURE]


def test_evidence_does_not_reassure_when_text_was_unreadable():
    text = ui.evidence((), unreadable=True)
    assert "could not be checked" in text
    assert "No known scam signals" not in text
