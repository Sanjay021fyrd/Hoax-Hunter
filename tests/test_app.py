"""Headless smoke tests of the Streamlit UI (no browser needed)."""

from pathlib import Path

import pytest
from streamlit.testing.v1 import AppTest

from src import scorer

APP_PATH = str(Path(__file__).resolve().parent.parent / "app.py")

needs_model = pytest.mark.skipif(
    not scorer.model_available(), reason="model not trained: run python -m src.model"
)


def new_app() -> AppTest:
    return AppTest.from_file(APP_PATH, default_timeout=30).run()


def click(at: AppTest, label: str) -> AppTest:
    [button] = [b for b in at.button if b.label == label]
    return button.click().run()


def page_html(at: AppTest) -> str:
    """All the HTML the app rendered with st.html, as one string."""
    return "".join(e.proto.body for e in at.get("html"))


def analyze_text(at: AppTest, text: str) -> AppTest:
    at.text_area(key="message").set_value(text).run()
    return click(at, "Analyze message")


def test_app_starts_without_errors():
    at = new_app()
    assert not at.exception
    html = page_html(at)
    assert "Hoax Hunter" in html
    assert '<div class="verdict ' not in html  # no result before the first analysis


def test_empty_message_shows_a_notice_not_a_crash():
    at = click(new_app(), "Analyze message")
    assert not at.exception
    assert any("Paste a message" in w.value for w in at.warning)


@needs_model
def test_scam_message_shows_scam_verdict_and_critical_evidence():
    at = analyze_text(
        new_app(),
        "URGENT: Share the OTP sent to you right now. Update KYC: http://sbi-kyc-update.xyz",
    )
    assert not at.exception
    html = page_html(at)
    assert "Likely a scam" in html
    assert '<div class="verdict verdict--danger">' in html
    assert '<div class="flag flag--critical">' in html


@needs_model
def test_genuine_message_shows_safe_verdict():
    at = analyze_text(
        new_app(),
        "Your OTP for Flipkart login is 902134. Do not share this code with anyone.",
    )
    assert not at.exception
    html = page_html(at)
    assert "Looks safe" in html
    assert '<div class="verdict verdict--safe">' in html


@needs_model
def test_sample_button_fills_the_box_and_analyzes_in_one_click():
    at = click(new_app(), "Parcel fee")
    assert not at.exception
    assert "customs" in at.text_area(key="message").value
    assert '<div class="verdict verdict--' in page_html(at)


@needs_model
def test_clear_button_resets_everything():
    at = click(new_app(), "Parcel fee")
    at = click(at, "Clear")
    assert at.text_area(key="message").value == ""
    assert '<div class="verdict ' not in page_html(at)


@needs_model
def test_message_with_markup_cannot_inject_html():
    at = analyze_text(
        new_app(), "<img src=x onerror=alert(1)> win a prize [click](http://evil.xyz)"
    )
    assert not at.exception
    html = page_html(at)
    assert "<img" not in html
    assert "&lt;img" in html


@needs_model
def test_a_stale_result_left_by_older_code_cannot_crash_the_page():
    """Regression: an old Analysis object in session_state once crashed the app
    ("'Analysis' object has no attribute 'unreadable'") after the code was updated."""
    at = analyze_text(new_app(), "URGENT: Share the OTP sent to you right now.")
    assert not at.exception

    class OldAnalysis:  # what an older version of the code would have left behind
        text = "x"
        score = 99
        verdict = "Likely Scam"

    at.session_state["analysis"] = OldAnalysis()  # the key older versions used
    at = at.run()
    assert not at.exception
    assert '<div class="verdict verdict--danger">' in page_html(at)


@needs_model
def test_result_survives_editing_the_text_box_after_analysis():
    at = analyze_text(new_app(), "Your Amazon parcel is stuck at customs. Pay Rs 99 fee.")
    shown = page_html(at)
    at.text_area(key="message").set_value("something else entirely").run()
    assert not at.exception
    assert "customs" in page_html(at)  # still the analysed message, until you press Analyze
    assert shown.count('class="verdict ') == page_html(at).count('class="verdict ')
