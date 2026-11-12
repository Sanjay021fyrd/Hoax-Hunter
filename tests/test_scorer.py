import pytest
from holdout_messages import GENUINE, SCAMS

from src import scorer
from src.scorer import SAFE, SCAM, SUSPICIOUS, analyze, combine, verdict_for

needs_model = pytest.mark.skipif(
    not scorer.model_available(), reason="model not trained: run python -m src.model"
)


def test_empty_message_is_rejected():
    for text in ("", "   \n  ", None):
        with pytest.raises(ValueError):
            analyze(text)


def test_verdict_thresholds():
    assert verdict_for(0) == SAFE
    assert verdict_for(scorer.SUSPICIOUS_FROM - 1) == SAFE
    assert verdict_for(scorer.SUSPICIOUS_FROM) == SUSPICIOUS
    assert verdict_for(scorer.SCAM_FROM - 1) == SUSPICIOUS
    assert verdict_for(scorer.SCAM_FROM) == SCAM
    assert verdict_for(100) == SCAM


def test_combine_blends_both_signals():
    assert combine(0.0, 0) == 0
    assert combine(1.0, 100) == 100
    assert combine(0.5, 50) == 50


def test_combine_critical_flag_forces_scam_even_if_model_is_unsure():
    assert combine(0.1, 30, critical=False) < scorer.SCAM_FROM
    assert combine(0.1, 30, critical=True) >= scorer.SCAM_FROM


def test_combine_without_model_uses_rules_only():
    assert combine(None, 42) == 42


def test_combine_a_lone_confident_model_is_not_diluted_but_a_weak_one_is():
    assert combine(0.97, 0) >= scorer.SCAM_FROM
    assert combine(0.78, 10) < scorer.SCAM_FROM


def test_rules_only_fallback_when_model_missing(monkeypatch):
    monkeypatch.setattr(scorer, "model_available", lambda: False)
    result = analyze("Share your OTP and PIN now to avoid account block")
    assert result.ml_probability is None
    assert result.verdict == SCAM  # critical rule still catches it


def test_result_text_is_cleaned_and_advice_matches_verdict():
    result = analyze("   Hello there   ")
    assert result.text == "Hello there"
    assert result.advice == scorer.ADVICE[result.verdict]


@needs_model
@pytest.mark.parametrize("message", SCAMS)
def test_unseen_scams_are_never_marked_safe(message):
    assert analyze(message).verdict != SAFE


@needs_model
@pytest.mark.parametrize("message", GENUINE)
def test_unseen_genuine_messages_are_marked_safe(message):
    assert analyze(message).verdict == SAFE


@needs_model
def test_most_unseen_scams_are_likely_scam():
    verdicts = [analyze(m).verdict for m in SCAMS]
    assert verdicts.count(SCAM) / len(verdicts) >= 0.75


# ---------- text the tool cannot read ----------

HINDI_SCRIPT_SCAMS = [
    "आपका खाता बंद हो जाएगा। अभी KYC अपडेट करें",
    "बधाई हो! आपने 25 लाख की लॉटरी जीती है। अपना OTP बताएं।",
]


@pytest.mark.parametrize("message", HINDI_SCRIPT_SCAMS)
def test_hindi_script_is_never_called_safe(message):
    result = analyze(message)
    assert result.unreadable
    assert result.verdict == scorer.UNSURE
    assert result.ml_probability is None  # the model has never seen this script


def test_hindi_script_with_a_fake_link_is_still_caught():
    result = analyze("आपका खाता बंद हो जाएगा। http://sbi-kyc-update.xyz")
    assert result.unreadable
    assert result.verdict == SCAM  # the link rules work in any language


def test_is_unreadable_thresholds():
    assert not scorer.is_unreadable("Hello, this is plain English.")
    assert not scorer.is_unreadable("URGENT: verify your account now")
    assert not scorer.is_unreadable("12345 !!! ...")  # no letters at all
    assert not scorer.is_unreadable("हाँ")  # too short to judge
    assert scorer.is_unreadable("आपका खाता बंद हो जाएगा")
    assert not scorer.is_unreadable(
        "Call me कल at 5 pm tomorrow, thanks a lot"
    )  # mostly Latin
