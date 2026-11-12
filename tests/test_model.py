import joblib

from src import model
from src.model import normalize_text


def test_normalize_text_hides_volatile_details():
    out = normalize_text("Pay Rs 500 at http://evil.xyz/x call 9876543210 or 12345")
    assert "evil" not in out
    assert "500" not in out
    for token in ("currtoken", "urltoken", "phonenum", "shortcode"):
        assert token in out


def test_official_and_fake_links_get_different_tokens():
    assert "officialurl" in normalize_text("see amazon.in/orders")
    assert "urltoken" in normalize_text("see amazon-refund.top")


def test_broken_or_missing_model_file_is_rebuilt_automatically(tmp_path, monkeypatch):
    """Simulates running on a new laptop where the saved model is unusable."""
    fake_model = tmp_path / "models" / "hoax_model.joblib"
    fake_model.parent.mkdir()
    fake_model.write_bytes(b"this is not a real model")
    monkeypatch.setattr(model, "MODEL_PATH", fake_model)
    monkeypatch.setattr(model, "METRICS_PATH", fake_model.parent / "metrics.json")
    model.load_model.cache_clear()
    try:
        model.load_model()  # corrupt file -> retrain
        assert 0.0 <= model.predict_scam_probability("hello friend") <= 1.0
        joblib.load(fake_model)  # the file on disk is now a real, loadable model
        assert (fake_model.parent / "metrics.json").exists()
    finally:
        model.load_model.cache_clear()  # don't leak the temporary model
