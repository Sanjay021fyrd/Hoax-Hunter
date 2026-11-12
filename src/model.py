"""Machine-learning layer: TF-IDF + Logistic Regression scam classifier.

Train:   python -m src.model
Predict: predict_scam_probability("some message")  -> float in [0, 1]
"""

from __future__ import annotations

import json
import logging
import re
import warnings
from functools import lru_cache
from pathlib import Path

import joblib
from sklearn.feature_extraction.text import TfidfVectorizer
from sklearn.linear_model import LogisticRegression
from sklearn.metrics import (
    accuracy_score,
    classification_report,
    confusion_matrix,
    precision_recall_fscore_support,
)
from sklearn.model_selection import train_test_split
from sklearn.pipeline import FeatureUnion, Pipeline

from sklearn.exceptions import InconsistentVersionWarning

from src.data import SMS_CSV, download_sms_dataset, load_training_data
from src.rules import URL_RE, is_official_url

log = logging.getLogger(__name__)

ROOT = Path(__file__).resolve().parent.parent
MODEL_PATH = ROOT / "models" / "hoax_model.joblib"
METRICS_PATH = ROOT / "models" / "metrics.json"
RANDOM_STATE = 42


def normalize_text(text: str) -> str:
    """Lower-case and replace volatile details (links, numbers) with tokens.

    The model should learn "message contains a link / a phone number" rather
    than memorise specific URLs or digits.
    """
    t = URL_RE.sub(
        lambda m: " officialurl " if is_official_url(m.group(0)) else " urltoken ",
        text.lower(),
    )
    t = re.sub(r"[₹$£€]|\brs\.?(?=\s*\d)|\binr\b", " currtoken ", t)
    t = re.sub(r"\d{10,}", " phonenum ", t)
    t = re.sub(r"\d{5,9}", " shortcode ", t)
    t = re.sub(r"\d+", " num ", t)
    return re.sub(r"\s+", " ", t).strip()


def build_pipeline() -> Pipeline:
    features = FeatureUnion(
        [
            ("word", TfidfVectorizer(ngram_range=(1, 2), min_df=2, sublinear_tf=True)),
            (
                "char",
                TfidfVectorizer(
                    analyzer="char_wb", ngram_range=(3, 5), min_df=3, sublinear_tf=True
                ),
            ),
        ]
    )
    clf = LogisticRegression(C=10, class_weight="balanced", max_iter=2000)
    return Pipeline([("tfidf", features), ("clf", clf)])


def train(save: bool = True, verbose: bool = True) -> dict:
    """Train on the combined dataset, report held-out metrics, save the model."""
    df = load_training_data()
    X = df["text"].map(normalize_text)
    y = df["is_scam"]

    X_train, X_test, y_train, y_test = train_test_split(
        X, y, test_size=0.2, stratify=y, random_state=RANDOM_STATE
    )
    pipe = build_pipeline().fit(X_train, y_train)
    pred = pipe.predict(X_test)

    precision, recall, f1, _ = precision_recall_fscore_support(
        y_test, pred, average="binary", zero_division=0
    )
    tn, fp, fn, tp = confusion_matrix(y_test, pred).ravel()
    metrics = {
        "accuracy": round(float(accuracy_score(y_test, pred)), 4),
        "scam_precision": round(float(precision), 4),
        "scam_recall": round(float(recall), 4),
        "scam_f1": round(float(f1), 4),
        "confusion": {"tn": int(tn), "fp": int(fp), "fn": int(fn), "tp": int(tp)},
        "train_size": int(len(X_train)),
        "test_size": int(len(X_test)),
    }

    if verbose:
        print(
            classification_report(
                y_test, pred, target_names=["genuine", "scam"], digits=3
            )
        )
        print("Confusion matrix:", metrics["confusion"])

    if save:
        # Final model uses all the data once the held-out numbers are known.
        final = build_pipeline().fit(X, y)
        MODEL_PATH.parent.mkdir(parents=True, exist_ok=True)
        joblib.dump(final, MODEL_PATH)
        METRICS_PATH.write_text(json.dumps(metrics, indent=2))
        if verbose:
            print(f"Saved model to {MODEL_PATH}")
    return metrics


@lru_cache(maxsize=1)
def load_model() -> Pipeline:
    """Load the saved model, or train a fresh one if that is not possible.

    A saved model file only works with the scikit-learn version that made it.
    On another laptop (different Python / library versions) the file may be
    missing or incompatible, so we simply retrain from the bundled data.
    """
    if MODEL_PATH.exists():
        try:
            with warnings.catch_warnings():
                warnings.simplefilter("error", InconsistentVersionWarning)
                return joblib.load(MODEL_PATH)
        except Exception:
            log.warning("Saved model unusable here, retraining.", exc_info=True)

    if not SMS_CSV.exists():
        download_sms_dataset()
    train(save=True, verbose=False)
    return joblib.load(MODEL_PATH)


def predict_scam_probability(text: str) -> float:
    return float(load_model().predict_proba([normalize_text(text)])[0, 1])


if __name__ == "__main__":
    train()
