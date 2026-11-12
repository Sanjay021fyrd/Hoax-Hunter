"""Hoax Hunter - paste a suspicious message and find out if it is a scam.

Run:  python run.py     (or: streamlit run app.py)
"""

from pathlib import Path

import streamlit as st

from src import ui
from src.scorer import analyze, load_metrics, model_available

CSS_PATH = Path(__file__).resolve().parent / "assets" / "style.css"

SCAM_SAMPLES = {
    "Fake KYC alert": (
        "Dear customer your Kotak account will be blocked today. "
        "Complete KYC at http://kotak-kyc-now.xyz or call 9876543210"
    ),
    "Lottery prize": (
        "Congratulations!! You won a brand new car in Big Bazaar lucky draw. "
        "Send Rs 3000 as registration fee to claim."
    ),
    "Parcel fee": "Your Amazon parcel is stuck at customs. Pay Rs 99 fee: http://amzn-delivery-fee.top",
    "OTP request": (
        "URGENT: Your bank account is compromised. "
        "Share the OTP sent to you right now to secure your funds."
    ),
}
REAL_SAMPLES = {
    "Login OTP": "Your OTP for Flipkart login is 902134. Do not share this code with anyone.",
    "Bank alert": "Rs 540 debited from A/c XX1122 at BIGBAZAAR on 11-Nov. Avl Bal Rs 8,100. -HDFC Bank",
}

st.set_page_config(
    page_title="Hoax Hunter",
    page_icon="🕵️",
    layout="wide",
    initial_sidebar_state="auto",  # open on desktop, collapsed on phones
)
st.html(f"<style>{CSS_PATH.read_text(encoding='utf-8')}</style>")


# ---------- actions (run before the page redraws) ----------
# Only plain text is kept in session_state, never an Analysis object: the result
# is recomputed on every redraw (milliseconds). Otherwise a result remembered by an
# older version of the code could crash the page after the code is updated.
def run_analysis() -> None:
    text = st.session_state.get("message", "").strip()
    if text:
        st.session_state["analyzed_text"] = text
        st.session_state["notice"] = None
    else:
        st.session_state["analyzed_text"] = None
        st.session_state["notice"] = "Paste a message first, then press Analyze."


def use_sample(text: str) -> None:
    st.session_state["message"] = text
    run_analysis()


def clear_all() -> None:
    st.session_state["message"] = ""
    st.session_state["analyzed_text"] = None
    st.session_state["notice"] = None


# ---------- page ----------
st.html(ui.hero())


def sample_row(label: str, samples: dict[str, str]) -> None:
    cols = st.columns([1.15, 1, 1, 1, 1])
    cols[0].html(ui.micro_label(label))
    for col, (name, text) in zip(cols[1:], samples.items()):
        col.button(name, key=f"sample-{name}", on_click=use_sample, args=(text,))


sample_row("Try a scam:", SCAM_SAMPLES)
sample_row("Try a real one:", REAL_SAMPLES)

st.text_area(
    "Message to check",
    key="message",
    height=170,
    max_chars=5000,
    placeholder="Paste the suspicious SMS, WhatsApp message or email here…",
)

analyze_col, clear_col, _ = st.columns([1.5, 0.8, 3])
analyze_col.button("Analyze message", type="primary", on_click=run_analysis)
clear_col.button("Clear", on_click=clear_all)

if st.session_state.get("notice"):
    st.warning(st.session_state["notice"])

analyzed_text = st.session_state.get("analyzed_text")
result = analyze(analyzed_text) if analyzed_text else None
if result:
    st.html(ui.section("What I found"))
    st.html(ui.verdict_card(result))
    if result.ml_probability is None and not result.unreadable:
        st.caption(
            "The learning model is unavailable, so only the rule engine was used."
        )

    st.html(ui.section("Why"))
    st.html(ui.evidence(result.flags, unreadable=result.unreadable))

    st.html(ui.section("Your message, marked up"))
    st.html(ui.annotated_message(result))

    st.html(ui.section("What to do now"))
    st.html(ui.advice(result))

st.html(ui.footnote())

with st.sidebar:
    st.html(ui.sidebar(load_metrics() if model_available() else None))
