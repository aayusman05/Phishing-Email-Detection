import os
import streamlit as st

from agent import analyse_email

# ── Page config ──────────────────────────────────────────────────────────────
st.set_page_config(
    page_title="Phishing Email Detection Agent",
    page_icon="🔍",
    layout="centered",
)

# ── Helpers ───────────────────────────────────────────────────────────────────
SAMPLES_DIR = os.path.join(os.path.dirname(__file__), "samples")


def load_sample(name: str) -> str:
    path = os.path.join(SAMPLES_DIR, f"{name}.txt")
    try:
        with open(path) as f:
            return f.read()
    except FileNotFoundError:
        return f"[Sample file '{name}.txt' not found]"


VERDICT_COLOURS = {
    "Safe": "#28a745",        # green
    "Suspicious": "#fd7e14",  # orange
    "Phishing": "#dc3545",    # red
}

CONFIDENCE_EMOJI = {
    "Low": "🟡",
    "Medium": "🟠",
    "High": "🔴",
}


def verdict_badge(verdict: str) -> str:
    colour = VERDICT_COLOURS.get(verdict, "#6c757d")
    return (
        f'<span style="background-color:{colour};color:white;padding:6px 18px;'
        f'border-radius:20px;font-size:1.2rem;font-weight:bold;">{verdict}</span>'
    )


# ── Session state ─────────────────────────────────────────────────────────────
if "email_text" not in st.session_state:
    st.session_state.email_text = ""

# ── Title ─────────────────────────────────────────────────────────────────────
st.title("🔍 Phishing Email Detection Agent")
st.caption(
    "Paste an email below and click **Analyse** to detect whether it is "
    "Safe, Suspicious, or a Phishing attempt."
)

# ── Try a sample ──────────────────────────────────────────────────────────────
st.subheader("Try a sample")
col1, col2, col3 = st.columns(3)

with col1:
    if st.button("✅ Safe email", use_container_width=True):
        st.session_state.email_text = load_sample("safe")

with col2:
    if st.button("⚠️ Suspicious email", use_container_width=True):
        st.session_state.email_text = load_sample("suspicious")

with col3:
    if st.button("🚨 Phishing email", use_container_width=True):
        st.session_state.email_text = load_sample("phishing")

st.divider()

# ── Input area ────────────────────────────────────────────────────────────────
email_input = st.text_area(
    "Email content",
    value=st.session_state.email_text,
    height=300,
    placeholder="Paste the full email here (including headers like From:, Subject:, etc.) …",
    key="email_textarea",
)

analyse_clicked = st.button("🔎 Analyse", type="primary", use_container_width=True)

# ── Analysis ──────────────────────────────────────────────────────────────────
if analyse_clicked:
    if not email_input.strip():
        st.warning("Please paste an email before clicking Analyse.")
    else:
        with st.spinner("Analysing email …"):
            result = analyse_email(email_input)

        if "error" in result:
            st.error(f"Analysis failed: {result['error']}")
            if "raw" in result:
                with st.expander("Raw model response"):
                    st.code(result["raw"])
        else:
            st.divider()
            st.subheader("Results")

            # Verdict badge
            verdict = result.get("verdict", "Unknown")
            st.markdown(verdict_badge(verdict), unsafe_allow_html=True)
            st.write("")  # spacing

            if result.get("reanalysed"):
                st.info("ℹ️ Low confidence detected — agent performed a second analysis.")

            # Confidence
            confidence = result.get("confidence", "Unknown")
            emoji = CONFIDENCE_EMOJI.get(confidence, "⚪")
            st.markdown(f"**Confidence:** {emoji} {confidence}")

            # Reasoning
            st.markdown("**Reasoning:**")
            st.info(result.get("reasoning", "No reasoning provided."))

            # Key signals
            signals = result.get("key_signals", [])
            if signals:
                st.markdown("**Key signals:**")
                for signal in signals:
                    st.markdown(f"- {signal}")

            # Raw tool output (collapsible)
            tool_outputs = result.get("_tool_outputs", {})
            if tool_outputs:
                with st.expander("🔧 Raw tool output"):
                    url_data = tool_outputs.get("url_analysis", {})
                    sender_data = tool_outputs.get("sender_analysis", {})
                    tone_data = tool_outputs.get("tone_analysis", {})

                    col_a, col_b, col_c = st.columns(3)
                    col_a.metric("URL risk score", f"{url_data.get('risk_score', 0)} / 10")
                    col_b.metric("Sender risk score", f"{sender_data.get('risk_score', 0)} / 10")
                    col_c.metric("Tone risk score", f"{tone_data.get('risk_score', 0)} / 10")

                    st.markdown("**URL Analysis**")
                    st.json(url_data)

                    st.markdown("**Sender Analysis**")
                    st.json(sender_data)

                    st.markdown("**Tone Analysis**")
                    st.json(tone_data)
