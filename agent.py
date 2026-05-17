import json
from groq import Groq

from tools import extract_urls, analyse_sender, analyse_tone
from prompts import SYSTEM_PROMPT

# llama-3.3-70b-versatile is capable and available on Groq's free tier
MODEL = "llama-3.3-70b-versatile"


def analyse_email(email_text: str) -> dict:
    """
    Run all three feature-extraction tools on the email, then ask Claude
    to reason over the results and return a structured verdict.

    Returns a dict with keys: verdict, confidence, reasoning, key_signals
    On failure, returns a dict with key: error
    """
    # Step 1 — run all three tools
    url_result = extract_urls(email_text)
    sender_result = analyse_sender(email_text)
    tone_result = analyse_tone(email_text)

    # Step 2 — build a structured report
    report = f"""=== EMAIL ANALYSIS REPORT ===

--- URL Analysis ---
URLs found: {url_result['urls_found']}
Suspicious URLs: {url_result['suspicious_urls']}
URL risk score: {url_result['risk_score']} / 10

--- Sender Analysis ---
Sender: {sender_result['sender']}
Domain: {sender_result['domain']}
Flags: {sender_result['flags']}
Sender risk score: {sender_result['risk_score']} / 10

--- Tone Analysis ---
Urgency words found: {tone_result['urgency_words_found']}
Count: {tone_result['count']}
Tone risk score: {tone_result['risk_score']} / 10

--- Raw Email ---
{email_text}
"""

    # Step 3 — call the Groq API (reads GROQ_API_KEY from environment)
    client = Groq()

    response = client.chat.completions.create(
        model=MODEL,
        max_tokens=500,
        messages=[
            {"role": "system", "content": SYSTEM_PROMPT},
            {"role": "user", "content": report},
        ],
    )

    raw_text = response.choices[0].message.content.strip()

    # Step 4 — parse the JSON response
    def _parse_json(text: str) -> dict:
        try:
            return json.loads(text)
        except json.JSONDecodeError:
            json_match = __import__("re").search(r"\{.*\}", text, __import__("re").DOTALL)
            if json_match:
                try:
                    return json.loads(json_match.group())
                except json.JSONDecodeError:
                    pass
            return {"error": "Failed to parse model response", "raw": text}

    result = _parse_json(raw_text)

    # Step 5 — confidence-based re-analysis (one retry only)
    reanalysed = False
    if "error" not in result and result.get("confidence") == "Low":
        retry_instruction = (
            "Your previous analysis returned Low confidence. "
            "Re-examine the evidence more critically. "
            "Look for any signal you may have underweighted. "
            "You must commit to a final verdict with Medium or High confidence. "
            "Return the same JSON format."
        )
        retry_response = client.chat.completions.create(
            model=MODEL,
            max_tokens=500,
            messages=[
                {"role": "system", "content": SYSTEM_PROMPT},
                {"role": "user", "content": report},
                {"role": "assistant", "content": raw_text},
                {"role": "user", "content": retry_instruction},
            ],
        )
        retry_raw = retry_response.choices[0].message.content.strip()
        retry_result = _parse_json(retry_raw)
        if "error" not in retry_result:
            result = retry_result
            reanalysed = True

    result["reanalysed"] = reanalysed

    # Attach raw tool outputs for the UI to display
    result["_tool_outputs"] = {
        "url_analysis": url_result,
        "sender_analysis": sender_result,
        "tone_analysis": tone_result,
    }

    return result


if __name__ == "__main__":
    import sys
    import os

    if len(sys.argv) > 1:
        path = sys.argv[1]
        if os.path.isfile(path):
            with open(path) as f:
                text = f.read()
            result = analyse_email(text)
            print(json.dumps(result, indent=2))
        else:
            print(f"File not found: {path}")
    else:
        print("Usage: python agent.py <email_file.txt>")
