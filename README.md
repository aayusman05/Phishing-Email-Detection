# 🔍 Phishing Email Detection Agent

An intelligent phishing email detection system powered by AI. This agent analyzes emails using multiple detection techniques and an LLM to classify them as **Safe**, **Suspicious**, or **Phishing** with confidence scoring.

## ✨ Features

- **Multi-Stage Analysis**: Combines URL analysis, sender verification, and tone detection
- **AI-Powered Reasoning**: Uses Llama 3.3 70B model via Groq API for intelligent decision-making
- **Interactive Web UI**: Built with Streamlit for easy email analysis
- **Sample Emails**: Try pre-built safe, suspicious, and phishing email samples
- **Detailed Reporting**: Get reasoning and key signals for each analysis
- **Batch Evaluation**: Evaluate against large datasets for performance metrics
- **Confidence Scoring**: Low, Medium, or High confidence verdicts with automatic re-analysis for low confidence results

## 🛠️ Technology Stack

- **Frontend**: [Streamlit](https://streamlit.io/) - Web UI framework
- **LLM Provider**: [Groq](https://groq.com/) - Fast inference on Llama 3.3 70B
- **Language**: Python 3.x

## 📋 Project Structure

```
phishing-agent/
├── app.py                 # Streamlit web application
├── agent.py              # Core analysis engine
├── tools.py              # Feature extraction tools (URLs, sender, tone)
├── prompts.py            # System prompt for the LLM
├── evaluate.py           # Batch evaluation script
├── requirements.txt      # Python dependencies
├── samples/              # Sample emails for testing
│   ├── safe.txt
│   ├── suspicious.txt
│   └── phishing.txt
└── README.md
```

## 🚀 Getting Started

### Prerequisites

- Python 3.8+
- Groq API key ([sign up free](https://console.groq.com))

### Installation

1. **Clone or download the project**
   ```bash
   cd phishing-agent
   ```

2. **Install dependencies**
   ```bash
   pip install -r requirements.txt
   ```

3. **Set up API key**
   ```bash
   export GROQ_API_KEY="your-groq-api-key-here"
   ```

### Running the Application

**Start the Streamlit web app:**
```bash
streamlit run app.py
```

The app will open in your browser at `http://localhost:8501`

**Batch evaluation:**
```bash
python evaluate.py --samples 100 --dataset path/to/phishing_email.csv
```

## 💡 How It Works

### Analysis Pipeline

1. **Feature Extraction** (3 parallel tools)
   - **URL Analysis**: Detects suspicious URLs, IP addresses, and malicious TLDs
   - **Sender Analysis**: Verifies sender legitimacy, domain spoofing, free email providers
   - **Tone Analysis**: Identifies urgency words and manipulative language

2. **Risk Scoring**: Each tool produces a risk score (0-10)

3. **LLM Reasoning**: Groq's Llama 3.3 70B model analyzes all signals and produces a structured verdict

4. **Confidence Handling**: Low confidence results trigger automatic re-analysis

5. **Structured Output**:
   ```json
   {
     "verdict": "Safe|Suspicious|Phishing",
     "confidence": "Low|Medium|High",
     "reasoning": "2-3 sentence explanation",
     "key_signals": ["signal1", "signal2", ...]
   }
   ```

## 🎯 Usage Examples

### Web UI
1. Paste an email (including headers) into the text area
2. Click "Analyse" button
3. View the verdict and detailed analysis
4. Try sample emails using the buttons

### Programmatic Usage
```python
from agent import analyse_email

result = analyse_email(email_text)
print(result['verdict'])          # "Safe", "Suspicious", or "Phishing"
print(result['confidence'])       # "Low", "Medium", or "High"
print(result['reasoning'])        # Detailed explanation
print(result['key_signals'])      # List of important signals
```

## 🔍 Detection Signals

### URL-Based Signals
- IP addresses used as domain
- Suspicious TLDs (.ru, .xyz, .tk, .ml, etc.)
- URL shorteners
- Mismatched display vs actual URLs

### Sender-Based Signals
- Sender spoofing or domain impersonation
- Free email provider for corporate communication
- Domain typosquatting (leet-speak variants)
- Suspicious TLDs in sender domain

### Tone-Based Signals
- Urgency words ("urgent", "immediate", "act now", etc.)
- Threatening language
- Excessive capitalization
- Suspicious punctuation patterns

## 📊 Evaluation & Metrics

The project includes tools for batch evaluation:

- **evaluate_results.csv**: Individual email predictions
- **evaluate_metrics.json**: Overall performance metrics (precision, recall, F1-score)

## 🔐 API Key Setup

### For macOS/Linux
```bash
export GROQ_API_KEY="gsk_your_key_here"
```

### For Windows
```powershell
$env:GROQ_API_KEY="gsk_your_key_here"
```

### Verify Setup
```bash
python -c "import os; print('API Key set!' if os.getenv('GROQ_API_KEY') else 'API Key NOT set')"
```

## 📝 Requirements

See `requirements.txt`:
- `groq` - Groq API client
- `streamlit` - Web UI framework

## ⚠️ Limitations

- Requires internet connection (Groq API)
- API rate limits apply (check Groq documentation)
- Analysis depends on email format quality
- LLM-based verdicts may vary with model updates

## 🤝 Contributing

To improve the detection:
1. Add more samples to `samples/` directory
2. Enhance tools in `tools.py` with additional heuristics
3. Fine-tune the system prompt in `prompts.py`
4. Run evaluation against test datasets

## 📄 License

This project is open source. See LICENSE file if present.

## 🆘 Troubleshooting

### "GROQ_API_KEY not set"
- Ensure you've set the environment variable
- Restart your terminal/IDE after setting

### "Failed to parse model response"
- May indicate API error or response formatting issue
- Check Groq API status
- Verify API key is valid

### Streamlit connection issues
- Ensure you have internet access
- Check firewall settings
- Verify Groq API endpoint is reachable

## 📮 Contact & Support

For issues or questions about this project, please create an issue in the repository.

---

**Last Updated**: May 2026
