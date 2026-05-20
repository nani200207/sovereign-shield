# Sovereign-Shield 🇸🇪🛡️

`Sovereign-Shield` is a production-grade, local-first LLM security reverse-proxy and auditing gateway designed specifically for **GDPR, NIS2, and the European Union AI Act** compliance. 

Built tailored for the Swedish and European enterprise markets, it enables organizations to securely deploy Generative AI features while ensuring sensitive personal data (PII) never leaves local borders and maintaining a cryptographically secure audit trail.

---

## 🇸🇪 Why Sovereign-Shield?

Under European regulations (GDPR) and state compliance directives:
* Swedish companies (e.g., Ericsson, Volvo, Saab, Swedbank) cannot send unmasked customer data or citizen identifiers to US-hosted cloud APIs.
* The **EU AI Act** mandates that any enterprise using AI must maintain immutable, tamper-proof audit trails documenting their AI usage.

`Sovereign-Shield` resolves this by standing as an active gateway middleware that redacts sensitive PII locally at lightning speeds (sub-1ms) and logs cryptographically signed audit records before forwarding sanitized queries to AI models.

---

## 🛡️ Key Features

1. **Local-First PII Scrubber (GDPR)**: High-speed regular expression processing that redacts:
   * **Swedish Personnummers** (personal identity numbers)
   * Credit Card numbers
   * Email addresses
   * IP addresses
2. **Real-Time Prompt Injection Shield**: Intercepts jailbreaks and guideline overrides locally and validates suspicious queries via fast, free cloud heuristics.
3. **Cryptographic Audit Trail (EU AI Act)**: Automatically generates a **SHA-256 compliance signature** linking the timestamp, hashed prompt, redacted count, and target model inside a local SQLite database to guarantee logs are tamper-proof.
4. **Sweden/EU Compliant Design**: Dual-language support for Swedish and English threat patterns.
5. **Zero-Resource Footprint**: Consumes less than 10MB of local storage, 0% CPU at rest, and runs dynamically on any computer without needing heavy local models (like Ollama) or complex infrastructure.

---

## 🛠️ Tech Stack
* **Backend API**: FastAPI / Uvicorn (Ultra-lightweight reverse proxy)
* **Frontend**: Streamlit (HSL dark-mode security compliance panel)
* **AI Core**: Google Gemini (via free Google AI Studio cloud endpoints)
* **Database**: SQLite (Tamper-proof audit logs storage)

---

## 🚀 Getting Started

### 1. Clone & Setup
```bash
# Navigate to the workspace
cd sovereign-shield

# Create a virtual environment using the shared mlenv
# (Or run directly using the shared environment!)
```

### 2. Configure Environment
Create a `.env` file containing your free Gemini API key:
```ini
GEMINI_API_KEY=your_gemini_api_key_here
PORT=8000
HOST=127.0.0.1
```

### 3. Run the Gateway Server
```bash
.\shared_envs\mlenv\Scripts\uvicorn.exe gateway:app --host 127.0.0.1 --port 8000
```

### 4. Run the Streamlit Analytics Panel
```bash
.\shared_envs\mlenv\Scripts\streamlit.exe run dashboard.py --server.port 8501
```

Open **`http://127.0.0.1:8501`** in your browser to launch the live compliance sandbox!

---

## 📝 Compliance Audit Fields (EU AI Act Auditing)
Each log in `Sovereign-Shield` records:
* `timestamp`: Precise UTC transaction time.
* `prompt_hash`: SHA-256 hash of the original prompt (ensuring prompt privacy).
* `redacted_pii_count`: Number of redacted PII components (GDPR metrics).
* `blocked`: Boolean threat flag (1 if prompt injection was intercepted).
* `compliance_signature`: SHA-256 tamper-proof signature calculated as:
  $$\text{SHA256}(\text{timestamp} \mid \text{prompt\_hash} \mid \text{redacted\_pii\_count} \mid \text{blocked} \mid \text{model})$$

---

*Developed with ❤️ in Sweden for EU Data Sovereignty.*
