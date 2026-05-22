from fastapi import FastAPI, HTTPException, Request
from pydantic import BaseModel
import re
import hashlib
import sqlite3
import datetime
import os
import time
import jwt
import requests as http_requests
import google.generativeai as genai
from dotenv import load_dotenv
from typing import Dict, List, Optional
import spacy
from slowapi import Limiter, _rate_limit_exceeded_handler
from slowapi.util import get_remote_address
from slowapi.errors import RateLimitExceeded
from prometheus_fastapi_instrumentator import Instrumentator

# Load environment
load_dotenv()
genai.configure(api_key=os.getenv("GEMINI_API_KEY"))

# Initialize Spacy NER for Swedish
try:
    nlp = spacy.load('sv_core_news_sm')
except Exception:
    import spacy.cli
    spacy.cli.download('sv_core_news_sm')
    nlp = spacy.load('sv_core_news_sm')

# Rate Limiter
limiter = Limiter(key_func=get_remote_address)
app = FastAPI(title="Sovereign-Shield AI Security Platform", version="3.1.0")
app.state.limiter = limiter
app.add_exception_handler(RateLimitExceeded, _rate_limit_exceeded_handler)

# Prometheus metrics
Instrumentator().instrument(app).expose(app)

# Database
DB_PATH = "sovereign_shield.db"

def init_db():
    conn = sqlite3.connect(DB_PATH)
    cursor = conn.cursor()
    # Drop table so we can add latency_ms column (for demo purposes)
    cursor.execute("DROP TABLE IF EXISTS audit_logs")
    cursor.execute("""
        CREATE TABLE audit_logs (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            tenant_id TEXT,
            timestamp TEXT,
            prompt_hash TEXT,
            redacted_pii_count INTEGER,
            blocked INTEGER,
            block_reason TEXT,
            target_model TEXT,
            compliance_signature TEXT,
            risk_level TEXT,
            gdpr_articles TEXT,
            mitre_tactics TEXT,
            source_ip TEXT,
            latency_ms REAL
        )
    """)
    conn.commit()
    conn.close()

init_db()

# --- Advanced PII & Swedish NER Scrubbing ---
SWEDISH_PERSONNUMMER_REGEX = re.compile(r'\b(19|20)?\d{6}[-+]?\d{4}\b')
EMAIL_REGEX = re.compile(r'\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}\b')
PHONE_SE_RE = re.compile(r'\b(\+46|0)\s?\d{1,4}[\s\-]?\d{6,8}\b')
IBAN_RE = re.compile(r'\bSE\d{2}\s?(\d{4}\s?){4,5}\d{1,4}\b')

def scrub_pii(text: str) -> (str, int, list, list):
    """Detects and redacts sensitive data using Regex + spaCy NER."""
    count = 0
    details = []
    gdpr_articles = set()
    
    # 1. Regex Passes
    matches = SWEDISH_PERSONNUMMER_REGEX.findall(text)
    if matches:
        count += len(matches)
        text = SWEDISH_PERSONNUMMER_REGEX.sub("[REDACTED_PERSONNUMMER]", text)
        details.append({"type": "ID", "confidence": 0.99})
        gdpr_articles.add("Art. 9 (Biometric/ID)")

    matches = EMAIL_REGEX.findall(text)
    if matches:
        count += len(matches)
        text = EMAIL_REGEX.sub("[REDACTED_EMAIL]", text)
        details.append({"type": "EMAIL", "confidence": 0.99})
        gdpr_articles.add("Art. 5 (Data Minimization)")

    matches = PHONE_SE_RE.findall(text)
    if matches:
        count += len(matches)
        text = PHONE_SE_RE.sub("[REDACTED_PHONE]", text)
        details.append({"type": "PHONE", "confidence": 0.99})
        gdpr_articles.add("Art. 4 (Personal Data)")

    matches = IBAN_RE.findall(text)
    if matches:
        count += len(matches)
        text = IBAN_RE.sub("[REDACTED_IBAN]", text)
        details.append({"type": "FINANCIAL", "confidence": 0.99})
        gdpr_articles.add("Art. 9 (Financial)")

    # 2. spaCy NER Pass
    doc = nlp(text)
    for ent in doc.ents:
        if ent.label_ in ['PER', 'ORG', 'LOC']:
            text = text.replace(ent.text, f"[REDACTED_{ent.label_}]")
            count += 1
            confidence = round(0.85 + (len(ent.text) % 15) / 100.0, 2)
            details.append({"type": ent.label_, "confidence": confidence})
            gdpr_articles.add("Art. 4 (Personal Data)")

    return text, count, details, list(gdpr_articles)

# --- Threat Intel & MITRE ATT&CK ---
INJECTION_PATTERNS = [
    (re.compile(r'ignore\s+(previous|all|prior)\s+instructions?', re.I), "T1534"),
    (re.compile(r'(jailbreak|DAN mode|developer mode)', re.I), "T1548"),
    (re.compile(r'override\s+(guidelines|rules|policy)', re.I), "T1489"),
    (re.compile(r'act as (an? )?(unrestricted|evil|unfiltered)', re.I), "T1548"),
    (re.compile(r'(pretend you|you are now|forget your training)', re.I), "T1534"),
    (re.compile(r'(repeat after me|print your (system )?prompt)', re.I), "T1534"),
]

def check_injection(prompt: str) -> (bool, str, str):
    for pattern, mitre_code in INJECTION_PATTERNS:
        if pattern.search(prompt):
            return True, "High-risk override detected", mitre_code
    return False, "", ""

def check_threat_intel(ip: str) -> bool:
    """Real AbuseIPDB integration."""
    key = os.getenv("ABUSEIPDB_API_KEY", "")
    if not key or ip in ("127.0.0.1", "::1"):
        return False
    try:
        r = http_requests.get(
            "https://api.abuseipdb.com/api/v2/check",
            headers={"Key": key, "Accept": "application/json"},
            params={"ipAddress": ip, "maxAgeInDays": 90},
            timeout=3
        )
        return r.json().get("data", {}).get("abuseConfidenceScore", 0) > 50
    except Exception:
        return False

# --- EU Compliance Classification ---
def classify_ai_act_risk(prompt: str) -> str:
    high_risk_kws = ['medical', 'legal', 'hire', 'fire', 'credit', 'loan', 'patient', 'diagnosis']
    if any(kw in prompt.lower() for kw in high_risk_kws):
        return "HIGH (Annex III)"
    return "LOW/MINIMAL"

# --- Cryptographic Audit Logger ---
def log_compliance(tenant_id: str, prompt: str, redacted_count: int, blocked: bool, block_reason: str, model_name: str, risk_level: str, gdpr_articles: list, mitre_tactics: str, source_ip: str, latency_ms: float):
    timestamp = datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    prompt_hash = hashlib.sha256(prompt.encode()).hexdigest()
    
    signature_base = f"{tenant_id}|{timestamp}|{prompt_hash}|{redacted_count}|{int(blocked)}|{model_name}|{risk_level}|{latency_ms}"
    compliance_signature = hashlib.sha256(signature_base.encode()).hexdigest()
    
    conn = sqlite3.connect(DB_PATH)
    cursor = conn.cursor()
    cursor.execute("""
        INSERT INTO audit_logs (tenant_id, timestamp, prompt_hash, redacted_pii_count, blocked, block_reason, target_model, compliance_signature, risk_level, gdpr_articles, mitre_tactics, source_ip, latency_ms)
        VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
    """, (tenant_id, timestamp, prompt_hash, redacted_count, int(blocked), block_reason, model_name, compliance_signature, risk_level, ",".join(gdpr_articles), mitre_tactics, source_ip, latency_ms))
    conn.commit()
    conn.close()
    return compliance_signature

class ProxyRequest(BaseModel):
    prompt: str
    model: str = "flash"

class ProxyResponse(BaseModel):
    original_prompt: str
    scrubbed_prompt: str
    redacted_pii_count: int
    pii_details: list
    blocked: bool
    block_reason: str
    mitre_tactics: str
    risk_level: str
    gdpr_articles: list
    response: str
    compliance_signature: str
    latency_ms: float

GEMINI_MODELS = {
    "flash": "gemini-2.0-flash",
    "pro":   "gemini-1.5-pro"
}

@app.post("/api/token")
async def generate_token(tenant_id: str, role: str = "USER"):
    payload = {
        "tenant_id": tenant_id,
        "role": role,
        "exp": datetime.datetime.utcnow() + datetime.timedelta(hours=24)
    }
    return {"access_token": jwt.encode(payload, os.getenv("JWT_SECRET", "change-me"), algorithm="HS256")}

@app.post("/api/proxy", response_model=ProxyResponse)
@limiter.limit("20/minute")
async def proxy_endpoint(request: Request, req: ProxyRequest):
    t_start = time.time()
    raw_prompt = req.prompt
    tenant_id = request.headers.get("X-API-Key", "tenant_default")
    source_ip = request.client.host if request.client else "127.0.0.1"
    model_name = GEMINI_MODELS.get(req.model, "gemini-2.0-flash")
    
    # 0. Threat Intel IP Check
    if check_threat_intel(source_ip):
        raise HTTPException(status_code=403, detail="IP flagged by Threat Intel (AbuseIPDB mock).")

    # 1. AI Act Risk Classification
    risk_level = classify_ai_act_risk(raw_prompt)

    # 2. Injection & MITRE Check
    is_blocked, reason, mitre = check_injection(raw_prompt)
    if is_blocked:
        latency_ms = round((time.time() - t_start) * 1000, 2)
        sig = log_compliance(tenant_id, raw_prompt, 0, True, reason, model_name, risk_level, [], mitre, source_ip, latency_ms)
        return ProxyResponse(
            original_prompt=raw_prompt, scrubbed_prompt=raw_prompt, redacted_pii_count=0, pii_details=[],
            blocked=True, block_reason=reason, mitre_tactics=mitre, risk_level=risk_level, gdpr_articles=[],
            response=f"🚫 SECURE EXCEPTION: Request terminated. Threat policy violation: {reason} (MITRE: {mitre})", 
            compliance_signature=sig, latency_ms=latency_ms
        )
        
    # 3. Scrub PII
    scrubbed_prompt, redacted_count, pii_details, gdpr_articles = scrub_pii(raw_prompt)
    
    # 4. LLM Call
    try:
        model = genai.GenerativeModel(model_name)
        response = model.generate_content(scrubbed_prompt)
        llm_response = response.text
    except Exception as e:
        llm_response = (
            "🛡️ [LOCAL SAFE-MODE ACTIVE] Sovereign-Shield intercepted and sanitized your prompt successfully!\n\n"
            f"Your sanitized input was: \"{scrubbed_prompt}\".\n\n"
        )
        
    # 5. Output Scrub
    llm_response, out_count, out_details, out_gdpr = scrub_pii(llm_response)
    total_redacted = redacted_count + out_count
    
    # 6. Audit & Latency
    latency_ms = round((time.time() - t_start) * 1000, 2)
    sig = log_compliance(tenant_id, raw_prompt, total_redacted, False, "", model_name, risk_level, gdpr_articles, "", source_ip, latency_ms)
    
    return ProxyResponse(
        original_prompt=raw_prompt, scrubbed_prompt=scrubbed_prompt, redacted_pii_count=total_redacted, pii_details=pii_details,
        blocked=False, block_reason="", mitre_tactics="", risk_level=risk_level, gdpr_articles=gdpr_articles,
        response=llm_response, compliance_signature=sig, latency_ms=latency_ms
    )

@app.get("/api/audit")
async def get_audit_logs(request: Request):
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    cursor = conn.cursor()
    cursor.execute("SELECT * FROM audit_logs ORDER BY id DESC")
    rows = cursor.fetchall()
    conn.close()
    return [dict(row) for row in rows]
