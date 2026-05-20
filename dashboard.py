import streamlit as st
import requests
import pandas as pd
import base64

# Page Configuration
st.set_page_config(
    page_title="Sovereign-Shield 🇸🇪🛡️ | Compliance AI Gateway",
    layout="wide",
    initial_sidebar_state="expanded"
)

# API Endpoint Configurations
GATEWAY_URL = "http://127.0.0.1:8000/api/proxy"
AUDIT_URL = "http://127.0.0.1:8000/api/audit"

# Custom Premium Styling (PREMIUM SLATE LIGHT THEME)
st.markdown("""
<style>
    /* Premium light background with clean slate accents */
    .stApp {
        background-color: #f8fafc;
        color: #0f172a;
        font-family: 'Inter', -apple-system, sans-serif;
    }
    
    /* Clean sidebar contrast */
    [data-testid="stSidebar"] {
        background-color: #ffffff !important;
        border-right: 1px solid #e2e8f0;
    }
    
    /* High-contrast Header Card */
    .header-card {
        background: linear-gradient(135deg, #0284c7, #0369a1);
        border-radius: 12px;
        padding: 26px 32px;
        margin-bottom: 28px;
        box-shadow: 0 4px 15px rgba(2, 132, 199, 0.15);
    }
    .header-title {
        color: #ffffff !important;
        font-size: 34px;
        font-weight: 800;
        margin: 0 0 6px 0;
        letter-spacing: -0.5px;
    }
    .header-subtitle {
        color: #e0f2fe !important;
        font-size: 16px;
        font-weight: 500;
        margin: 0;
        line-height: 1.5;
    }
    
    /* Crisp light metric cards */
    .metric-card {
        background-color: #ffffff;
        border: 1px solid #e2e8f0;
        border-radius: 10px;
        padding: 18px;
        text-align: center;
        margin-bottom: 18px;
        box-shadow: 0 4px 6px -1px rgba(0, 0, 0, 0.05), 0 2px 4px -2px rgba(0, 0, 0, 0.03);
        transition: transform 0.2s ease, box-shadow 0.2s ease;
    }
    .metric-card:hover {
        transform: translateY(-2px);
        box-shadow: 0 10px 15px -3px rgba(0, 0, 0, 0.08), 0 4px 6px -4px rgba(0, 0, 0, 0.08);
    }
    .metric-value {
        font-size: 32px;
        font-weight: 800;
        margin-top: 6px;
        letter-spacing: -0.5px;
    }
    .val-neutral { color: #0f172a; }
    .val-secure { color: #059669; }
    .val-threat { color: #dc2626; }
    .val-warn { color: #d97706; }
    
    /* Audit Log visual styling */
    .audit-card {
        background-color: #ffffff;
        border-left: 5px solid #0284c7;
        padding: 16px 20px;
        border-radius: 0 10px 10px 0;
        margin-bottom: 14px;
        box-shadow: 0 1px 3px rgba(0,0,0,0.05);
        border: 1px solid #e2e8f0;
        border-left: 5px solid #0284c7;
    }
    
    /* Input Form styling - high contrast and white bg */
    .stTextArea textarea {
        background-color: #ffffff !important;
        color: #0f172a !important;
        border: 1px solid #cbd5e1 !important;
        border-radius: 10px !important;
        font-size: 15px !important;
        padding: 12px !important;
        box-shadow: inset 0 1px 2px rgba(0,0,0,0.02) !important;
    }
    .stTextArea textarea:focus {
        border-color: #0284c7 !important;
        box-shadow: 0 0 0 3px rgba(2, 132, 199, 0.15) !important;
    }
    
    /* Text readability updates */
    h1, h2, h3, h4, p, span, li, label {
        color: #0f172a !important;
    }
    
    .stMarkdown p {
        color: #334155 !important;
        font-size: 15px;
        line-height: 1.6;
    }
    
    /* Subheader color refinement */
    .stSubheader {
        font-weight: 700 !important;
        letter-spacing: -0.3px !important;
    }
</style>
""", unsafe_allow_html=True)

# App Header
st.markdown("""
<div class="header-card">
    <h1 class="header-title">Sovereign-Shield 🇸🇪🛡️</h1>
    <p class="header-subtitle">
        Enterprise AI Security Gateway proxy for GDPR, NIS2, and the European Union AI Act. 
        Detects prompt injections, redacts citizen PII locally, and logs cryptographic compliance records instantly.
    </p>
</div>
""", unsafe_allow_html=True)

# Fetch Audit Logs to calculate real-time analytics
try:
    response = requests.get(AUDIT_URL)
    response.raise_for_status()
    audit_data = response.json()
except Exception:
    audit_data = []

# Sidebar Analytics & Metrics
total_requests = len(audit_data)
blocked_requests = sum(1 for x in audit_data if x.get("blocked") == 1)
redacted_pii = sum(x.get("redacted_pii_count", 0) for x in audit_data)
health_rate = round(((total_requests - blocked_requests) / total_requests * 100), 1) if total_requests > 0 else 100.0

with st.sidebar:
    st.image("https://img.shields.io/badge/SOVEREIGN--SHIELD-ACTIVE-green?style=for-the-badge&logo=appveyor")
    
    st.markdown("<h3 style='color:#0f172a; font-size:18px; margin-top:20px; font-weight:700;'>📊 Compliance Analytics</h3>", unsafe_allow_html=True)
    
    st.markdown(f"""
    <div class="metric-card">
        <div style="color:#64748b; font-size:12px; font-weight:700; letter-spacing:0.5px;">TOTAL PROMPTS AUDITED</div>
        <div class="metric-value val-neutral">{total_requests}</div>
    </div>
    """, unsafe_allow_html=True)
    
    st.markdown(f"""
    <div class="metric-card">
        <div style="color:#64748b; font-size:12px; font-weight:700; letter-spacing:0.5px;">GDPR PII REDACTIONS</div>
        <div class="metric-value val-warn">{redacted_pii}</div>
    </div>
    """, unsafe_allow_html=True)
    
    st.markdown(f"""
    <div class="metric-card">
        <div style="color:#64748b; font-size:12px; font-weight:700; letter-spacing:0.5px;">INJECTIONS BLOCKED</div>
        <div class="metric-value val-threat">{blocked_requests}</div>
    </div>
    """, unsafe_allow_html=True)
    
    st.markdown(f"""
    <div class="metric-card">
        <div style="color:#64748b; font-size:12px; font-weight:700; letter-spacing:0.5px;">GATEWAY HEALTH RATIO</div>
        <div class="metric-value val-secure">{health_rate}%</div>
    </div>
    """, unsafe_allow_html=True)
    
    # Beautifully styled Sweden Sovereignty Badge
    st.markdown("""
    <div style="background-color: #f0fdf4; border: 1px solid #bbf7d0; border-radius: 10px; padding: 14px; margin-top: 24px; box-shadow: 0 1px 3px rgba(0,0,0,0.02);">
        <span style="font-size: 24px;">🇸🇪</span>
        <div style="font-weight: 800; color: #15803d; margin-top: 6px; font-size: 13px; letter-spacing: 0.3px;">SWEDISH DATA SOVEREIGNTY</div>
        <div style="color: #166534; font-size: 12px; margin-top: 4px; line-height: 1.4;">Fully optimized for EU AI Act, NIS2, and GDPR regulations.</div>
    </div>
    """, unsafe_allow_html=True)

# Tabs
tab1, tab2 = st.tabs(["🚀 Live Compliance Sandbox", "📝 Cryptographic Audit Logs (EU AI Act)"])

# --- TAB 1: Live Compliance Sandbox ---
with tab1:
    st.subheader("🧪 Test the Security Gateway")
    st.write(
        "Type a prompt to test. Try writing a prompt injection (like *'ignore previous instructions'*) "
        "or writing a Swedish Personnummer (*'My ID is 19900512-1234'*) or standard email to witness the dynamic security filters!"
    )
    
    user_prompt = st.text_area("User Prompt Input", placeholder="Skriv din fråga eller prompt här...", height=120)
    col1, col2 = st.columns([1, 4])
    
    with col1:
        run_btn = st.button("🛡️ Submit Securely")
        
    with col2:
        st.caption("🔒 All scrubbing and injection filters are executed locally inside Sweden before reaching the LLM cloud.")
        
    if run_btn:
        if not user_prompt.strip():
            st.warning("Please enter a valid prompt to test.")
        else:
            with st.spinner("Processing through Sovereign-Shield proxy..."):
                try:
                    payload = {"prompt": user_prompt}
                    res = requests.post(GATEWAY_URL, json=payload, timeout=20)
                    res.raise_for_status()
                    data = res.json()
                except Exception as e:
                    st.error(f"Failed to communicate with local gateway proxy: {e}")
                else:
                    # Render response components
                    if data.get("blocked"):
                        st.error(data.get("response"))
                        st.markdown(f"**Blocked Threat Reason:** `{data.get('block_reason')}`")
                        st.markdown(f"**Hashed SHA-256 Compliance Signature:** `{data.get('compliance_signature')}`")
                    else:
                        st.success("✅ Prompt clean. Secured transaction successfully forwarded.")
                        
                        col_in, col_out = st.columns(2)
                        with col_in:
                            st.info("📤 **Scrubbed Prompt Sent to LLM Cloud**")
                            st.code(data.get("scrubbed_prompt"), language="text")
                            st.metric("GDPR Redacted Entities Count", data.get("redacted_pii_count"))
                        with col_out:
                            st.success("📥 **Scrubbed Response Returned to User**")
                            st.write(data.get("response"))
                            st.markdown(f"**Compliance Stamp:** `{data.get('compliance_signature')}`")
                            
                    # Trigger rerun to update sidebar metrics instantly
                    st.rerun()

# --- TAB 2: Cryptographic Audit Logs ---
with tab2:
    st.subheader("📜 Cryptographically Signed Audit Trail")
    st.write(
        "Below are the tamper-proof compliance logs generated in real-time. In accordance with the **EU AI Act**, "
        "every prompt is logged securely with a cryptographic hash, a redacted count, and a SHA-256 signature."
    )
    
    if audit_data:
        df = pd.DataFrame(audit_data)
        # Reorder columns for optimal look
        df_display = df[[
            "id", "timestamp", "prompt_hash", "redacted_pii_count", 
            "blocked", "block_reason", "target_model", "compliance_signature"
        ]]
        
        # Display as clean interactive table
        st.dataframe(df_display, use_container_width=True)
        
        st.download_button(
            label="📥 Download Audit Logs (.csv)",
            data=df_display.to_csv(index=False),
            file_name="sovereign_shield_compliance_audit.csv",
            mime="text/csv"
        )
    else:
        st.info("No compliance records found. Submit prompts in the sandbox to generate compliance logs!")
