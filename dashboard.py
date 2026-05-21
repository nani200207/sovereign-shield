import streamlit as st
import requests
import pandas as pd
import plotly.express as px
from reportlab.pdfgen import canvas
import io
import datetime
import base64

# Page Configuration
st.set_page_config(
    page_title="Sovereign-Shield 🇸🇪🛡️ | AI Security Platform",
    layout="wide",
    initial_sidebar_state="expanded"
)

# API Endpoint Configurations
GATEWAY_URL = "http://127.0.0.1:8000/api/proxy"
AUDIT_URL = "http://127.0.0.1:8000/api/audit"

# Dark/Light Mode Toggle
is_dark_mode = st.sidebar.toggle("🌙 Dark Mode", value=False)

if is_dark_mode:
    bg_color = "#0d1117"
    text_color = "#c9d1d9"
    card_bg = "#161b22"
    border_color = "#30363d"
    header_gradient = "linear-gradient(135deg, #1e293b, #0f172a)"
else:
    bg_color = "#f8fafc"
    text_color = "#0f172a"
    card_bg = "#ffffff"
    border_color = "#e2e8f0"
    header_gradient = "linear-gradient(135deg, #0284c7, #0369a1)"

st.markdown(f"""
<style>
    .stApp {{
        background-color: {bg_color};
        color: {text_color};
        font-family: 'Inter', -apple-system, sans-serif;
    }}
    .header-card {{
        background: {header_gradient};
        border-radius: 12px;
        padding: 26px 32px;
        margin-bottom: 28px;
        box-shadow: 0 4px 15px rgba(2, 132, 199, 0.15);
    }}
    .header-title {{
        color: #ffffff !important;
        font-size: 34px;
        font-weight: 800;
        margin: 0 0 6px 0;
    }}
    .metric-card {{
        background-color: {card_bg};
        border: 1px solid {border_color};
        border-radius: 10px;
        padding: 18px;
        text-align: center;
        margin-bottom: 18px;
    }}
    .stTextArea textarea {{
        background-color: {card_bg} !important;
        color: {text_color} !important;
        border: 1px solid {border_color} !important;
    }}
    h1, h2, h3, h4, p, span, li, label {{
        color: {text_color} !important;
    }}
</style>
""", unsafe_allow_html=True)

# App Header
st.markdown("""
<div class="header-card">
    <h1 class="header-title">Sovereign-Shield 🇸🇪🛡️ Enterprise AI Security Platform</h1>
    <p style="color: #e0f2fe !important; font-size: 16px;">
        Multi-Tenant AI Security Gateway mapping GDPR, NIS2, and the European Union AI Act. 
        Powered by spaCy NER, MITRE ATT&CK Threat Intel, and Cryptographic Logging.
    </p>
</div>
""", unsafe_allow_html=True)

# Fetch Audit Logs
try:
    response = requests.get(AUDIT_URL, headers={"X-API-Key": "tenant_default"})
    response.raise_for_status()
    audit_data = response.json()
except Exception:
    audit_data = []

# Analytics
total_requests = len(audit_data)
blocked_requests = sum(1 for x in audit_data if x.get("blocked") == 1)
redacted_pii = sum(x.get("redacted_pii_count", 0) for x in audit_data)
nis2_score = round(((total_requests - blocked_requests) / total_requests * 100), 1) if total_requests > 0 else 100.0

with st.sidebar:
    st.image("https://img.shields.io/badge/SOVEREIGN--SHIELD-ENTERPRISE-green?style=for-the-badge&logo=appveyor")
    
    st.markdown(f"### 📊 Enterprise Analytics")
    
    st.markdown(f"""
    <div class="metric-card">
        <div style="font-size:12px; font-weight:700; color:{text_color};">TOTAL AUDITS</div>
        <div style="font-size:32px; font-weight:800; color:#0284c7;">{total_requests}</div>
    </div>
    <div class="metric-card">
        <div style="font-size:12px; font-weight:700; color:{text_color};">GDPR REDACTIONS (NER)</div>
        <div style="font-size:32px; font-weight:800; color:#d97706;">{redacted_pii}</div>
    </div>
    <div class="metric-card">
        <div style="font-size:12px; font-weight:700; color:{text_color};">MITRE THREATS BLOCKED</div>
        <div style="font-size:32px; font-weight:800; color:#dc2626;">{blocked_requests}</div>
    </div>
    <div class="metric-card">
        <div style="font-size:12px; font-weight:700; color:{text_color};">NIS2 COMPLIANCE SCORE</div>
        <div style="font-size:32px; font-weight:800; color:#059669;">{nis2_score}%</div>
    </div>
    """, unsafe_allow_html=True)

    def generate_pdf():
        buffer = io.BytesIO()
        c = canvas.Canvas(buffer)
        c.setFont("Helvetica-Bold", 16)
        c.drawString(100, 800, "Sovereign-Shield EU Compliance Report 🇸🇪")
        c.setFont("Helvetica", 12)
        c.drawString(100, 770, f"Generated: {datetime.datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
        c.drawString(100, 740, f"Total Audits Logged: {total_requests}")
        c.drawString(100, 720, f"GDPR Redactions (spaCy NER): {redacted_pii}")
        c.drawString(100, 700, f"MITRE ATT&CK Threats Blocked: {blocked_requests}")
        c.drawString(100, 680, f"NIS2 Infrastructure Score: {nis2_score}%")
        
        c.drawString(100, 640, "Status: Enterprise Multi-Tenant Mode ACTIVE")
        c.drawString(100, 620, "Regulatory Alignment: GDPR, NIS2, EU AI Act")
        c.showPage()
        c.save()
        buffer.seek(0)
        return buffer

    pdf_data = generate_pdf()
    st.download_button(
        label="📄 Export EU Compliance Report (PDF)",
        data=pdf_data,
        file_name="compliance_report.pdf",
        mime="application/pdf",
        use_container_width=True
    )
    
    st.markdown("""
    <div style="background-color: #f0fdf4; border: 1px solid #bbf7d0; border-radius: 10px; padding: 14px; margin-top: 24px;">
        <span style="font-size: 24px;">🇸🇪</span>
        <div style="font-weight: 800; color: #15803d; margin-top: 6px; font-size: 13px;">SWEDISH DATA SOVEREIGNTY</div>
        <div style="color: #166534; font-size: 12px; margin-top: 4px;">Fully optimized for EU AI Act, NIS2, and GDPR regulations.</div>
    </div>
    """, unsafe_allow_html=True)

tab1, tab2, tab3 = st.tabs(["🚀 Live Security Sandbox", "📈 Real-Time Dashboards", "📝 Cryptographic Audit Logs"])

with tab1:
    st.subheader("🧪 Enterprise Security Sandbox (spaCy + Regex)")
    user_prompt = st.text_area("User Prompt Input", placeholder="Try writing a prompt injection or a Swedish Personnummer...", height=120)
    
    if st.button("🛡️ Submit Securely"):
        if user_prompt.strip():
            with st.spinner("Processing through Sovereign-Shield Enterprise Engine..."):
                try:
                    payload = {"prompt": user_prompt}
                    res = requests.post(GATEWAY_URL, json=payload, headers={"X-API-Key": "tenant_default"}, timeout=20)
                    res.raise_for_status()
                    data = res.json()
                    
                    if data.get("blocked"):
                        st.error(data.get("response"))
                        # Play Alert Sound using HTML audio
                        alert_html = """
                            <audio autoplay>
                                <source src="https://www.soundjay.com/buttons/sounds/beep-07a.mp3" type="audio/mpeg">
                            </audio>
                        """
                        st.markdown(alert_html, unsafe_allow_html=True)
                    else:
                        st.success("✅ Transaction Secured. AI Act & GDPR compliant.")
                        col1, col2 = st.columns(2)
                        with col1:
                            st.info("📤 **Scrubbed Prompt Sent**")
                            st.code(data.get("scrubbed_prompt"), language="text")
                            if data.get("pii_details"):
                                st.write("**spaCy NER Confidence Scores:**")
                                st.json(data.get("pii_details"))
                        with col2:
                            st.success("📥 **Response**")
                            st.write(data.get("response"))
                            st.write("**GDPR Articles Mapped:** ", ", ".join(data.get("gdpr_articles", [])))
                            st.write("**AI Act Risk:** ", data.get("risk_level"))
                except Exception as e:
                    st.error(f"Gateway error: {e}")
                st.rerun()

with tab2:
    st.subheader("📊 Live Threat & Compliance Telemetry")
    if audit_data:
        df = pd.DataFrame(audit_data)
        df['timestamp'] = pd.to_datetime(df['timestamp'])
        
        col1, col2 = st.columns(2)
        with col1:
            fig1 = px.histogram(df, x="timestamp", color="blocked", title="Transactions Over Time (Blocked vs Secure)")
            fig1.update_layout(paper_bgcolor=bg_color, plot_bgcolor=card_bg, font_color=text_color)
            st.plotly_chart(fig1, use_container_width=True)
            
        with col2:
            fig2 = px.pie(df, names="risk_level", title="EU AI Act Risk Classification Distribution")
            fig2.update_layout(paper_bgcolor=bg_color, font_color=text_color)
            st.plotly_chart(fig2, use_container_width=True)
    else:
        st.info("No data yet to visualize.")

with tab3:
    st.subheader("📜 Cryptographically Signed Audit Trail")
    if audit_data:
        df = pd.DataFrame(audit_data)
        # Display as clean interactive table
        st.dataframe(df, use_container_width=True)
