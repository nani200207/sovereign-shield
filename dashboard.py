import streamlit as st
import requests
import pandas as pd
import plotly.express as px
from reportlab.pdfgen import canvas
from reportlab.platypus import SimpleDocTemplate, Table, TableStyle, Paragraph, Spacer
from reportlab.lib.pagesizes import letter
from reportlab.lib.styles import getSampleStyleSheet
from reportlab.lib import colors
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
        doc = SimpleDocTemplate(buffer, pagesize=letter)
        elements = []
        styles = getSampleStyleSheet()
        
        # Title
        elements.append(Paragraph("<b>Sovereign-Shield EU Compliance Report 🇸🇪</b>", styles['Title']))
        elements.append(Spacer(1, 12))
        elements.append(Paragraph(f"<b>Generated:</b> {datetime.datetime.now().strftime('%Y-%m-%d %H:%M:%S')}", styles['Normal']))
        elements.append(Spacer(1, 12))
        
        # Calculate per-tenant stats
        tenant_stats = {}
        for row in audit_data:
            tid = row.get('tenant_id', 'Unknown')
            if tid not in tenant_stats:
                tenant_stats[tid] = {'requests': 0, 'blocked': 0, 'pii': 0}
            tenant_stats[tid]['requests'] += 1
            if row.get('blocked') == 1:
                tenant_stats[tid]['blocked'] += 1
            tenant_stats[tid]['pii'] += row.get('redacted_pii_count', 0)
            
        data = [['Tenant ID', 'Total Requests', 'Blocked Threats', 'PII Redacted']]
        for tid, stats in tenant_stats.items():
            data.append([tid, str(stats['requests']), str(stats['blocked']), str(stats['pii'])])
            
        if not tenant_stats:
            data.append(['No Data', '0', '0', '0'])
            
        t = Table(data, colWidths=[150, 100, 100, 100])
        t.setStyle(TableStyle([
            ('BACKGROUND', (0,0), (-1,0), colors.HexColor("#0284c7")),
            ('TEXTCOLOR', (0,0), (-1,0), colors.whitesmoke),
            ('ALIGN', (0,0), (-1,-1), 'CENTER'),
            ('FONTNAME', (0,0), (-1,0), 'Helvetica-Bold'),
            ('BOTTOMPADDING', (0,0), (-1,0), 12),
            ('BACKGROUND', (0,1), (-1,-1), colors.beige),
            ('GRID', (0,0), (-1,-1), 1, colors.black)
        ]))
        elements.append(t)
        
        doc.build(elements)
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

tab1, tab2, tab3 = st.tabs(["🚀 Live Security Sandbox", "📈 Real-Time Dashboards", "📝 Cryptographic Audit Logs"])

with tab1:
    st.subheader("🧪 Enterprise Security Sandbox")
    model_choice = st.selectbox("Gemini Model", ["flash", "pro"])
    user_prompt = st.text_area("User Prompt Input", placeholder="Try writing a prompt injection or a Swedish Personnummer...", height=120)
    
    if st.button("🛡️ Submit Securely"):
        if user_prompt.strip():
            with st.spinner(f"Processing through Sovereign-Shield Engine (Model: {model_choice})..."):
                try:
                    payload = {"prompt": user_prompt, "model": model_choice}
                    res = requests.post(GATEWAY_URL, json=payload, headers={"X-API-Key": "tenant_default"}, timeout=20)
                    res.raise_for_status()
                    data = res.json()
                    
                    if data.get("blocked"):
                        st.error(data.get("response"))
                        alert_html = """
                            <audio autoplay>
                                <source src="https://www.soundjay.com/buttons/sounds/beep-07a.mp3" type="audio/mpeg">
                            </audio>
                        """
                        st.markdown(alert_html, unsafe_allow_html=True)
                    else:
                        st.success(f"✅ Transaction Secured. (Latency: {data.get('latency_ms')} ms)")
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
            
        if 'latency_ms' in df.columns and not df['latency_ms'].isnull().all():
            fig3 = px.line(df.sort_values("timestamp"), x="timestamp", y="latency_ms", title="Response Latency Over Time (ms)")
            fig3.update_layout(paper_bgcolor=bg_color, plot_bgcolor=card_bg, font_color=text_color)
            st.plotly_chart(fig3, use_container_width=True)
    else:
        st.info("No data yet to visualize.")

with tab3:
    st.subheader("📜 Cryptographically Signed Audit Trail")
    if audit_data:
        df = pd.DataFrame(audit_data)
        st.dataframe(df, use_container_width=True)
