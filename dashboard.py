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

# Page Configuration
st.set_page_config(
    page_title="Sovereign-Shield | AI Security Platform",
    layout="wide",
    initial_sidebar_state="expanded"
)

# API Endpoint Configurations
GATEWAY_URL = "http://127.0.0.1:8000/api/proxy"
AUDIT_URL = "http://127.0.0.1:8000/api/audit"
TOKEN_URL = "http://127.0.0.1:8000/api/token"
ADMIN_TENANTS_URL = "http://127.0.0.1:8000/api/admin/tenants"
ADMIN_POLICIES_URL = "http://127.0.0.1:8000/api/admin/policies"

# Dark/Light Mode Toggle
is_dark_mode = st.sidebar.toggle("Dark Mode", value=False)

if is_dark_mode:
    bg_color = "#0d1117"
    sidebar_bg = "#161b22"
    text_color = "#c9d1d9"
    card_bg = "#1f2937"
    border_color = "#374151"
    header_gradient = "linear-gradient(135deg, #1e293b, #0f172a)"
    metric_label_color = "#9ca3af"
    metric_value_color = "#f3f4f6"
else:
    bg_color = "#ffffff"
    sidebar_bg = "#f1f5f9"
    text_color = "#0f172a"
    card_bg = "#f8fafc"
    border_color = "#cbd5e1"
    header_gradient = "linear-gradient(135deg, #0284c7, #0369a1)"
    metric_label_color = "#475569"
    metric_value_color = "#0f172a"

# Advanced High-Contrast Custom CSS styling
st.markdown(f"""
<style>
    /* Full Page Background Overrides */
    .stApp, [data-testid="stAppViewContainer"] {{
        background-color: {bg_color} !important;
        color: {text_color} !important;
        font-family: 'Inter', -apple-system, sans-serif;
    }}
    
    /* Sidebar Background Overrides */
    [data-testid="stSidebar"], [data-testid="stSidebar"] > div {{
        background-color: {sidebar_bg} !important;
    }}
    
    /* Header Card Styling */
    .header-card {{
        background: {header_gradient};
        border-radius: 12px;
        padding: 26px 32px;
        margin-bottom: 28px;
        box-shadow: 0 4px 15px rgba(2, 132, 199, 0.1);
    }}
    .header-title {{
        color: #ffffff !important;
        font-size: 34px;
        font-weight: 800;
        margin: 0 0 6px 0;
    }}
    .header-subtitle {{
        color: #e0f2fe !important;
        font-size: 16px;
        margin: 0;
    }}
    
    /* Custom Telemetry Metrics Cards */
    .metric-card {{
        background-color: {card_bg};
        border: 1px solid {border_color};
        border-radius: 10px;
        padding: 18px;
        text-align: center;
        margin-bottom: 18px;
        box-shadow: 0 1px 3px rgba(0, 0, 0, 0.05);
    }}
    .metric-label {{
        font-size: 11px;
        font-weight: 700;
        letter-spacing: 0.05em;
        color: {metric_label_color} !important;
        margin-bottom: 4px;
        text-transform: uppercase;
    }}
    .metric-value {{
        font-size: 28px;
        font-weight: 800;
        color: {metric_value_color} !important;
        line-height: 1.1;
    }}
    
    /* Input Form Label Styling */
    label, [data-testid="stWidgetLabel"] p {{
        color: {text_color} !important;
        font-weight: 600 !important;
    }}
    
    /* Standard Text Styling */
    p, span, li {{
        color: {text_color} !important;
    }}
    
    /* Title Subheaders styling */
    h1, h2, h3, h4, h5, h6 {{
        color: {text_color} !important;
        font-weight: 700 !important;
    }}
    
    /* Tab label styling */
    button[data-baseweb="tab"] p {{
        font-weight: 600 !important;
        font-size: 15px !important;
    }}
</style>
""", unsafe_allow_html=True)

# App Header
st.markdown(f"""
<div class="header-card">
    <h1 class="header-title">Sovereign-Shield Enterprise AI Security Platform</h1>
    <p class="header-subtitle">
        Asynchronous Multi-Tenant AI Security Platform mapped to GDPR, NIS2, and the EU AI Act.
        Featuring Dynamic Tenant Policy Controls, Vendor-Agnostic LLM Gateways, and Token-Billing Cost Telemetry.
    </p>
</div>
""", unsafe_allow_html=True)

# --- Tenant Session & JWT Auth Resolver ---
st.sidebar.markdown("### Tenant Session")
active_tenant_id = st.sidebar.selectbox("Selected Tenant Profile", ["tenant_default", "tenant_pro", "tenant_enterprise"])

# Fetch dynamic JWT Token for active tenant
access_token = ""
tenant_api_key = "free_key_123"
tenant_tier = "Free"
tenant_webhook = ""

try:
    token_res = requests.post(f"{TOKEN_URL}?tenant_id={active_tenant_id}")
    if token_res.status_code == 200:
        access_token = token_res.json().get("access_token", "")
except Exception:
    pass

# Retrieve active tenant API Key & Policy settings from Admin Route
tenant_policy = {}
try:
    tenants_list_res = requests.get(ADMIN_TENANTS_URL)
    if tenants_list_res.status_code == 200:
        for t in tenants_list_res.json():
            if t.get("id") == active_tenant_id:
                tenant_api_key = t.get("api_key", "free_key_123")
                tenant_tier = t.get("tier", "Free")
                tenant_webhook = t.get("webhook_url", "")
                tenant_policy = t
                break
except Exception:
    pass

# Fetch Audit Logs with Bearer Token
audit_data = []
if access_token:
    try:
        response = requests.get(AUDIT_URL, headers={"Authorization": f"Bearer {access_token}"})
        if response.status_code == 200:
            audit_data = response.json()
    except Exception:
        pass

# Analytics Metrics
total_requests = len(audit_data)
blocked_requests = sum(1 for x in audit_data if x.get("blocked") == 1)
redacted_pii = sum(x.get("redacted_pii_count", 0) for x in audit_data)
total_tokens = sum(x.get("tokens_used", 0) for x in audit_data)
total_cost = sum(x.get("cost_usd", 0.0) for x in audit_data)
nis2_score = round(((total_requests - blocked_requests) / total_requests * 100), 1) if total_requests > 0 else 100.0

with st.sidebar:
    st.image(f"https://img.shields.io/badge/TIER-{tenant_tier.upper()}-blue?style=for-the-badge")
    st.markdown(f"**Webhook Alerts Endpoint:** `{tenant_webhook if tenant_webhook else 'None Configured'}`")
    
    st.markdown("### Live Analytics Dashboard")
    st.markdown(f"""
    <div class="metric-card">
        <div class="metric-label">Total Transactions</div>
        <div class="metric-value">{total_requests}</div>
    </div>
    <div class="metric-card">
        <div class="metric-label">GDPR Redactions (spaCy NER)</div>
        <div class="metric-value">{redacted_pii}</div>
    </div>
    <div class="metric-card">
        <div class="metric-label">Cost Chargeback (USD)</div>
        <div class="metric-value">${total_cost:.5f}</div>
    </div>
    <div class="metric-card">
        <div class="metric-label">NIS2 Infrastructure Score</div>
        <div class="metric-value">{nis2_score}%</div>
    </div>
    """, unsafe_allow_html=True)

    def generate_pdf():
        buffer = io.BytesIO()
        doc = SimpleDocTemplate(buffer, pagesize=letter)
        elements = []
        styles = getSampleStyleSheet()
        
        elements.append(Paragraph("<b>Sovereign-Shield EU Compliance Report</b>", styles['Title']))
        elements.append(Spacer(1, 12))
        elements.append(Paragraph(f"<b>Tenant profile:</b> {active_tenant_id} ({tenant_tier} Tier)", styles['Normal']))
        elements.append(Paragraph(f"<b>Generated:</b> {datetime.datetime.now().strftime('%Y-%m-%d %H:%M:%S')}", styles['Normal']))
        elements.append(Spacer(1, 15))
        
        data = [
            ['Metric Description', 'Value'],
            ['Total Requests Logged', str(total_requests)],
            ['Blocked Security Incidents', str(blocked_requests)],
            ['PII Data Redactions (spaCy NER)', str(redacted_pii)],
            ['Estimated LLM Token Overhead', f"{total_tokens} tokens"],
            ['Department Cost Allocation', f"${total_cost:.5f}"],
            ['NIS2 Compliance Score', f"{nis2_score}%"]
        ]
        
        t = Table(data, colWidths=[250, 200])
        t.setStyle(TableStyle([
            ('BACKGROUND', (0,0), (-1,0), colors.HexColor("#0284c7")),
            ('TEXTCOLOR', (0,0), (-1,0), colors.whitesmoke),
            ('ALIGN', (0,0), (-1,-1), 'LEFT'),
            ('FONTNAME', (0,0), (-1,0), 'Helvetica-Bold'),
            ('BOTTOMPADDING', (0,0), (-1,0), 8),
            ('ROWBACKGROUNDS', (0,1), (-1,-1), [colors.HexColor("#f8fafc"), colors.HexColor("#ffffff")]),
            ('GRID', (0,0), (-1,-1), 1, colors.HexColor("#cbd5e1"))
        ]))
        elements.append(t)
        doc.build(elements)
        buffer.seek(0)
        return buffer

    pdf_data = generate_pdf()
    st.download_button(
        label="Export EU Compliance Report (PDF)",
        data=pdf_data,
        file_name=f"compliance_report_{active_tenant_id}.pdf",
        mime="application/pdf",
        use_container_width=True
    )

tab1, tab2, tab3, tab4, tab5 = st.tabs([
    "Live Security Sandbox", 
    "Tenant Policies", 
    "Real-Time Dashboards", 
    "Cryptographic Audit Logs",
    "Platform Admin Suite"
])

with tab1:
    st.subheader("Enterprise Security Sandbox (Multi-LLM)")
    
    col_a, col_b = st.columns(2)
    with col_a:
        provider_choice = st.selectbox("LLM Cloud Provider", ["gemini", "openai", "anthropic"])
    with col_b:
        if provider_choice == "gemini":
            model_choice = st.selectbox("Model", ["flash", "pro"])
        elif provider_choice == "openai":
            model_choice = st.selectbox("Model", ["gpt-4o", "gpt-4o-mini"])
        else:
            model_choice = st.selectbox("Model", ["claude-3-5-sonnet"])
            
    user_prompt = st.text_area("Prompt Input Buffer", placeholder="Type a prompt to test your policies...", height=120)
    
    if st.button("Submit Securely"):
        if user_prompt.strip():
            with st.spinner("Sanitizing prompt, verifying risk guidelines and executing API..."):
                try:
                    payload = {"prompt": user_prompt, "provider": provider_choice, "model": model_choice}
                    headers = {"X-API-Key": tenant_api_key}
                    res = requests.post(GATEWAY_URL, json=payload, headers=headers, timeout=20)
                    
                    if res.status_code == 403:
                        st.error("Access Blocked by Security Policies (AbuseIPDB Threat Intelligence check).")
                    elif res.status_code == 200:
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
                            st.success(f"Transaction Completed successfully! (Latency: {data.get('latency_ms')} ms)")
                            col1, col2 = st.columns(2)
                            with col1:
                                st.info("Input Prompt Sanitized")
                                st.code(data.get("scrubbed_prompt"), language="text")
                                if data.get("input_scrubbed"):
                                    st.write("**PII Found (Input):**")
                                    st.json(data.get("pii_details", []))
                            with col2:
                                st.success("Output Response Sanitized")
                                st.write(data.get("response"))
                                
                                # Highlight Response PII scrubbing
                                if data.get("output_scrubbed"):
                                    st.warning("Sensitive leaked data was detected in output and successfully redacted!")
                                    st.code(data.get("output_scrubbed"), language="text")
                                    
                                st.write("**Cost Allocation:**", f"${data.get('cost_usd', 0.0):.6f}")
                                st.write("**EU AI Act Risk:**", data.get("risk_level"))
                                st.write("**GDPR Articles Matched:**", ", ".join(data.get("gdpr_articles", [])))
                    else:
                        st.error(f"Error: {res.text}")
                except Exception as e:
                    st.error(f"Gateway connection error: {e}")
                st.rerun()

with tab2:
    st.subheader("Configure Active Tenant Security Policy")
    if tenant_policy:
        p_bp = st.checkbox("Block Swedish Personnummers", value=bool(tenant_policy.get("block_personnummer", 1)))
        p_be = st.checkbox("Block Email Addresses", value=bool(tenant_policy.get("block_email", 1)))
        p_bp_ph = st.checkbox("Block Swedish Phone Numbers", value=bool(tenant_policy.get("block_phone", 1)))
        p_bi = st.checkbox("Block IBANs / Bank Accounts", value=bool(tenant_policy.get("block_iban", 1)))
        
        # spaCy Entities selector
        entities_input = st.text_input("spaCy NER Categories to Redact (comma-separated)", value=tenant_policy.get("block_entities", "PER,ORG,LOC"))
        
        # Risk thresholds
        risk_threshold = st.selectbox("Max Allowed EU AI Act Risk Level", ["HIGH", "LOW/MINIMAL"], index=0 if tenant_policy.get("allowed_risk_level") == "HIGH" else 1)
        
        # Custom keywords block
        custom_kws = st.text_area("Blocked Custom Keywords (comma-separated)", value=tenant_policy.get("custom_keywords", ""))
        
        if st.button("Save Policy Config"):
            policy_update = {
                "block_personnummer": int(p_bp),
                "block_email": int(p_be),
                "block_phone": int(p_bp_ph),
                "block_iban": int(p_bi),
                "block_entities": entities_input,
                "allowed_risk_level": risk_threshold,
                "custom_keywords": custom_kws
            }
            try:
                update_res = requests.post(f"{ADMIN_POLICIES_URL}/{active_tenant_id}", json=policy_update)
                if update_res.status_code == 200:
                    st.success("Tenant Security Policies successfully updated!")
                    st.rerun()
                else:
                    st.error(f"Failed to update policy: {update_res.text}")
            except Exception as e:
                st.error(f"Connection issue: {e}")
    else:
        st.warning("Failed to fetch tenant configuration settings.")

with tab3:
    st.subheader("Real-Time Compliance & Financial Telemetry")
    if audit_data:
        df = pd.DataFrame(audit_data)
        df['timestamp'] = pd.to_datetime(df['timestamp'])
        
        col1, col2 = st.columns(2)
        with col1:
            fig1 = px.histogram(df, x="timestamp", color="blocked", title="Security Violations vs Cleared Prompts")
            fig1.update_layout(paper_bgcolor=bg_color, plot_bgcolor=card_bg, font_color=text_color)
            st.plotly_chart(fig1, use_container_width=True)
            
        with col2:
            fig2 = px.pie(df, names="risk_level", title="EU AI Act Risk Profiles")
            fig2.update_layout(paper_bgcolor=bg_color, font_color=text_color)
            st.plotly_chart(fig2, use_container_width=True)
            
        col3, col4 = st.columns(2)
        with col3:
            fig3 = px.line(df.sort_values("timestamp"), x="timestamp", y="latency_ms", title="API Gateway Response Latency (ms)")
            fig3.update_layout(paper_bgcolor=bg_color, plot_bgcolor=card_bg, font_color=text_color)
            st.plotly_chart(fig3, use_container_width=True)
        with col4:
            fig4 = px.bar(df.sort_values("timestamp"), x="timestamp", y="cost_usd", color="target_model", title="AI Operational Cost Allocation ($)")
            fig4.update_layout(paper_bgcolor=bg_color, plot_bgcolor=card_bg, font_color=text_color)
            st.plotly_chart(fig4, use_container_width=True)
    else:
        st.info("No compliance telemetry is logged for this tenant yet.")

with tab4:
    st.subheader("Cryptographic Signed Audits Ledger")
    if audit_data:
        df = pd.DataFrame(audit_data)
        st.dataframe(df, use_container_width=True)
    else:
        st.info("Log is completely clean.")

with tab5:
    st.subheader("Platform Administration & Billing Portal")
    
    st.markdown("### Initialize New Enterprise Tenant Profile")
    with st.form("new_tenant_form"):
        new_id = st.text_input("Tenant Unique ID (slug)", placeholder="e.g. volvo_tech")
        new_name = st.text_input("Company Name", placeholder="e.g. Volvo Group Sweden")
        new_key = st.text_input("Custom API Authentication Key", placeholder="e.g. volvo_secure_key_999")
        new_tier = st.selectbox("Subscription / Billing Tier", ["Free", "Pro", "Enterprise"])
        new_rate = st.number_input("Rate Limit (requests per minute)", min_value=1, max_value=10000, value=60)
        new_webhook = st.text_input("Alerting Webhook URL (Slack/Teams)", placeholder="e.g. https://hooks.slack.com/services/...")
        
        submitted = st.form_submit_button("Create Enterprise Account")
        if submitted:
            if new_id and new_name and new_key:
                new_payload = {
                    "id": new_id,
                    "name": new_name,
                    "api_key": new_key,
                    "tier": new_tier,
                    "rate_limit": int(new_rate),
                    "webhook_url": new_webhook
                }
                try:
                    create_res = requests.post(ADMIN_TENANTS_URL, json=new_payload)
                    if create_res.status_code == 200:
                        st.success(f"Tenant profile '{new_name}' successfully provisioned on Sovereign-Shield!")
                        st.rerun()
                    else:
                        st.error(f"Failed to initialize: {create_res.text}")
                except Exception as e:
                    st.error(f"Connection issue: {e}")
            else:
                st.warning("All required configuration parameters must be filled out.")
                
    st.markdown("### Active Tenant Subscriptions & Policies")
    try:
        admin_list = requests.get(ADMIN_TENANTS_URL)
        if admin_list.status_code == 200:
            df_admin = pd.DataFrame(admin_list.json())
            st.dataframe(df_admin, use_container_width=True)
    except Exception as e:
        st.error(f"Unable to load active subscriptions: {e}")
