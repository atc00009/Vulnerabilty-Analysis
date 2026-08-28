import os
import re
import time
import requests
import streamlit as st
from google import genai
from google.genai.errors import APIError


# ============================================================
# PAGE CONFIG
# ============================================================

st.set_page_config(
    page_title="AI Vulnerability Analysis",
    page_icon="🛡️",
    layout="wide",
    initial_sidebar_state="expanded"
)


# ============================================================
# CUSTOM CSS
# ============================================================

st.markdown(
    """
    <style>

    /* GLOBAL */
    .stApp {
        background: #f4f7fb;
    }

    .block-container {
        max-width: 1200px;
        padding-top: 2rem;
        padding-bottom: 4rem;
    }

    /* HERO */
    .hero {
        background: linear-gradient(
            135deg,
            #0f172a,
            #1e3a8a
        );
        padding: 2.5rem;
        border-radius: 24px;
        color: #ffffff !important;
        margin-bottom: 2rem;
        box-shadow: 0 15px 40px rgba(15, 23, 42, 0.20);
    }

    .hero h1 {
        color: #ffffff !important;
        font-size: 2.7rem;
        margin-bottom: 0.6rem;
    }

    .hero p {
        color: #e2e8f0 !important;
        font-size: 1.05rem;
        line-height: 1.7;
    }

    /* CARDS */
    .card {
        background: #ffffff !important;
        color: #111827 !important;
        padding: 1.5rem;
        border-radius: 18px;
        border: 1px solid #dbe3ef;
        box-shadow: 0 6px 20px rgba(15, 23, 42, 0.07);
        margin-bottom: 1rem;
    }

    .card h2, .card h3, .card h4, .card p, .card strong, .card li {
        color: #111827 !important;
    }

    /* METRIC CARDS */
    .metric-card {
        background: #ffffff !important;
        color: #111827 !important;
        padding: 1.4rem;
        border-radius: 18px;
        border: 1px solid #dbe3ef;
        text-align: center;
        min-height: 125px;
        box-shadow: 0 6px 20px rgba(15, 23, 42, 0.07);
    }

    .metric-title {
        color: #64748b !important;
        font-size: 0.85rem;
        margin-bottom: 0.5rem;
    }

    .metric-value {
        color: #111827 !important;
        font-size: 1.55rem;
        font-weight: 700;
    }

    /* SECTION TITLES */
    .section-title {
        color: #0f172a !important;
        font-size: 1.75rem;
        font-weight: 700;
        margin-top: 2rem;
        margin-bottom: 0.8rem;
    }

    /* RESEARCH BOX */
    .research-box {
        background: #eef2ff !important;
        color: #1e293b !important;
        border-left: 5px solid #4f46e5;
        padding: 1.3rem;
        border-radius: 12px;
        margin: 1rem 0;
    }

    .research-box strong, .research-box p {
        color: #1e293b !important;
    }

    /* SOURCE BADGES */
    .source {
        display: inline-block;
        padding: 0.35rem 0.75rem;
        border-radius: 999px;
        background: #e0e7ff !important;
        color: #3730a3 !important;
        font-size: 0.8rem;
        font-weight: 600;
        margin-right: 0.4rem;
    }

    /* INPUT BOXES */
    .stTextInput input, .stNumberInput input, .stTextArea textarea {
        color: #111827 !important;
        background-color: #ffffff !important;
        border: 1px solid #cbd5e1 !important;
    }

    .stTextInput input::placeholder, .stTextArea textarea::placeholder {
        color: #64748b !important;
        opacity: 1 !important;
    }

    .stSelectbox label, .stTextInput label, .stNumberInput label, .stTextArea label {
        color: #111827 !important;
        font-weight: 600 !important;
    }

    /* GENERAL TEXT */
    .stMarkdown, .stMarkdown p, .stMarkdown li {
        color: #111827;
    }

    .stAlert p {
        color: inherit !important;
    }

    /* FOOTER */
    .footer {
        text-align: center;
        color: #64748b !important;
        padding: 2rem;
        font-size: 0.85rem;
    }

    </style>
    """,
    unsafe_allow_html=True
)


# ============================================================
# HERO
# ============================================================

st.markdown(
    """
    <div class="hero">
        <h1>🛡️ AI-Powered Vulnerability Analysis</h1>
        <p>
        Investigate a CVE using trusted vulnerability databases,
        record your own findings, and compare your analysis with
        an AI-assisted security assessment.
        </p>
    </div>
    """,
    unsafe_allow_html=True
)


# ============================================================
# SIDEBAR
# ============================================================

with st.sidebar:
    st.markdown("## 🛡️ Investigation")
    st.markdown(
        """
        ### Recommended workflow

        **1️⃣ Identify the CVE**

        **2️⃣ Research NVD**

        **3️⃣ Cross-check CVE Details**

        **4️⃣ Complete Student Investigation**

        **5️⃣ Submit your findings**

        **6️⃣ Compare with Gemini**
        """
    )
    st.divider()
    st.markdown("### 📚 Research Sources")
    st.markdown(
        """
        🏛️ **NVD**

        📚 **CVE Details**

        📄 **Vendor Advisory**

        🤖 **Gemini AI**
        """
    )
    st.divider()
    st.caption("Educational vulnerability-analysis tool")


# ============================================================
# HELPER FUNCTIONS & API
# ============================================================

def clean_cve(cve):
    cve = cve.strip().upper()
    pattern = r"^CVE-\d{4}-\d{4,}$"
    if re.match(pattern, cve):
        return cve
    return None


def get_nvd_data(cve_id):
    url = "https://services.nvd.nist.gov/rest/json/cves/2.0"
    params = {"cveId": cve_id}

    try:
        response = requests.get(url, params=params, timeout=20)
        if response.status_code != 200:
            return None, f"NVD returned HTTP {response.status_code}"

        data = response.json()
        vulnerabilities = data.get("vulnerabilities", [])

        if not vulnerabilities:
            return None, "This CVE could not be found in the NVD database."

        return vulnerabilities[0]["cve"], None

    except requests.RequestException as error:
        return None, f"Unable to contact NVD: {error}"


def get_description(cve_data):
    descriptions = cve_data.get("descriptions", [])
    for item in descriptions:
        if item.get("lang") == "en":
            return item.get("value", "")
    return "No English description available."


def get_cvss(cve_data):
    metrics = cve_data.get("metrics", {})

    if metrics.get("cvssMetricV31"):
        metric = metrics["cvssMetricV31"][0]
        cvss = metric.get("cvssData", {})
        return {
            "version": "CVSS 3.1",
            "score": cvss.get("baseScore"),
            "severity": cvss.get("baseSeverity"),
            "vector": cvss.get("vectorString"),
            "attack_vector": cvss.get("attackVector"),
            "attack_complexity": cvss.get("attackComplexity"),
            "privileges_required": cvss.get("privilegesRequired"),
            "user_interaction": cvss.get("userInteraction"),
            "scope": cvss.get("scope"),
            "confidentiality": cvss.get("confidentialityImpact"),
            "integrity": cvss.get("integrityImpact"),
            "availability": cvss.get("availabilityImpact")
        }

    if metrics.get("cvssMetricV30"):
        metric = metrics["cvssMetricV30"][0]
        cvss = metric.get("cvssData", {})
        return {
            "version": "CVSS 3.0",
            "score": cvss.get("baseScore"),
            "severity": cvss.get("baseSeverity"),
            "vector": cvss.get("vectorString"),
            "attack_vector": cvss.get("attackVector"),
            "attack_complexity": cvss.get("attackComplexity"),
            "privileges_required": cvss.get("privilegesRequired"),
            "user_interaction": cvss.get("userInteraction"),
            "scope": cvss.get("scope"),
            "confidentiality": cvss.get("confidentialityImpact"),
            "integrity": cvss.get("integrityImpact"),
            "availability": cvss.get("availabilityImpact")
        }

    return None


def get_cwe(cve_data):
    weaknesses = cve_data.get("weaknesses", [])
    for weakness in weaknesses:
        descriptions = weakness.get("description", [])
        for item in descriptions:
            value = item.get("value")
            if value:
                return value
    return "Not available"


def get_references(cve_data):
    references = []
    for reference in cve_data.get("references", []):
        url = reference.get("url")
        if url:
            references.append(url)
    return references


def nvd_url(cve_id):
    return "https://nvd.nist.gov/vuln/detail/" + cve_id


def cve_details_url(cve_id):
    return "https://www.cvedetails.com/cve/" + cve_id + "/"


def get_gemini_key():
    try:
        if "GEMINI_API_KEY" in st.secrets:
            return st.secrets["GEMINI_API_KEY"]
    except Exception:
        pass
    return os.getenv("GEMINI_API_KEY")


# ============================================================
# GEMINI ANALYSIS (WITH RETRIES & FALLBACKS)
# ============================================================

def run_gemini_analysis(cve_id, description, cvss, cwe, student):
    api_key = get_gemini_key()

    if not api_key:
        return None, "CONFIG_ERROR: GEMINI_API_KEY is not configured in Streamlit Secrets."

    try:
        client = genai.Client(api_key=api_key)

        prompt = f"""
You are a cybersecurity vulnerability-analysis tutor.
Your purpose is to help a university student understand vulnerability analysis.
Do NOT provide instructions for exploiting the vulnerability.

CVE ID: {cve_id}
DESCRIPTION: {description}
CWE: {cwe}
CVSS INFORMATION: {cvss}

STUDENT INVESTIGATION:
CVSS SCORE: {student["cvss_score"]}
CVSS SEVERITY: {student["severity"]}
ATTACK VECTOR: {student["attack_vector"]}
PRIVILEGES REQUIRED: {student["privileges_required"]}
USER INTERACTION: {student["user_interaction"]}
POTENTIAL IMPACT: {student["impact"]}
FINAL RISK RATING: {student["risk_rating"]}
JUSTIFICATION: {student["justification"]}
RECOMMENDED MITIGATION: {student["mitigation"]}

REQUIRED ANALYSIS:
## 1. Vulnerability Summary
Explain the vulnerability in simple language.

## 2. CVSS Analysis
Explain the CVSS score and the metrics. Compare these with the student's findings.

## 3. Potential Impact
Explain what could happen if the vulnerability were successfully exploited.

## 4. Student Investigation Review
Explain what the student identified correctly, what needs improvement, and any missed items.

## 5. Risk Assessment
Evaluate whether the student's final risk rating is reasonable. Explain CVSS severity vs overall risk.

## 6. Recommended Mitigation
Provide defensive remediation guidance.

## 7. Learning Feedback
Give three practical recommendations to improve vulnerability-analysis skills.
"""
        models_to_try = ["gemini-2.5-flash"]
        max_retries = 3

        for model_name in models_to_try:
            for attempt in range(max_retries):
                try:
                    response = client.models.generate_content(
                        model=model_name,
                        contents=prompt
                    )
                    return response.text, None
                except APIError as e:
                    # Retry on temporary high demand (503) or rate limits (429)
                    if getattr(e, "code", None) in [503, 429] and attempt < max_retries - 1:
                        time.sleep(2 ** attempt)  # Wait 1s, 2s, 4s...
                        continue
                    break

        return None, "SERVER_BUSY: Google Gemini is experiencing temporary high demand. Please try again in a few seconds."

    except Exception as error:
        return None, f"Gemini analysis failed: {error}"


# ============================================================
# 1. IDENTIFY CVE
# ============================================================

st.markdown('<div class="section-title">1️⃣ Identify the Vulnerability</div>', unsafe_allow_html=True)

st.markdown(
    """
    <div class="card">
    <h3>🔎 Start Your Investigation</h3>
    Enter a CVE identifier below.<br><br>
    <strong>Example:</strong> CVE-2021-44228
    </div>
    """,
    unsafe_allow_html=True
)

cve_input = st.text_input("CVE ID", placeholder="CVE-2021-44228")
search_button = st.button("🔍 Investigate CVE", type="primary", use_container_width=True)


# ============================================================
# SEARCH NVD
# ============================================================

if search_button:
    cve_id = clean_cve(cve_input)

    if not cve_id:
        st.error("Please enter a valid CVE identifier, for example CVE-2021-44228.")
        st.stop()

    with st.spinner("🔎 Searching the NVD database..."):
        cve_data, error = get_nvd_data(cve_id)

    if error:
        st.error(error)
        st.stop()

    st.session_state["cve_data"] = cve_data
    st.session_state["cve_id"] = cve_id
    st.session_state.pop("student_investigation", None)
    st.session_state.pop("ai_result", None)


# ============================================================
# DISPLAY RESULTS
# ============================================================

if "cve_data" in st.session_state:
    cve_data = st.session_state["cve_data"]
    cve_id = st.session_state["cve_id"]

    description = get_description(cve_data)
    cvss = get_cvss(cve_data)
    cwe = get_cwe(cve_data)
    references = get_references(cve_data)

    st.markdown('<div class="section-title">2️⃣ Vulnerability Overview</div>', unsafe_allow_html=True)

    st.markdown(
        f"""
        <div class="card">
        <h2>{cve_id}</h2>
        <p>{description}</p>
        <span class="source">NVD</span>
        <span class="source">CVE</span>
        </div>
        """,
        unsafe_allow_html=True
    )

    if cvss:
        st.markdown("### 📊 CVSS Overview")
        col1, col2, col3, col4 = st.columns(4)

        with col1:
            st.markdown(f'<div class="metric-card"><div class="metric-title">CVSS Score</div><div class="metric-value">{cvss["score"]}</div></div>', unsafe_allow_html=True)
        with col2:
            st.markdown(f'<div class="metric-card"><div class="metric-title">Severity</div><div class="metric-value">{cvss["severity"]}</div></div>', unsafe_allow_html=True)
        with col3:
            st.markdown(f'<div class="metric-card"><div class="metric-title">Attack Vector</div><div class="metric-value">{cvss["attack_vector"]}</div></div>', unsafe_allow_html=True)
        with col4:
            st.markdown(f'<div class="metric-card"><div class="metric-title">CWE</div><div class="metric-value">{cwe}</div></div>', unsafe_allow_html=True)

        st.markdown("### 🔐 CVSS Security Metrics")
        col1, col2, col3 = st.columns(3)

        with col1:
            st.markdown(f'<div class="card"><h4>Attack Conditions</h4><strong>Attack Vector</strong><br>{cvss["attack_vector"]}<br><br><strong>Attack Complexity</strong><br>{cvss["attack_complexity"]}</div>', unsafe_allow_html=True)
        with col2:
            st.markdown(f'<div class="card"><h4>Access Requirements</h4><strong>Privileges Required</strong><br>{cvss["privileges_required"]}<br><br><strong>User Interaction</strong><br>{cvss["user_interaction"]}<br><br><strong>Scope</strong><br>{cvss["scope"]}</div>', unsafe_allow_html=True)
        with col3:
            st.markdown(f'<div class="card"><h4>Security Impact</h4><strong>Confidentiality</strong><br>{cvss["confidentiality"]}<br><br><strong>Integrity</strong><br>{cvss["integrity"]}<br><br><strong>Availability</strong><br>{cvss["availability"]}</div>', unsafe_allow_html=True)

    st.markdown("### 🔎 Research the Vulnerability")
    st.markdown('<div class="research-box"><strong>Important:</strong> Do not simply copy the automated dashboard results. Use the sources below to investigate independently.</div>', unsafe_allow_html=True)

    source1, source2 = st.columns(2)
    with source1:
        st.markdown('<div class="card"><h3>🏛️ NVD</h3><p>Use NVD to investigate CVSS scores, attack vectors, and CWE classifications.</p></div>', unsafe_allow_html=True)
        st.link_button("Open NVD Record ↗", nvd_url(cve_id), use_container_width=True)
    with source2:
        st.markdown('<div class="card"><h3>📚 CVE Details</h3><p>Use CVE Details to cross-check product data and historical information.</p></div>', unsafe_allow_html=True)
        st.link_button("Open CVE Details ↗", cve_details_url(cve_id), use_container_width=True)

    # ========================================================
    # 3. STUDENT INVESTIGATION (WITH FORM PREVENTING RE-RENDERS)
    # ========================================================

    st.markdown('<div class="section-title">3️⃣ Student Investigation</div>', unsafe_allow_html=True)

    with st.form("student_investigation_form"):
        st.markdown("### 📝 Record Your Findings")

        student_cvss = st.number_input("Your CVSS Score", min_value=0.0, max_value=10.0, value=0.0, step=0.1, format="%.1f")
        student_severity = st.selectbox("Your CVSS Severity", ["Select...", "None", "Low", "Medium", "High", "Critical"])
        student_attack_vector = st.selectbox("Your Attack Vector", ["Select...", "Network", "Adjacent Network", "Local", "Physical"])
        student_privileges = st.selectbox("Privileges Required", ["Select...", "None", "Low", "High"])
        student_user_interaction = st.selectbox("User Interaction", ["Select...", "None", "Required"])
        student_impact = st.text_area("What could be the impact of this vulnerability?", placeholder="Explain potential impact...", height=140)
        student_risk = st.selectbox("Your Final Vulnerability Risk Rating", ["Select...", "Low", "Medium", "High", "Critical"])
        student_justification = st.text_area("Justify your final rating", placeholder="Use evidence from your research...", height=160)
        student_mitigation = st.text_area("Recommended Mitigation", placeholder="Explain remediation guidance...", height=140)

        submit_investigation = st.form_submit_button("✅ Submit My Investigation", type="primary", use_container_width=True)

        if submit_investigation:
            valid = all([
                student_severity != "Select...",
                student_attack_vector != "Select...",
                student_privileges != "Select...",
                student_user_interaction != "Select...",
                student_impact.strip() != "",
                student_risk != "Select...",
                student_justification.strip() != "",
                student_mitigation.strip() != ""
            ])

            if not valid:
                st.error("Please complete all investigation fields before submitting.")
            else:
                st.session_state["student_investigation"] = {
                    "cvss_score": student_cvss,
                    "severity": student_severity,
                    "attack_vector": student_attack_vector,
                    "privileges_required": student_privileges,
                    "user_interaction": student_user_interaction,
                    "impact": student_impact,
                    "risk_rating": student_risk,
                    "justification": student_justification,
                    "mitigation": student_mitigation
                }
                st.session_state.pop("ai_result", None)
                st.success("✅ Your investigation has been recorded.")
                st.info("You can now compare your findings with the automated dashboard analysis.")

    # ========================================================
    # 4. AUTOMATED DASHBOARD ANALYSIS
    # ========================================================

    if "student_investigation" in st.session_state:
        st.markdown("---")
        st.markdown('<div class="section-title">4️⃣ Automated Dashboard Analysis</div>', unsafe_allow_html=True)

        st.markdown('<div class="card"><h3>🤖 Gemini Vulnerability Analysis</h3><p>Your independent investigation has been completed. Trigger the AI analysis to evaluate your work.</p></div>', unsafe_allow_html=True)

        if st.button("🤖 Analyse My Investigation with Gemini", type="primary", use_container_width=True):
            student = st.session_state["student_investigation"]

            with st.spinner("🤖 Gemini is analysing your investigation..."):
                ai_result, ai_error = run_gemini_analysis(cve_id, description, cvss, cwe, student)

            if ai_error:
                st.error(ai_error)
                if ai_error.startswith("CONFIG_ERROR"):
                    st.info("Check that GEMINI_API_KEY is correctly configured in Streamlit Secrets.")
            else:
                st.session_state["ai_result"] = ai_result
                st.success("✅ Gemini analysis completed.")

    # ========================================================
    # DISPLAY AI RESULT & COMPARISON TABLE
    # ========================================================

    if "ai_result" in st.session_state:
        st.markdown("### 🤖 Automated Analysis")
        st.markdown(f'<div class="card">{st.session_state["ai_result"]}</div>', unsafe_allow_html=True)

        st.markdown('<div class="section-title">5️⃣ Compare Your Findings</div>', unsafe_allow_html=True)
        student = st.session_state["student_investigation"]

        comparison_data = {
            "Investigation Area": ["CVSS Score", "Severity", "Attack Vector", "Privileges Required", "User Interaction", "Final Risk Rating"],
            "Your Finding": [
                str(student["cvss_score"]),
                student["severity"],
                student["attack_vector"],
                student["privileges_required"],
                student["user_interaction"],
                student["risk_rating"]
            ],
            "NVD Reference": [
                str(cvss["score"]) if cvss else "Unavailable",
                cvss["severity"] if cvss else "Unavailable",
                cvss["attack_vector"] if cvss else "Unavailable",
                cvss["privileges_required"] if cvss else "Unavailable",
                cvss["user_interaction"] if cvss else "Unavailable",
                "Student judgement"
            ]
        }

        st.table(comparison_data)

    if references:
        st.markdown("---")
        st.markdown("### 🔗 CVE References")
        for reference in references[:10]:
            st.markdown(f"- [{reference}]({reference})")


# ============================================================
# FOOTER
# ============================================================

st.markdown(
    """
    <div class="footer">
    🛡️ AI-Powered Vulnerability Analysis<br>
    Educational Use • NVD • CVE Details • Gemini
    </div>
    """,
    unsafe_allow_html=True
)
