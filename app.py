import os
import re
import requests
import streamlit as st
from google import genai

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

st.markdown("""
<style>

    /* Main background */
    .stApp {
        background: linear-gradient(
            135deg,
            #f8fafc 0%,
            #eef2ff 50%,
            #f8fafc 100%
        );
    }

    /* Main content */
    .block-container {
        max-width: 1200px;
        padding-top: 2rem;
        padding-bottom: 4rem;
    }

    /* Hero */
    .hero {
        padding: 2.2rem;
        border-radius: 22px;
        background: linear-gradient(
            135deg,
            #111827,
            #1e3a8a
        );
        color: white;
        margin-bottom: 2rem;
        box-shadow: 0 12px 35px rgba(15, 23, 42, 0.18);
    }

    .hero h1 {
        font-size: 2.6rem;
        margin-bottom: 0.5rem;
    }

    .hero p {
        font-size: 1.05rem;
        opacity: 0.9;
    }

    /* Cards */
    .card {
        background: white;
        padding: 1.3rem;
        border-radius: 16px;
        border: 1px solid #e5e7eb;
        box-shadow: 0 5px 18px rgba(15, 23, 42, 0.06);
        margin-bottom: 1rem;
    }

    .metric-card {
        background: white;
        padding: 1.2rem;
        border-radius: 16px;
        border: 1px solid #e5e7eb;
        text-align: center;
        min-height: 125px;
        box-shadow: 0 5px 18px rgba(15, 23, 42, 0.06);
    }

    .metric-title {
        font-size: 0.85rem;
        color: #64748b;
        margin-bottom: 0.4rem;
    }

    .metric-value {
        font-size: 1.55rem;
        font-weight: 700;
        color: #111827;
    }

    /* Section headings */
    .section-title {
        font-size: 1.65rem;
        font-weight: 700;
        color: #111827;
        margin-top: 2rem;
        margin-bottom: 0.7rem;
    }

    /* Source badges */
    .source {
        display: inline-block;
        padding: 0.35rem 0.7rem;
        border-radius: 999px;
        background: #e0e7ff;
        color: #3730a3;
        font-size: 0.8rem;
        font-weight: 600;
        margin-right: 0.4rem;
    }

    /* Risk */
    .risk-box {
        padding: 1.4rem;
        border-radius: 16px;
        background: #f8fafc;
        border: 1px solid #e2e8f0;
        margin-top: 1rem;
    }

    /* Small text */
    .small-text {
        color: #64748b;
        font-size: 0.9rem;
    }

</style>
""", unsafe_allow_html=True)

# ============================================================
# HEADER
# ============================================================

st.markdown("""
<div class="hero">

    <h1>🛡️ AI-Powered Vulnerability Analysis</h1>

    <p>
        Investigate a CVE using trusted vulnerability databases,
        record your own findings, and compare your analysis with
        automated AI-assisted results.
    </p>

</div>
""", unsafe_allow_html=True)

# ============================================================
# SIDEBAR
# ============================================================

with st.sidebar:

    st.image(
        "https://img.icons8.com/fluency/96/security-shield-green.png",
        width=70
    )

    st.title("Investigation")

    st.markdown("""
    ### Recommended workflow

    **1. Identify the CVE**

    **2. Research NVD**

    **3. Research CVE Details**

    **4. Complete your investigation**

    **5. Submit your findings**

    **6. Compare with AI analysis**
    """)

    st.divider()

    st.caption(
        "Educational vulnerability-analysis tool"
    )

# ============================================================
# HELPER FUNCTIONS
# ============================================================

def clean_cve(cve):
    cve = cve.strip().upper()

    if not re.match(r"^CVE-\d{4}-\d{4,}$", cve):
        return None

    return cve


def get_nvd_data(cve_id):

    url = "https://services.nvd.nist.gov/rest/json/cves/2.0"

    params = {
        "cveId": cve_id
    }

    try:

        response = requests.get(
            url,
            params=params,
            timeout=20
        )

        if response.status_code != 200:
            return None, f"NVD returned HTTP {response.status_code}"

        data = response.json()

        vulnerabilities = data.get("vulnerabilities", [])

        if not vulnerabilities:
            return None, "CVE was not found in NVD."

        return vulnerabilities[0]["cve"], None

    except requests.RequestException as e:

        return None, f"Unable to contact NVD: {e}"


def get_description(cve_data):

    descriptions = cve_data.get("descriptions", [])

    for item in descriptions:

        if item.get("lang") == "en":
            return item.get("value", "")

    return "No English description available."


def get_cvss(cve_data):

    metrics = cve_data.get("metrics", {})

    # Prefer CVSS 3.1
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

    # CVSS 3.0 fallback
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

        for description in weakness.get("description", []):

            value = description.get("value")

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


def cve_details_url(cve_id):

    return (
        "https://www.cvedetails.com/cve/"
        + cve_id
        + "/"
    )


def nvd_url(cve_id):

    return (
        "https://nvd.nist.gov/vuln/detail/"
        + cve_id
    )


# ============================================================
# 1. CVE SELECTION
# ============================================================

st.markdown(
    '<div class="section-title">1️⃣ Identify the Vulnerability</div>',
    unsafe_allow_html=True
)

st.markdown("""
<div class="card">

Enter a CVE identifier to begin your investigation.

<strong>Example:</strong> CVE-2021-44228

</div>
""", unsafe_allow_html=True)

cve_input = st.text_input(
    "CVE ID",
    placeholder="CVE-2021-44228"
)

search_button = st.button(
    "🔍 Investigate CVE",
    type="primary",
    use_container_width=True
)

# ============================================================
# SEARCH
# ============================================================

if search_button:

    cve_id = clean_cve(cve_input)

    if not cve_id:

        st.error(
            "Please enter a valid CVE identifier, for example CVE-2021-44228."
        )

        st.stop()

    with st.spinner("Retrieving vulnerability information from NVD..."):

        cve_data, error = get_nvd_data(cve_id)

    if error:

        st.error(error)
        st.stop()

    st.session_state["cve_data"] = cve_data
    st.session_state["cve_id"] = cve_id

    # Reset investigation
    st.session_state.pop("student_investigation", None)

# ============================================================
# DISPLAY CVE
# ============================================================

if "cve_data" in st.session_state:

    cve_data = st.session_state["cve_data"]
    cve_id = st.session_state["cve_id"]

    description = get_description(cve_data)
    cvss = get_cvss(cve_data)
    cwe = get_cwe(cve_data)
    references = get_references(cve_data)

    # --------------------------------------------------------
    # CVE SUMMARY
    # --------------------------------------------------------

    st.markdown(
        '<div class="section-title">2️⃣ Vulnerability Overview</div>',
        unsafe_allow_html=True
    )

    st.markdown(
        f"""
        <div class="card">

        <h2>{cve_id}</h2>

        <p>{description}</p>

        <span class="source">NVD</span>
        <span class="source">CVE Database</span>

        </div>
        """,
        unsafe_allow_html=True
    )

    # --------------------------------------------------------
    # METRICS
    # --------------------------------------------------------

    if cvss:

        st.markdown("### 📊 NVD Vulnerability Metrics")

        col1, col2, col3, col4 = st.columns(4)

        with col1:
            st.markdown(
                f"""
                <div class="metric-card">
                    <div class="metric-title">CVSS Score</div>
                    <div class="metric-value">
                        {cvss["score"]}
                    </div>
                </div>
                """,
                unsafe_allow_html=True
            )

        with col2:
            st.markdown(
                f"""
                <div class="metric-card">
                    <div class="metric-title">Severity</div>
                    <div class="metric-value">
                        {cvss["severity"]}
                    </div>
                </div>
                """,
                unsafe_allow_html=True
            )

        with col3:
            st.markdown(
                f"""
                <div class="metric-card">
                    <div class="metric-title">Attack Vector</div>
                    <div class="metric-value">
                        {cvss["attack_vector"]}
                    </div>
                </div>
                """,
                unsafe_allow_html=True
            )

        with col4:
            st.markdown(
                f"""
                <div class="metric-card">
                    <div class="metric-title">CWE</div>
                    <div class="metric-value">
                        {cwe}
                    </div>
                </div>
                """,
                unsafe_allow_html=True
            )

        st.markdown("### 🔐 CVSS Security Metrics")

        metric_col1, metric_col2, metric_col3 = st.columns(3)

        with metric_col1:

            st.markdown(
                f"""
                <div class="card">

                <strong>Attack Complexity</strong><br>
                {cvss["attack_complexity"]}

                <br><br>

                <strong>Privileges Required</strong><br>
                {cvss["privileges_required"]}

                </div>
                """,
                unsafe_allow_html=True
            )

        with metric_col2:

            st.markdown(
                f"""
                <div class="card">

                <strong>User Interaction</strong><br>
                {cvss["user_interaction"]}

                <br><br>

                <strong>Scope</strong><br>
                {cvss["scope"]}

                </div>
                """,
                unsafe_allow_html=True
            )

        with metric_col3:

            st.markdown(
                f"""
                <div class="card">

                <strong>Confidentiality</strong><br>
                {cvss["confidentiality"]}

                <br><br>

                <strong>Integrity</strong><br>
                {cvss["integrity"]}

                <br><br>

                <strong>Availability</strong><br>
                {cvss["availability"]}

                </div>
                """,
                unsafe_allow_html=True
            )

    # --------------------------------------------------------
    # RESEARCH SOURCES
    # --------------------------------------------------------

    st.markdown("### 🔎 Research the CVE")

    st.info("""
    **Do not simply copy the NVD score.**

    Your investigation should compare information from more than one
    vulnerability database before you make your final risk judgement.
    """)

    source_col1, source_col2 = st.columns(2)

    with source_col1:

        st.markdown(
            f"""
            <div class="card">

            <h3>🏛️ NVD</h3>

            Use NVD to investigate:

            • CVSS score  
            • CVSS severity  
            • Attack Vector  
            • Privileges Required  
            • User Interaction  
            • CWE  
            • Affected products  
            • References  

            </div>
            """,
            unsafe_allow_html=True
        )

        st.link_button(
            "Open NVD Record ↗",
            nvd_url(cve_id),
            use_container_width=True
        )

    with source_col2:

        st.markdown(
            f"""
            <div class="card">

            <h3>📚 CVE Details</h3>

            Use CVE Details as a second vulnerability database to
            cross-check information about the CVE.

            Look for:

            • Vulnerability history  
            • Vendor/product information  
            • CVSS information  
            • CWE classification  
            • References  
            • Related vulnerabilities  

            </div>
            """,
            unsafe_allow_html=True
        )

        st.link_button(
            "Open CVE Details ↗",
            cve_details_url(cve_id),
            use_container_width=True
        )

    # ========================================================
    # STUDENT INVESTIGATION
    # ========================================================

    st.markdown(
        '<div class="section-title">3️⃣ Student Investigation</div>',
        unsafe_allow_html=True
    )

    st.markdown("""
    <div class="card">

    <h3>🔍 Complete your own investigation first</h3>

    Complete this section using your <strong>own research BEFORE
    checking the automated dashboard results.</strong>

    <br><br>

    Use the following sources:

    <br><br>

    <strong>🏛️ NVD</strong> – CVSS score, severity and CVSS metrics.

    <br>

    <strong>📚 CVE Details</strong> – Cross-check vulnerability,
    product, classification and historical information.

    <br>

    <strong>📄 CVE / Vendor Advisory</strong> – Understand the
    vulnerability, potential impact and recommended mitigation.

    <br><br>

    Record your findings below. After completing your investigation,
    compare your answers with the automated dashboard analysis.

    </div>
    """, unsafe_allow_html=True)

    # --------------------------------------------------------
    # STUDENT INPUT
    # --------------------------------------------------------

    st.markdown("### 📝 Record Your Findings")

    student_cvss = st.number_input(
        "Your CVSS Score",
        min_value=0.0,
        max_value=10.0,
        step=0.1,
        format="%.1f"
    )

    student_severity = st.selectbox(
        "Your CVSS Severity",
        [
            "Select...",
            "None",
            "Low",
            "Medium",
            "High",
            "Critical"
        ]
    )

    student_attack_vector = st.selectbox(
        "Your Attack Vector",
        [
            "Select...",
            "Network",
            "Adjacent Network",
            "Local",
            "Physical"
        ]
    )

    student_privileges = st.selectbox(
        "Privileges Required",
        [
            "Select...",
            "None",
            "Low",
            "High"
        ]
    )

    student_user_interaction = st.selectbox(
        "User Interaction",
        [
            "Select...",
            "None",
            "Required"
        ]
    )

    student_impact = st.text_area(
        "What could be the impact of this vulnerability?",
        placeholder=(
            "Explain what an attacker could potentially achieve "
            "if the vulnerability were successfully exploited."
        ),
        height=130
    )

    student_risk = st.selectbox(
        "Your Final Vulnerability Risk Rating",
        [
            "Select...",
            "Low",
            "Medium",
            "High",
            "Critical"
        ]
    )

    student_justification = st.text_area(
        "Justify your final rating",
        placeholder=(
            "Use evidence from your research. Consider the CVSS score, "
            "attack vector, privileges required, user interaction, "
            "potential impact and affected software."
        ),
        height=150
    )

    student_mitigation = st.text_area(
        "Recommended Mitigation",
        placeholder=(
            "Based on the vendor advisory or trusted vulnerability "
            "information, explain what should be done to reduce or "
            "remove the risk."
        ),
        height=130
    )

    # --------------------------------------------------------
    # SUBMIT
    # --------------------------------------------------------

    if st.button(
        "✅ Submit My Investigation",
        type="primary",
        use_container_width=True
    ):

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

            st.error(
                "Please complete all investigation fields before submitting."
            )

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

            st.success(
                "✅ Your investigation has been recorded."
            )

            st.info(
                "You can now continue to the automated dashboard analysis."
            )

    # ========================================================
    # AUTOMATED ANALYSIS
    # ========================================================

    if "student_investigation" in st.session_state:

        st.markdown("---")

        st.markdown(
            '<div class="section-title">4️⃣ Automated Dashboard Analysis</div>',
            unsafe_allow_html=True
        )

        st.info(
            "Your investigation has been completed. "
            "The automated analysis below can now be used for comparison."
        )

        # ----------------------------------------------------
        # OpenAI
        # ----------------------------------------------------

        api_key = os.getenv("OPENAI_API_KEY")

        if not api_key:

            st.warning(
                "⚠️ OPENAI_API_KEY is not configured. "
                "The NVD/CVE Details investigation still works, "
                "but AI analysis is unavailable."
            )

        else:

            if st.button(
                "🤖 Analyse with AI",
                type="primary",
                use_container_width=True
            ):

                client = OpenAI(api_key=api_key)

                student = st.session_state["student_investigation"]

                prompt = f"""
You are a cybersecurity vulnerability-analysis tutor.

Analyse the following CVE investigation.

CVE:
{cve_id}

NVD description:
{description}

NVD CVSS data:
{cvss}

CWE:
{cwe}

Student investigation:
CVSS Score: {student["cvss_score"]}
Severity: {student["severity"]}
Attack Vector: {student["attack_vector"]}
Privileges Required: {student["privileges_required"]}
User Interaction: {student["user_interaction"]}
Impact: {student["impact"]}
Final Risk Rating: {student["risk_rating"]}
Justification: {student["justification"]}
Mitigation: {student["mitigation"]}

Provide:

1. Correct CVSS interpretation
2. Vulnerability explanation
3. Key security impact
4. Assessment of the student's reasoning
5. Areas where the student's analysis agrees with the evidence
6. Areas that need improvement
7. Recommended mitigation
8. A final risk assessment

Do not simply say the student is correct or incorrect.
Explain the reasoning in educational language.
"""

                with st.spinner(
                    "AI is analysing the vulnerability..."
                ):

                    try:

                        response = client.responses.create(
                            model="gpt-5-mini",
                            input=prompt
                        )

                        ai_result = response.output_text

                        st.session_state["ai_result"] = ai_result

                    except Exception as e:

                        st.error(
                            f"AI analysis failed: {e}"
                        )

        # ----------------------------------------------------
        # DISPLAY AI RESULT
        # ----------------------------------------------------

        if "ai_result" in st.session_state:

            st.markdown(
                '<div class="card">',
                unsafe_allow_html=True
            )

            st.markdown(
                st.session_state["ai_result"]
            )

            st.markdown(
                '</div>',
                unsafe_allow_html=True
            )

            # ------------------------------------------------
            # COMPARISON
            # ------------------------------------------------

            st.markdown("### 🔄 Compare Your Investigation")

            student = st.session_state["student_investigation"]

            comparison = {
                "Investigation Area": [
                    "CVSS Score",
                    "Severity",
                    "Attack Vector",
                    "Privileges Required",
                    "User Interaction",
                    "Final Risk Rating"
                ],

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

            st.table(comparison)

    # ========================================================
    # REFERENCES
    # ========================================================

    st.markdown("---")

    st.markdown("### 🔗 Additional References")

    if references:

        for ref in references[:10]:

            st.markdown(
                f"- [{ref}]({ref})"
            )

    st.caption(
        "Data source: National Vulnerability Database (NVD). "
        "CVE Details is provided as a secondary research database."
    )

# ============================================================
# FOOTER
# ============================================================

st.markdown("---")

st.markdown(
    """
    <div style="text-align:center; color:#64748b; padding:1rem;">
        🛡️ AI-Powered Vulnerability Analysis |
        Educational Use
    </div>
    """,
    unsafe_allow_html=True
)
