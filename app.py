import os
import re
import requests
import streamlit as st
from google import genai


# ============================================================
# PAGE CONFIGURATION
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

    /* -------------------------------------------------------
       GLOBAL
    ------------------------------------------------------- */

    .stApp {
        background:
            linear-gradient(
                135deg,
                #f8fafc 0%,
                #eef2ff 50%,
                #f8fafc 100%
            );
    }

    .block-container {
        max-width: 1200px;
        padding-top: 2rem;
        padding-bottom: 4rem;
    }


    /* -------------------------------------------------------
       HERO
    ------------------------------------------------------- */

    .hero {
        background:
            linear-gradient(
                135deg,
                #111827,
                #1e3a8a
            );

        padding: 2.5rem;

        border-radius: 24px;

        color: white;

        margin-bottom: 2rem;

        box-shadow:
            0 15px 40px
            rgba(15, 23, 42, 0.18);
    }

    .hero h1 {
        font-size: 2.7rem;
        margin-bottom: 0.5rem;
    }

    .hero p {
        font-size: 1.05rem;
        line-height: 1.7;
        opacity: 0.92;
    }


    /* -------------------------------------------------------
       CARDS
       ------------------------------------------------------- */

    .card {

        background: white;

        padding: 1.4rem;

        border-radius: 18px;

        border: 1px solid #e5e7eb;

        box-shadow:
            0 6px 20px
            rgba(15, 23, 42, 0.06);

        margin-bottom: 1rem;
    }


    /* -------------------------------------------------------
       METRIC CARDS
       ------------------------------------------------------- */

    .metric-card {

        background: white;

        padding: 1.3rem;

        border-radius: 18px;

        border: 1px solid #e5e7eb;

        text-align: center;

        min-height: 125px;

        box-shadow:
            0 6px 20px
            rgba(15, 23, 42, 0.06);
    }

    .metric-title {

        font-size: 0.85rem;

        color: #64748b;

        margin-bottom: 0.5rem;
    }

    .metric-value {

        font-size: 1.55rem;

        font-weight: 700;

        color: #111827;
    }


    /* -------------------------------------------------------
       SECTION TITLES
       ------------------------------------------------------- */

    .section-title {

        font-size: 1.7rem;

        font-weight: 700;

        color: #111827;

        margin-top: 2rem;

        margin-bottom: 0.8rem;
    }


    /* -------------------------------------------------------
       SOURCE BADGES
       ------------------------------------------------------- */

    .source {

        display: inline-block;

        padding: 0.35rem 0.75rem;

        border-radius: 999px;

        background: #e0e7ff;

        color: #3730a3;

        font-size: 0.8rem;

        font-weight: 600;

        margin-right: 0.4rem;
    }


    /* -------------------------------------------------------
       INFO BOX
       ------------------------------------------------------- */

    .research-box {

        background: #f8fafc;

        border-left: 5px solid #4f46e5;

        padding: 1.2rem;

        border-radius: 12px;

        margin: 1rem 0;
    }


    /* -------------------------------------------------------
       FOOTER
       ------------------------------------------------------- */

    .footer {

        text-align: center;

        color: #64748b;

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
        Investigate a vulnerability using trusted vulnerability databases,
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

        **6️⃣ Compare with Gemini analysis**
        """
    )

    st.divider()

    st.markdown(
        """
        ### 📚 Research Sources

        🏛️ **NVD**

        📚 **CVE Details**

        📄 **CVE / Vendor Advisory**

        🤖 **Gemini AI**
        """
    )

    st.divider()

    st.caption(
        "Educational vulnerability-analysis tool"
    )


# ============================================================
# HELPER FUNCTIONS
# ============================================================

def clean_cve(cve):

    cve = cve.strip().upper()

    pattern = r"^CVE-\d{4}-\d{4,}$"

    if re.match(pattern, cve):
        return cve

    return None


# ------------------------------------------------------------
# NVD API
# ------------------------------------------------------------

def get_nvd_data(cve_id):

    url = (
        "https://services.nvd.nist.gov/rest/json/"
        "cves/2.0"
    )

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

            return None, (
                f"NVD returned HTTP "
                f"{response.status_code}"
            )

        data = response.json()

        vulnerabilities = data.get(
            "vulnerabilities",
            []
        )

        if not vulnerabilities:

            return None, (
                "This CVE could not be found "
                "in the NVD database."
            )

        return vulnerabilities[0]["cve"], None

    except requests.RequestException as error:

        return None, (
            f"Unable to contact NVD: {error}"
        )


# ------------------------------------------------------------
# DESCRIPTION
# ------------------------------------------------------------

def get_description(cve_data):

    descriptions = cve_data.get(
        "descriptions",
        []
    )

    for description in descriptions:

        if description.get("lang") == "en":

            return description.get(
                "value",
                ""
            )

    return "No English description available."


# ------------------------------------------------------------
# CVSS
# ------------------------------------------------------------

def get_cvss(cve_data):

    metrics = cve_data.get(
        "metrics",
        {}
    )

    # CVSS 3.1
    if metrics.get("cvssMetricV31"):

        metric = metrics[
            "cvssMetricV31"
        ][0]

        cvss = metric.get(
            "cvssData",
            {}
        )

        return {

            "version": "CVSS 3.1",

            "score":
                cvss.get("baseScore"),

            "severity":
                cvss.get("baseSeverity"),

            "vector":
                cvss.get("vectorString"),

            "attack_vector":
                cvss.get("attackVector"),

            "attack_complexity":
                cvss.get("attackComplexity"),

            "privileges_required":
                cvss.get("privilegesRequired"),

            "user_interaction":
                cvss.get("userInteraction"),

            "scope":
                cvss.get("scope"),

            "confidentiality":
                cvss.get(
                    "confidentialityImpact"
                ),

            "integrity":
                cvss.get(
                    "integrityImpact"
                ),

            "availability":
                cvss.get(
                    "availabilityImpact"
                )
        }

    # CVSS 3.0 fallback
    if metrics.get("cvssMetricV30"):

        metric = metrics[
            "cvssMetricV30"
        ][0]

        cvss = metric.get(
            "cvssData",
            {}
        )

        return {

            "version": "CVSS 3.0",

            "score":
                cvss.get("baseScore"),

            "severity":
                cvss.get("baseSeverity"),

            "vector":
                cvss.get("vectorString"),

            "attack_vector":
                cvss.get("attackVector"),

            "attack_complexity":
                cvss.get("attackComplexity"),

            "privileges_required":
                cvss.get("privilegesRequired"),

            "user_interaction":
                cvss.get("userInteraction"),

            "scope":
                cvss.get("scope"),

            "confidentiality":
                cvss.get(
                    "confidentialityImpact"
                ),

            "integrity":
                cvss.get(
                    "integrityImpact"
                ),

            "availability":
                cvss.get(
                    "availabilityImpact"
                )
        }

    return None


# ------------------------------------------------------------
# CWE
# ------------------------------------------------------------

def get_cwe(cve_data):

    weaknesses = cve_data.get(
        "weaknesses",
        []
    )

    for weakness in weaknesses:

        descriptions = weakness.get(
            "description",
            []
        )

        for item in descriptions:

            value = item.get(
                "value"
            )

            if value:
                return value

    return "Not available"


# ------------------------------------------------------------
# REFERENCES
# ------------------------------------------------------------

def get_references(cve_data):

    references = []

    for reference in cve_data.get(
        "references",
        []
    ):

        url = reference.get("url")

        if url:
            references.append(url)

    return references


# ------------------------------------------------------------
# NVD URL
# ------------------------------------------------------------

def nvd_url(cve_id):

    return (
        "https://nvd.nist.gov/vuln/detail/"
        + cve_id
    )


# ------------------------------------------------------------
# CVE DETAILS URL
# ------------------------------------------------------------

def cve_details_url(cve_id):

    return (
        "https://www.cvedetails.com/cve/"
        + cve_id
        + "/"
    )


# ------------------------------------------------------------
# GEMINI CLIENT
# ------------------------------------------------------------

def get_gemini_key():

    # First try Streamlit Secrets
    try:

        if "GEMINI_API_KEY" in st.secrets:

            return st.secrets[
                "GEMINI_API_KEY"
            ]

    except Exception:
        pass

    # Then try environment variable
    return os.getenv(
        "GEMINI_API_KEY"
    )


# ------------------------------------------------------------
# GEMINI ANALYSIS
# ------------------------------------------------------------

def run_gemini_analysis(
    cve_id,
    description,
    cvss,
    cwe,
    student
):

    api_key = get_gemini_key()

    if not api_key:

        return None, (
            "GEMINI_API_KEY is not configured."
        )

    try:

        client = genai.Client(
            api_key=api_key
        )

        prompt = f"""
You are a cybersecurity vulnerability-analysis tutor.

Your role is to help a student understand how to analyse
a vulnerability. Do not provide offensive exploitation
instructions.

Analyse the following CVE and compare it with the student's
investigation.

============================================================
CVE INFORMATION
============================================================

CVE ID:
{cve_id}

Description:
{description}

CWE:
{cwe}

CVSS:
{cvss}

============================================================
STUDENT INVESTIGATION
============================================================

Student CVSS Score:
{student["cvss_score"]}

Student Severity:
{student["severity"]}

Student Attack Vector:
{student["attack_vector"]}

Student Privileges Required:
{student["privileges_required"]}

Student User Interaction:
{student["user_interaction"]}

Student Impact:
{student["impact"]}

Student Final Risk Rating:
{student["risk_rating"]}

Student Justification:
{student["justification"]}

Student Recommended Mitigation:
{student["mitigation"]}

============================================================
TASK
============================================================

Provide an educational vulnerability-analysis report.

Use the following structure:

## 1. Vulnerability Summary

Explain the vulnerability in clear language.

## 2. CVSS Analysis

Explain whether the student's CVSS information agrees
with the NVD information.

Explain:
- Attack Vector
- Privileges Required
- User Interaction
- Severity

## 3. Potential Impact

Explain the possible security consequences.

## 4. Student Analysis Review

Identify:
- What the student identified correctly
- What needs improvement
- Any important evidence the student missed

Do not simply say "correct" or "incorrect".
Explain why.

## 5. Risk Assessment

Discuss whether the student's final risk rating
is reasonable based on the available evidence.

Remember that CVSS severity and organisational risk
are not necessarily identical.

## 6. Recommended Mitigation

Give defensive remediation advice based on the
vulnerability information.

## 7. Learning Feedback

Give the student three concise recommendations
for improving their vulnerability-analysis skills.

Keep the explanation suitable for university students.
"""

        interaction = client.interactions.create(

            model="gemini-3.7-flash",

            input=prompt,

            generation_config={
                "thinking_level": "medium"
            }
        )

        return (
            interaction.output_text,
            None
        )

    except Exception as error:

        return None, (
            f"Gemini analysis failed: {error}"
        )


# ============================================================
# 1. CVE SELECTION
# ============================================================

st.markdown(
    '<div class="section-title">'
    '1️⃣ Identify the Vulnerability'
    '</div>',
    unsafe_allow_html=True
)

st.markdown(
    """
    <div class="card">

    Enter a CVE identifier to begin your investigation.

    <br><br>

    <strong>Example:</strong>
    CVE-2021-44228

    </div>
    """,
    unsafe_allow_html=True
)


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

    cve_id = clean_cve(
        cve_input
    )

    if not cve_id:

        st.error(
            "Please enter a valid CVE ID, "
            "for example CVE-2021-44228."
        )

        st.stop()

    with st.spinner(
        "🔎 Retrieving vulnerability information from NVD..."
    ):

        cve_data, error = get_nvd_data(
            cve_id
        )

    if error:

        st.error(error)

        st.stop()

    st.session_state[
        "cve_data"
    ] = cve_data

    st.session_state[
        "cve_id"
    ] = cve_id

    # Clear previous investigation
    st.session_state.pop(
        "student_investigation",
        None
    )

    st.session_state.pop(
        "ai_result",
        None
    )


# ============================================================
# DISPLAY CVE
# ============================================================

if "cve_data" in st.session_state:

    cve_data = st.session_state[
        "cve_data"
    ]

    cve_id = st.session_state[
        "cve_id"
    ]

    description = get_description(
        cve_data
    )

    cvss = get_cvss(
        cve_data
    )

    cwe = get_cwe(
        cve_data
    )

    references = get_references(
        cve_data
    )


    # ========================================================
    # 2. VULNERABILITY OVERVIEW
    # ========================================================

    st.markdown(
        '<div class="section-title">'
        '2️⃣ Vulnerability Overview'
        '</div>',
        unsafe_allow_html=True
    )


    st.markdown(
        f"""
        <div class="card">

        <h2>{cve_id}</h2>

        <p>
        {description}
        </p>

        <span class="source">
        NVD
        </span>

        <span class="source">
        CVE
        </span>

        </div>
        """,
        unsafe_allow_html=True
    )


    # ========================================================
    # CVSS SUMMARY
    # ========================================================

    if cvss:

        st.markdown(
            "### 📊 NVD Vulnerability Metrics"
        )

        col1, col2, col3, col4 = st.columns(4)


        with col1:

            st.markdown(
                f"""
                <div class="metric-card">

                <div class="metric-title">
                CVSS Score
                </div>

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

                <div class="metric-title">
                Severity
                </div>

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

                <div class="metric-title">
                Attack Vector
                </div>

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

                <div class="metric-title">
                CWE
                </div>

                <div class="metric-value">
                {cwe}
                </div>

                </div>
                """,
                unsafe_allow_html=True
            )


        # ====================================================
        # CVSS DETAILS
        # ====================================================

        st.markdown(
            "### 🔐 CVSS Security Metrics"
        )

        col1, col2, col3 = st.columns(3)


        with col1:

            st.markdown(
                f"""
                <div class="card">

                <strong>
                Attack Complexity
                </strong>

                <br>

                {cvss["attack_complexity"]}

                <br><br>

                <strong>
                Privileges Required
                </strong>

                <br>

                {cvss["privileges_required"]}

                </div>
                """,
                unsafe_allow_html=True
            )


        with col2:

            st.markdown(
                f"""
                <div class="card">

                <strong>
                User Interaction
                </strong>

                <br>

                {cvss["user_interaction"]}

                <br><br>

                <strong>
                Scope
                </strong>

                <br>

                {cvss["scope"]}

                </div>
                """,
                unsafe_allow_html=True
            )


        with col3:

            st.markdown(
                f"""
                <div class="card">

                <strong>
                Confidentiality
                </strong>

                <br>

                {cvss["confidentiality"]}

                <br><br>

                <strong>
                Integrity
                </strong>

                <br>

                {cvss["integrity"]}

                <br><br>

                <strong>
                Availability
                </strong>

                <br>

                {cvss["availability"]}

                </div>
                """,
                unsafe_allow_html=True
            )


    # ========================================================
    # RESEARCH SOURCES
    # ========================================================

    st.markdown(
        "### 🔎 Research Sources"
    )


    st.markdown(
        """
        <div class="research-box">

        <strong>
        Do not rely on one source only.
        </strong>

        <br><br>

        Research the CVE using NVD and CVE Details before
        completing the Student Investigation.

        Then use the CVE description or vendor advisory
        to understand the vulnerability and mitigation.

        </div>
        """,
        unsafe_allow_html=True
    )


    source1, source2 = st.columns(2)


    with source1:

        st.markdown(
            """
            <div class="card">

            <h3>🏛️ NVD</h3>

            Use NVD to investigate:

            <br><br>

            • CVSS score<br>
            • CVSS severity<br>
            • Attack Vector<br>
            • Privileges Required<br>
            • User Interaction<br>
            • CWE<br>
            • Affected products<br>
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


    with source2:

        st.markdown(
            """
            <div class="card">

            <h3>📚 CVE Details</h3>

            Use CVE Details as a second vulnerability
            database to cross-check your findings.

            <br><br>

            Look for:

            <br>

            • Vendor information<br>
            • Product information<br>
            • CVSS information<br>
            • CWE classification<br>
            • Vulnerability history<br>
            • References

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
    # 3. STUDENT INVESTIGATION
    # ========================================================

    st.markdown(
        '<div class="section-title">'
        '3️⃣ Student Investigation'
        '</div>',
        unsafe_allow_html=True
    )


    st.markdown(
        """
        <div class="card">

        <h3>
        🔍 Complete your own investigation first
        </h3>

        Complete this section using your
        <strong>own research BEFORE checking the
        automated dashboard results.</strong>

        <br><br>

        Use the following sources:

        <br><br>

        <strong>🏛️ NVD</strong>
        – CVSS score, severity and CVSS metrics.

        <br>

        <strong>📚 CVE Details</strong>
        – Cross-check vulnerability, product,
        classification and historical information.

        <br>

        <strong>📄 CVE / Vendor Advisory</strong>
        – Understand the vulnerability,
        potential impact and recommended mitigation.

        <br><br>

        Record your findings below.

        After completing your investigation,
        compare your answers with the automated
        dashboard analysis.

        </div>
        """,
        unsafe_allow_html=True
    )


    # ========================================================
    # STUDENT FORM
    # ========================================================

    st.markdown(
        "### 📝 Record Your Findings"
    )


    student_cvss = st.number_input(
        "Your CVSS Score",
        min_value=0.0,
        max_value=10.0,
        value=0.0,
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
            "Explain what an attacker could potentially "
            "achieve if the vulnerability were successfully "
            "exploited."
        ),

        height=140
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
            "Use evidence from your research. Consider "
            "the CVSS score, attack vector, privileges "
            "required, user interaction, potential impact "
            "and affected software."
        ),

        height=160
    )


    student_mitigation = st.text_area(
        "Recommended Mitigation",

        placeholder=(
            "Based on the vendor advisory, NVD or other "
            "trusted information, explain what should "
            "be done to reduce or remove the risk."
        ),

        height=140
    )


    # ========================================================
    # SUBMIT STUDENT INVESTIGATION
    # ========================================================

    if st.button(
        "✅ Submit My Investigation",
        type="primary",
        use_container_width=True
    ):

        valid = all(
            [
                student_severity != "Select...",

                student_attack_vector != "Select...",

                student_privileges != "Select...",

                student_user_interaction != "Select...",

                student_impact.strip() != "",

                student_risk != "Select...",

                student_justification.strip() != "",

                student_mitigation.strip() != ""
            ]
        )


        if not valid:

            st.error(
                "Please complete all investigation "
                "fields before submitting."
            )


        else:

            st.session_state[
                "student_investigation"
            ] = {

                "cvss_score":
                    student_cvss,

                "severity":
                    student_severity,

                "attack_vector":
                    student_attack_vector,

                "privileges_required":
                    student_privileges,

                "user_interaction":
                    student_user_interaction,

                "impact":
                    student_impact,

                "risk_rating":
                    student_risk,

                "justification":
                    student_justification,

                "mitigation":
                    student_mitigation
            }


            st.session_state.pop(
                "ai_result",
                None
            )


            st.success(
                "✅ Your investigation has been recorded."
            )


            st.info(
                "You can now compare your investigation "
                "with the automated dashboard analysis."
            )


    # ========================================================
    # 4. AUTOMATED DASHBOARD ANALYSIS
    # ========================================================

    if (
        "student_investigation"
        in st.session_state
    ):

        st.markdown("---")


        st.markdown(
            '<div class="section-title">'
            '4️⃣ Automated Dashboard Analysis'
            '</div>',
            unsafe_allow_html=True
        )


        st.markdown(
            """
            <div class="card">

            <h3>
            🤖 Gemini Vulnerability Analysis
            </h3>

            Your investigation has been completed.

            The automated analysis will now review the
            vulnerability information and compare it
            with your investigation.

            </div>
            """,
            unsafe_allow_html=True
        )


        if st.button(
            "🤖 Analyse My Investigation with Gemini",
            type="primary",
            use_container_width=True
        ):

            student = st.session_state[
                "student_investigation"
            ]


            with st.spinner(
                "🤖 Gemini is analysing your investigation..."
            ):

                ai_result, ai_error = (
                    run_gemini_analysis(
                        cve_id,
                        description,
                        cvss,
                        cwe,
                        student
                    )
                )


            if ai_error:

                st.error(
                    ai_error
                )

                st.info(
                    "Check that GEMINI_API_KEY is correctly "
                    "configured in Streamlit Secrets."
                )


            else:

                st.session_state[
                    "ai_result"
                ] = ai_result

                st.success(
                    "✅ Gemini analysis completed."
                )


    # ========================================================
    # DISPLAY GEMINI RESULT
    # ========================================================

    if "ai_result" in st.session_state:

        st.markdown(
            "### 🤖 Automated Analysis"
        )


        st.markdown(
            """
            <div class="card">
            """,
            unsafe_allow_html=True
        )


        st.markdown(
            st.session_state[
                "ai_result"
            ]
        )


        st.markdown(
            "</div>",
            unsafe_allow_html=True
        )


        # ====================================================
        # 5. COMPARISON
        # ====================================================

        st.markdown(
            '<div class="section-title">'
            '5️⃣ Compare Your Findings'
            '</div>',
            unsafe_allow_html=True
        )


        student = st.session_state[
            "student_investigation"
        ]


        st.markdown(
            """
            <div class="research-box">

            Compare your original investigation with
            the evidence presented by the automated
            analysis.

            Ask yourself:

            <br><br>

            • Did I identify the correct CVSS information?

            <br>

            • Did I understand the attack vector?

            <br>

            • Did I correctly interpret privileges and
            user interaction?

            <br>

            • Did I understand the potential impact?

            <br>

            • Is my final risk rating justified?

            <br>

            • Is my mitigation appropriate?

            </div>
            """,
            unsafe_allow_html=True
        )


        comparison_data = {

            "Investigation Area": [

                "CVSS Score",

                "Severity",

                "Attack Vector",

                "Privileges Required",

                "User Interaction",

                "Final Risk Rating"
            ],


            "Your Finding": [

                str(
                    student[
                        "cvss_score"
                    ]
                ),

                student[
                    "severity"
                ],

                student[
                    "attack_vector"
                ],

                student[
                    "privileges_required"
                ],

                student[
                    "user_interaction"
                ],

                student[
                    "risk_rating"
                ]
            ],


            "NVD Reference": [

                str(
                    cvss["score"]
                ) if cvss else "Unavailable",

                cvss[
                    "severity"
                ] if cvss else "Unavailable",

                cvss[
                    "attack_vector"
                ] if cvss else "Unavailable",

                cvss[
                    "privileges_required"
                ] if cvss else "Unavailable",

                cvss[
                    "user_interaction"
                ] if cvss else "Unavailable",

                "Student judgement"
            ]
        }


        st.table(
            comparison_data
        )


    # ========================================================
    # REFERENCES
    # ========================================================

    st.markdown("---")


    st.markdown(
        "### 🔗 CVE References"
    )


    if references:

        for reference in references[:10]:

            st.markdown(
                f"- [{reference}]({reference})"
            )


# ============================================================
# FOOTER
# ============================================================

st.markdown(
    """
    <div class="footer">

    🛡️ AI-Powered Vulnerability Analysis

    <br>

    Educational Use • NVD • CVE Details • Gemini

    </div>
    """,
    unsafe_allow_html=True
)
