import os
import re
import json
import requests
import streamlit as st

# ============================================================
# PAGE CONFIGURATION
# ============================================================

st.set_page_config(
    page_title="AI Vulnerability Analysis Dashboard",
    page_icon="🔐",
    layout="wide"
)

st.title("🔐 AI Vulnerability Analysis Dashboard")
st.caption(
    "Student investigation, evidence comparison and vulnerability reporting"
)

# ============================================================
# CONFIGURATION
# ============================================================

NVD_API = "https://services.nvd.nist.gov/rest/json/cves/2.0"
EPSS_API = "https://api.first.org/data/v1/epss"

CISA_KEV_URL = (
    "https://www.cisa.gov/sites/default/files/feeds/"
    "known_exploited_vulnerabilities.json"
)

MITRE_URL = (
    "https://attack.mitre.org/"
)

NVD_WEB = "https://nvd.nist.gov/vuln/detail/"
CVE_WEB = "https://www.cve.org/CVERecord?id="

# ============================================================
# HELPER FUNCTIONS
# ============================================================

def clean_cve(cve):
    """Validate and normalise CVE input."""
    cve = cve.strip().upper()

    pattern = r"^CVE-\d{4}-\d{4,}$"

    if re.match(pattern, cve):
        return cve

    return None


def get_nvd_data(cve):
    """Retrieve CVE information from NVD API 2.0."""

    api_key = st.secrets.get("NVD_API_KEY", "")

    headers = {}

    if api_key:
        headers["apiKey"] = api_key

    try:
        response = requests.get(
            NVD_API,
            params={"cveId": cve},
            headers=headers,
            timeout=20
        )

        response.raise_for_status()

        data = response.json()

        if not data.get("vulnerabilities"):
            return None, "CVE was not found in NVD."

        return data["vulnerabilities"][0]["cve"], None

    except Exception as e:
        return None, f"NVD request failed: {e}"


def get_epss(cve):
    """Retrieve EPSS information."""

    try:
        response = requests.get(
            EPSS_API,
            params={"cve": cve},
            timeout=20
        )

        response.raise_for_status()

        data = response.json()

        if not data.get("data"):
            return None

        return data["data"][0]

    except Exception:
        return None


@st.cache_data(ttl=3600)
def get_cisa_kev_catalog():
    """Download the current CISA KEV catalogue."""

    try:
        response = requests.get(
            CISA_KEV_URL,
            timeout=30
        )

        response.raise_for_status()

        return response.json()

    except Exception:
        return None


def get_kev_data(cve):
    """Find a CVE in CISA KEV."""

    catalog = get_cisa_kev_catalog()

    if not catalog:
        return None

    for vulnerability in catalog.get("vulnerabilities", []):

        if vulnerability.get("cveID", "").upper() == cve:

            return vulnerability

    return None


def get_cvss(cve_data):
    """Extract the highest available CVSS metric."""

    metrics = cve_data.get("metrics", {})

    # Prefer CVSS v4
    if "cvssMetricV40" in metrics:
        item = metrics["cvssMetricV40"][0]
        cvss = item.get("cvssData", {})

        return {
            "version": "4.0",
            "score": cvss.get("baseScore"),
            "severity": cvss.get("baseSeverity"),
            "vector": cvss.get("vectorString")
        }

    # Then CVSS v3.1
    if "cvssMetricV31" in metrics:
        item = metrics["cvssMetricV31"][0]
        cvss = item.get("cvssData", {})

        return {
            "version": "3.1",
            "score": cvss.get("baseScore"),
            "severity": cvss.get("baseSeverity"),
            "vector": cvss.get("vectorString")
        }

    # Then CVSS v3.0
    if "cvssMetricV30" in metrics:
        item = metrics["cvssMetricV30"][0]
        cvss = item.get("cvssData", {})

        return {
            "version": "3.0",
            "score": cvss.get("baseScore"),
            "severity": cvss.get("baseSeverity"),
            "vector": cvss.get("vectorString")
        }

    # Finally CVSS v2
    if "cvssMetricV2" in metrics:
        item = metrics["cvssMetricV2"][0]
        cvss = item.get("cvssData", {})

        return {
            "version": "2.0",
            "score": cvss.get("baseScore"),
            "severity": item.get("baseSeverity"),
            "vector": cvss.get("vectorString")
        }

    return None


def get_description(cve_data):

    descriptions = cve_data.get("descriptions", [])

    for item in descriptions:

        if item.get("lang") == "en":
            return item.get("value", "")

    return "No English description available."


def get_references(cve_data):

    references = []

    for item in cve_data.get("references", []):

        url = item.get("url")

        if url:
            references.append(url)

    return references


def compare_value(student, reference):
    """Simple comparison helper."""

    if student is None or student == "":
        return "⚠️ Not provided"

    if reference is None or reference == "":
        return "ℹ️ No reference available"

    if str(student).strip().lower() == str(reference).strip().lower():
        return "✅ Correct"

    return "❌ Review"


def severity_from_cvss(score, version):

    if score is None:
        return "Unknown"

    score = float(score)

    # CVSS v3.x ranges
    if version in ["3.0", "3.1"]:

        if score == 0:
            return "None"

        if score <= 3.9:
            return "Low"

        if score <= 6.9:
            return "Medium"

        if score <= 8.9:
            return "High"

        return "Critical"

    # CVSS v4 severity ranges
    if version == "4.0":

        if score == 0:
            return "None"

        if score <= 3.9:
            return "Low"

        if score <= 6.9:
            return "Medium"

        if score <= 8.9:
            return "High"

        return "Critical"

    return "Unknown"


# ============================================================
# SIDEBAR
# ============================================================

with st.sidebar:

    st.header("🔎 Research Sources")

    st.markdown(
        """
        **Students should research these sources themselves before
        submitting their answers.**
        """
    )

    st.link_button(
        "🌐 NVD",
        "https://nvd.nist.gov/"
    )

    st.link_button(
        "📚 CVE.org",
        "https://www.cve.org/"
    )

    st.link_button(
        "🛡️ CISA KEV",
        "https://www.cisa.gov/known-exploited-vulnerabilities-catalog"
    )

    st.link_button(
        "📈 EPSS",
        "https://www.first.org/epss/"
    )

    st.link_button(
        "🎯 MITRE ATT&CK",
        "https://attack.mitre.org/"
    )

    st.markdown("---")

    st.info(
        "Research first. Submit your own assessment. "
        "Use the dashboard to check and improve your analysis."
    )

# ============================================================
# CVE INPUT
# ============================================================

st.header("1️⃣ Vulnerability Investigation")

cve_input = st.text_input(
    "Enter the CVE provided by your tutor",
    placeholder="Example: CVE-2021-44228"
)

search_button = st.button(
    "🔍 Retrieve Reference Information",
    type="primary"
)

# ============================================================
# LOAD CVE
# ============================================================

if search_button:

    cve = clean_cve(cve_input)

    if not cve:

        st.error(
            "Please enter a valid CVE format, e.g. CVE-2021-44228."
        )

    else:

        with st.spinner("Retrieving vulnerability information..."):

            nvd_data, error = get_nvd_data(cve)

            epss_data = get_epss(cve)

            kev_data = get_kev_data(cve)

        if error:

            st.error(error)

        else:

            st.session_state["cve"] = cve
            st.session_state["nvd"] = nvd_data
            st.session_state["epss"] = epss_data
            st.session_state["kev"] = kev_data

            st.success(
                f"{cve} loaded successfully."
            )

# ============================================================
# DISPLAY REFERENCE INFORMATION
# ============================================================

if "nvd" in st.session_state:

    cve = st.session_state["cve"]
    nvd = st.session_state["nvd"]
    epss = st.session_state["epss"]
    kev = st.session_state["kev"]

    st.header("2️⃣ Reference Information")

    description = get_description(nvd)

    cvss = get_cvss(nvd)

    col1, col2, col3, col4 = st.columns(4)

    with col1:

        st.metric(
            "CVE",
            cve
        )

    with col2:

        if cvss:

            st.metric(
                f"CVSS {cvss['version']}",
                cvss["score"]
            )

        else:

            st.metric(
                "CVSS",
                "N/A"
            )

    with col3:

        if cvss:

            st.metric(
                "CVSS Severity",
                cvss["severity"]
            )

        else:

            st.metric(
                "Severity",
                "N/A"
            )

    with col4:

        if kev:

            st.metric(
                "CISA KEV",
                "YES"
            )

        else:

            st.metric(
                "CISA KEV",
                "NO"
            )

    st.subheader("Vulnerability Description")

    st.write(description)

    # --------------------------------------------------------
    # CVSS DETAILS
    # --------------------------------------------------------

    st.subheader("CVSS Information")

    if cvss:

        cvss_col1, cvss_col2, cvss_col3 = st.columns(3)

        with cvss_col1:

            st.write(
                f"**Version:** {cvss['version']}"
            )

        with cvss_col2:

            st.write(
                f"**Score:** {cvss['score']}"
            )

        with cvss_col3:

            st.write(
                f"**Severity:** {cvss['severity']}"
            )

        st.code(
            cvss["vector"] or "No vector available"
        )

    # --------------------------------------------------------
    # EPSS
    # --------------------------------------------------------

    st.subheader("EPSS")

    if epss:

        epss_score = float(epss.get("epss", 0)) * 100

        st.metric(
            "EPSS Probability",
            f"{epss_score:.2f}%"
        )

        st.write(
            f"EPSS Percentile: "
            f"{float(epss.get('percentile', 0)) * 100:.2f}%"
        )

    else:

        st.info("No EPSS information was returned.")

    # --------------------------------------------------------
    # CISA KEV
    # --------------------------------------------------------

    st.subheader("CISA Known Exploited Vulnerabilities")

    if kev:

        st.warning(
            "⚠️ This CVE is listed in the CISA KEV catalogue."
        )

        st.write(
            f"**Vendor:** {kev.get('vendorProject', 'N/A')}"
        )

        st.write(
            f"**Product:** {kev.get('product', 'N/A')}"
        )

        st.write(
            f"**Date Added:** {kev.get('dateAdded', 'N/A')}"
        )

        st.write(
            f"**Required Action:** "
            f"{kev.get('requiredAction', 'N/A')}"
        )

    else:

        st.success(
            "This CVE was not found in the current CISA KEV catalogue."
        )

    # --------------------------------------------------------
    # SOURCE LINKS
    # --------------------------------------------------------

    st.subheader("Primary Sources")

    st.link_button(
        "Open this CVE in NVD",
        NVD_WEB + cve
    )

    st.link_button(
        "Open this CVE in CVE.org",
        CVE_WEB + cve
    )

    st.link_button(
        "Open MITRE ATT&CK",
        MITRE_URL
    )

    # ========================================================
    # STUDENT INPUT
    # ========================================================

    st.header("3️⃣ Student Investigation")

    st.info(
        "Complete this section using your own research BEFORE "
        "checking the dashboard results."
    )

    student_cvss = st.text_input(
        "Your CVSS Score"
    )

    student_cvss_severity = st.selectbox(
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

    student_kev = st.selectbox(
        "Is the CVE listed in CISA KEV?",
        [
            "Select...",
            "Yes",
            "No"
        ]
    )

    student_epss = st.text_input(
        "EPSS Probability (%)"
    )

    student_mitre = st.text_input(
        "Relevant MITRE ATT&CK Technique ID",
        placeholder="Example: T1190"
    )

    student_impact = st.text_area(
        "What could be the impact of this vulnerability?"
    )

    student_rating = st.selectbox(
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
        "Justify your final rating"
    )

    student_mitigation = st.text_area(
        "Recommended Mitigation"
    )

    check_button = st.button(
        "🔍 CHECK MY ANSWERS",
        type="primary"
    )

    # ========================================================
    # ANSWER CHECKING
    # ========================================================

    if check_button:

        st.header("4️⃣ Answer Validation")

        checks = []

        # CVSS
        if cvss and student_cvss:

            try:

                student_score = float(student_cvss)

                correct_score = float(cvss["score"])

                if abs(student_score - correct_score) < 0.01:

                    result = "✅ Correct"

                else:

                    result = (
                        f"❌ Review — reference score: "
                        f"{correct_score}"
                    )

                checks.append(
                    ["CVSS Score", student_cvss, correct_score, result]
                )

            except ValueError:

                checks.append(
                    [
                        "CVSS Score",
                        student_cvss,
                        cvss["score"],
                        "❌ Invalid number"
                    ]
                )

        # Severity
        if cvss:

            checks.append(
                [
                    "CVSS Severity",
                    student_cvss_severity,
                    cvss["severity"],
                    compare_value(
                        student_cvss_severity,
                        cvss["severity"]
                    )
                ]
            )

        # KEV
        reference_kev = "Yes" if kev else "No"

        checks.append(
            [
                "CISA KEV",
                student_kev,
                reference_kev,
                compare_value(
                    student_kev,
                    reference_kev
                )
            ]
        )

        # EPSS
        if epss and student_epss:

            try:

                student_epss_value = float(student_epss)

                reference_epss = (
                    float(epss["epss"]) * 100
                )

                difference = abs(
                    student_epss_value - reference_epss
                )

                if difference <= 1:

                    epss_result = "✅ Correct"

                else:

                    epss_result = (
                        f"❌ Review — reference: "
                        f"{reference_epss:.2f}%"
                    )

                checks.append(
                    [
                        "EPSS",
                        f"{student_epss_value:.2f}%",
                        f"{reference_epss:.2f}%",
                        epss_result
                    ]
                )

            except ValueError:

                checks.append(
                    [
                        "EPSS",
                        student_epss,
                        f"{float(epss['epss']) * 100:.2f}%",
                        "❌ Invalid number"
                    ]
                )

        # ----------------------------------------------------
        # DISPLAY RESULTS
        # ----------------------------------------------------

        st.dataframe(
            checks,
            column_config={
                0: "Assessment Item",
                1: "Student Answer",
                2: "Reference",
                3: "Result"
            },
            use_container_width=True,
            hide_index=True
        )

        # ----------------------------------------------------
        # FINAL RATING CHECK
        # ----------------------------------------------------

        st.subheader("🎯 Final Risk Rating")

        if student_rating != "Select...":

            if cvss:

                cvss_rating = cvss["severity"]

                if student_rating == cvss_rating:

                    st.success(
                        f"Your rating **{student_rating}** "
                        f"matches the CVSS severity."
                    )

                else:

                    st.warning(
                        f"⚠️ Your rating is **{student_rating}**, "
                        f"while the CVSS severity is "
                        f"**{cvss_rating}**."
                    )

                    st.info(
                        "This does not automatically mean your "
                        "organisational risk rating is wrong. "
                        "Consider asset criticality, exposure, "
                        "exploitability and business impact."
                    )

        # ----------------------------------------------------
        # STUDENT JUSTIFICATION
        # ----------------------------------------------------

        st.subheader("🧠 Your Analysis")

        if student_justification:

            st.write(
                student_justification
            )

        else:

            st.warning(
                "Please provide a justification for your rating."
            )

        # ----------------------------------------------------
        # MITIGATION
        # ----------------------------------------------------

        st.subheader("🛡️ Your Mitigation")

        if student_mitigation:

            st.write(
                student_mitigation
            )

        else:

            st.warning(
                "Please provide a mitigation recommendation."
            )

        # ----------------------------------------------------
        # REPORT PREVIEW
        # ----------------------------------------------------

        st.header("5️⃣ Vulnerability Report")

        report = f"""
# Vulnerability Assessment Report

## Vulnerability

CVE: {cve}

## Description

{description}

## CVSS

Score: {cvss['score'] if cvss else 'N/A'}

Severity: {cvss['severity'] if cvss else 'N/A'}

Version: {cvss['version'] if cvss else 'N/A'}

## CISA KEV

{"Listed in CISA KEV" if kev else "Not listed in current CISA KEV catalogue"}

## EPSS

{
    f"{float(epss['epss']) * 100:.2f}%"
    if epss else
    "N/A"
}

## MITRE ATT&CK

Student identified technique:

{student_mitre}

## Student Risk Assessment

Final Rating:

{student_rating}

### Justification

{student_justification}

## Student Recommended Mitigation

{student_mitigation}

## Assessment Note

The CVSS severity is a standard vulnerability severity measure.
The student's final organisational risk rating should consider
additional context such as asset criticality, exposure,
exploitability and business impact.

## References

NVD:
{NVD_WEB}{cve}

CVE.org:
{CVE_WEB}{cve}

MITRE ATT&CK:
{MITRE_URL}
"""

        st.download_button(
            label="📄 Download Vulnerability Report",
            data=report,
            file_name=f"{cve}_vulnerability_report.md",
            mime="text/markdown"
        )
