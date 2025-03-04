import streamlit as st
import httpx
import asyncio
from models.vulnerability import VulnerabilityReport
from utils.latex_generator import LatexGenerator  # Keep for now
import os
from datetime import datetime
from analyzer.zap_scanner import scan_url
from analyzer.wapiti_scanner import run_wapiti
from analyzer.sqlmap_scanner import run_sqlmap
from analyzer.commix_scanner import run_commix
from analyzer.sstimap_scanner import run_sstimap
from analyzer.XSStrike_scanner import run_XSStrike
from report_manager import ReportManager
from zapv2 import ZAPv2


zap = ZAPv2(
    proxies={"http": "http://localhost:8081", "https": "http://localhost:8081"},
    apikey=os.getenv("ZAP_API_KEY"),
)


# --- Helper Functions ---
def is_valid_repo_url(url: str) -> bool:
    return url.startswith("http://") or url.startswith("https://")


def is_valid_scan_url(url: str) -> bool:
    return url.startswith("http://") or url.startswith("https://")


# --- Initialize Session State ---
if "scan_completed" not in st.session_state:
    st.session_state.scan_completed = False
if "scan_results" not in st.session_state:
    st.session_state.scan_results = None
if "scan_results_pdf" not in st.session_state:
    st.session_state.scan_results_pdf = None

# --- UI Setup ---
st.set_page_config(page_title="INSPECTIFY", layout="wide")
st.title("INSPECTIFY")
st.write("Tool for analyzing code and scanning web applications for vulnerabilities.")

with st.sidebar:
    st.markdown("<h1 style='font-size: 3em;'>INSPECTIFY</h1>", unsafe_allow_html=True)

    st.header("Select task")
    tabs = st.tabs(["Code Analysis", "Vulnerability Scanning"])

    with tabs[0]:
        input_type = st.radio(
            "Select Input Type", ["Upload Code File", "Provide Repository URL"]
        )

        if input_type == "Upload Code File":
            uploaded_files = st.file_uploader(
                "Upload Code File(s)",
                type=[
                    "py",
                    "js",
                    "java",
                    "cpp",
                    "c",
                    "cs",
                    "go",
                    "rb",
                    "php",
                    "rs",
                    "swift",
                    "kt",
                    "scala",
                ],
                accept_multiple_files=True,
            )
            if uploaded_files:
                st.write(f"You have uploaded {len(uploaded_files)} file(s).")
            repo_url = None
            branch = None
            scan_depth = None

        else:  # input_type == "Provide Repository URL"
            repo_url = st.text_input("Repository URL")
            branch = st.text_input("Branch", "main")
            scan_depth = st.number_input("Scan Depth", min_value=1, value=3)
            uploaded_files = None

        analyze_button = st.button("Analyze")
with tabs[1]:
    st.write("Vulnerability Scanning (Injection and Broken Access Control)")
    target_url = st.text_input("Enter URL to scan")
    scan_depth = st.number_input(
        "Scan Depth", min_value=1, max_value=10, value=1
    )  # Change to number input for depth

    # Add a multiselect dropdown for scanners with information icon
    # Add a multiselect dropdown for scanners with information icon
    st.markdown(
        """
            <style>
            .tooltip {
                position: relative;
                display: inline-block;
                cursor: pointer;
            }
            .tooltip .tooltiptext {
                visibility: hidden;
                width: 400px;
                background-color: #555;
                color: #fff;
                text-align: center;
                border-radius: 6px;
                padding: 5px 0;
                position: absolute;
                z-index: 1;
                bottom: 125%; /* Position the tooltip above the text */
                left: 50%;
                margin-left: -100px;
                opacity: 0;
                transition: opacity 0.3s;
            }
            .tooltip:hover .tooltiptext {
                visibility: visible;
                opacity: 1;
            }
            </style>
            """,
        unsafe_allow_html=True,
    )
    st.markdown(
        """
            <div style="display: flex; align-items: center;">
                <h3 style="margin: 0;">Select Scanners</h3>
                <div class="tooltip" style="margin-left: 5px;">ℹ️
                    <span class="tooltiptext">
                        <b>OWASP ZAP:</b> A popular security tool for finding vulnerabilities in web applications.<br>
                        <b>Wapiti:</b> A web application vulnerability scanner that audits the security of web applications.<br>
                        <b>SQLMap:</b> An open-source penetration testing tool that automates the process of detecting and exploiting SQL injection flaws.<br>
                        <b>XSStrike:</b> A tool for detecting and exploiting XSS vulnerabilities.<br>
                        <b>COMMIX:</b> A tool for testing web applications for command injection vulnerabilities.(May take long)<br>
                        <b>SSTImap:</b> A tool for detecting and exploiting Server-Side Template Injection vulnerabilities.(May take long)
                    </span>
                </div>
            </div>
            """,
        unsafe_allow_html=True,
    )

    # Add a multiselect dropdown for scanners
    selected_scanners = st.multiselect(
        "Options",
        ["ZAP", "Wapiti", "SQLMap", "XSStrike", "COMMIX", "SSTImap"],
        default=["ZAP", "Wapiti"],
    )

    # Center the "Start Scan" button and make it fill the space
    col1, col2, col3 = st.columns([1, 2, 1])
    with col2:
        # Only show scan button if we haven't completed a scan or if we need to run a new scan
        if not st.session_state.scan_completed:
            scan_button = st.button(
                "Start Scan", use_container_width=True, key="scan_button"
            )
        else:
            # Add a button to run a new scan if we've already completed one
            new_scan_button = st.button(
                "Run New Scan", use_container_width=True, key="new_scan_button"
            )
            if new_scan_button:
                st.session_state.scan_completed = False
                st.rerun()


def run_scan(target_url, scan_depth, selected_scanners):
    if is_valid_scan_url(target_url):
        if not selected_scanners:
            st.error("Please select at least one scanner.")
            return False
        else:
            report_manager = ReportManager("./scans/consolidated_scan_results.pdf")

            if "ZAP" in selected_scanners:
                st.header("OWASP ZAP Scan:")
                st.write(f"Scanning URL: {target_url} with depth: {scan_depth}")
                scan_url(report_manager, target_url, scan_depth)
                st.markdown("---")
            if "Wapiti" in selected_scanners:
                st.header("Wapiti Scan:")
                run_wapiti(report_manager, target_url, scan_depth)
                st.markdown("---")
            if "SQLMap" in selected_scanners:
                st.header("SQLMap Scan:")
                run_sqlmap(report_manager, target_url, scan_depth)
                st.markdown("---")
            if "XSStrike" in selected_scanners:
                st.header("XSStrike Scan:")
                run_XSStrike(report_manager, target_url, scan_depth)
                st.markdown("---")
            if "COMMIX" in selected_scanners:
                st.header("COMMIX Scan:")
                run_commix(report_manager, target_url, scan_depth)
                st.markdown("---")
            if "SSTImap" in selected_scanners:
                st.header("SSTImap Scan:")
                run_sstimap(report_manager, target_url, scan_depth)
                st.markdown("---")

            # Save the PDF to session state
            with open("scans/consolidated_scan_results.pdf", "rb") as file:
                st.session_state.scan_results_pdf = file.read()

            # Mark scan as completed
            st.session_state.scan_completed = True
            return True
    else:
        st.error(
            "Invalid URL. Please enter a valid URL starting with http:// or https://."
        )
        return False


# Check if scan button was pressed or we have scan results already
if "scan_button" in locals() and scan_button:
    if target_url:
        with st.spinner("Running scan..."):
            success = run_scan(target_url, scan_depth, selected_scanners)
            if success:
                # Store important values in session state
                st.session_state.target_url = target_url
                st.session_state.scan_depth = scan_depth
                st.session_state.selected_scanners = selected_scanners
    else:
        st.error("Please enter a URL to scan.")

# # Display download button if scan completed
# if st.session_state.scan_completed and st.session_state.scan_results_pdf:
#     st.download_button(
#         label="📥 Download Consolidated Scan Results (PDF)",
#         data=st.session_state.scan_results_pdf,
#         file_name="consolidated_scan_results.pdf",
#         mime="application/pdf",
#         key="download_button",
#     )


#     # Display scan information
#     st.success("Scan completed successfully!")
#     st.write(f"**Target URL:** {st.session_state.target_url}")
#     st.write(f"**Scan Depth:** {st.session_state.scan_depth}")
#     st.write(f"**Scanners Used:** {', '.join(st.session_state.selected_scanners)}")

# Display scan information
if st.session_state.scan_completed and st.session_state.scan_results_pdf:
    st.success("Scan completed successfully!")
    st.write(f"**Target URL:** {st.session_state.target_url}")
    st.write(f"**Scan Depth:** {st.session_state.scan_depth}")
    st.write(f"**Scanners Used:** {', '.join(st.session_state.selected_scanners)}")

    # Display individual scanner outputs with download buttons
    st.header("Download Scan Results by Tool :")

    for scanner in st.session_state.get(
        "selected_scanners", []
    ):  # Avoid KeyError if selected_scanners is missing
        st.header(scanner)
        pdf_key = f"{scanner.lower()}_scan_report_pdf"

        try:
            with open(f"scans/{scanner.lower()}_scan_report.pdf", "rb") as pdf_file:
                pdf_data = pdf_file.read()

            # Add a download button
            st.download_button(
                label=f"📥 Download {scanner} Scan Report (PDF)",
                data=pdf_data,
                file_name=f"{scanner.lower()}_scan_report.pdf",
                mime="application/pdf",
            )

        except FileNotFoundError:
            st.error(
                f"File not found: {scanner.lower()}_scan_report.pdf. Ensure the file exists and the path is correct."
            )

    st.markdown("---")

    st.header("Consolidated Scan Results")
    st.download_button(
        label="📥 Download Consolidated Scan Results (PDF)",
        data=st.session_state.scan_results_pdf,
        file_name="consolidated_scan_results.pdf",
        mime="application/pdf",
        key="download_button",
    )


# --- Analysis Logic (using httpx for requests to FastAPI) ---
async def analyze_code_file(files):
    print("--- Starting analyze_code_file (Streamlit) ---")
    async with httpx.AsyncClient(timeout=30.0) as client:
        files_data = []
        for file in files:
            print(f"  Processing file: {file.name}")
            files_data.append(("files", (file.name, file.getvalue(), file.type)))
        print(f"  Files data prepared: {files_data}")

        try:
            print("  Sending POST request to FastAPI...")
            response = await client.post(
                "http://127.0.0.1:8001/analyze/file", files=files_data
            )
            print(f"  Received response. Status: {response.status_code}")
            response.raise_for_status()
            report = VulnerabilityReport(**response.json())
            print("  Response parsed successfully.")
            return report
        except httpx.RequestError as e:
            print(f"  Network error: {e}")
            st.error(f"Network error: {e}")
            return None
        except httpx.HTTPStatusError as e:
            print(f"  Server error: {e.response.status_code} - {e.response.text}")
            st.error(f"Server error: {e.response.status_code} - {e.response.text}")
            return None
        except Exception as e:
            print(f"  Unexpected error: {e}")
            st.error(f"Unexpected error: {e}")
            return None
        finally:
            print("--- Finishing analyze_code_file (Streamlit) ---")


async def analyze_repo(repo_url, branch, scan_depth):
    print("--- Starting analyze_repo (Streamlit) ---")
    async with httpx.AsyncClient(timeout=30.0) as client:
        try:
            print("  Sending POST request to FastAPI...")
            response = await client.post(
                "http://127.0.0.1:8001/analyze/repository",
                json={
                    "repository_url": repo_url,
                    "branch": branch,
                    "scan_depth": scan_depth,
                },
            )
            print(f"  Received response. Status: {response.status_code}")
            response.raise_for_status()
            report = VulnerabilityReport(**response.json())
            print("  Response parsed successfully.")
            return report
        except httpx.RequestError as e:
            print(f"  Network error: {e}")
            st.error(f"Network error: {e}")
            return None
        except httpx.HTTPStatusError as e:
            print(f"  Server error: {e.response.status_code} - {e.response.text}")
            st.error(f"Server error: {e.response.status_code} - {e.response.text}")
            return None
        except Exception as e:
            print(f"  Unexpected error: {e}")
            st.error(f"Unexpected error: {e}")
            return None
        finally:
            print("--- Finishing analyze_repo (Streamlit) ---")


# --- Main Analysis Execution ---
if analyze_button:
    if input_type == "Upload Code File" and uploaded_files:
        with st.spinner("Analyzing code..."):
            report = asyncio.run(analyze_code_file(uploaded_files))
            if report:
                # --- Display Results Directly on the Page ---
                st.header("Vulnerability Report")
                st.subheader("Summary")
                if report.summary:
                    col1, col2, col3, col4, col5, col6 = st.columns(6)
                    col1.metric("Total", report.summary["total"])
                    col2.metric("Critical", report.summary["critical"])
                    col3.metric("High", report.summary["high"])
                    col4.metric("Medium", report.summary["medium"])
                    col5.metric("Low", report.summary["low"])
                    col6.metric("Info", report.summary["info"])
                st.metric(
                    "Risk Score",
                    (
                        f"{report.risk_score:.2f}"
                        if report.risk_score is not None
                        else "N/A"
                    ),
                )

                st.subheader("Detailed Vulnerabilities")
                for vuln in report.vulnerabilities:
                    with st.expander(
                        f"{vuln.type} - {vuln.severity} - {vuln.location.file_path}:{vuln.location.start_line}"
                    ):
                        st.write(f"**Description:** {vuln.description}")
                        st.write(f"**Impact:** {vuln.impact}")
                        st.write(f"**Remediation:** {vuln.remediation}")
                        st.write(
                            f"**CWE ID:** [{vuln.cwe_id}](https://cwe.mitre.org/data/definitions/{vuln.cwe_id}.html)"
                        )
                        st.write(f"**OWASP Category:** {vuln.owasp_category}")
                        st.write(f"**CVSS Score:** {vuln.cvss_score}")
                        if vuln.references:
                            st.write("**References:**")
                            for ref in vuln.references:
                                st.write(f"- [{ref}]({ref})")

                        if vuln.proof_of_concept:
                            st.write("**Proof of Concept:**")  # Just write the heading
                            st.code(
                                vuln.proof_of_concept, language="python"
                            )  # Display the code

                        if vuln.secure_code_example:
                            st.write(
                                "**Secure Code Example:**"
                            )  # Just write the heading
                            st.code(
                                vuln.secure_code_example, language="python"
                            )  # Display the code

                st.subheader("Chained Vulnerabilities")
                for chain in report.chained_vulnerabilities:
                    with st.expander(
                        f"Chain - Combined Severity: {chain.combined_severity}"
                    ):
                        st.write(f"**Attack Path:** {chain.attack_path}")
                        st.write(f"**Likelihood:** {chain.likelihood}")
                        st.write("**Prerequisites:**")
                        for prereq in chain.prerequisites:
                            st.write(f"- {prereq}")
                        st.write(
                            f"**Mitigation Priority:** {chain.mitigation_priority}"
                        )

    elif input_type == "Provide Repository URL" and repo_url:
        if not is_valid_repo_url(repo_url):
            st.error("Invalid repository URL.")
        else:
            with st.spinner("Analyzing repository..."):
                report = asyncio.run(analyze_repo(repo_url, branch, scan_depth))
                if report:
                    # --- Display Results Directly on the Page ---
                    st.header("Vulnerability Report")
                    st.subheader("Summary")
                    if report.summary:
                        col1, col2, col3, col4, col5, col6 = st.columns(6)
                        col1.metric("Total", report.summary["total"])
                        col2.metric("Critical", report.summary["critical"])
                        col3.metric("High", report.summary["high"])
                        col4.metric("Medium", report.summary["medium"])
                        col5.metric("Low", report.summary["low"])
                        col6.metric("Info", report.summary["info"])
                    st.metric(
                        "Risk Score",
                        (
                            f"{report.risk_score:.2f}"
                            if report.risk_score is not None
                            else "N/A"
                        ),
                    )

                    st.subheader("Detailed Vulnerabilities")
                    for vuln in report.vulnerabilities:
                        with st.expander(
                            f"{vuln.type} - {vuln.severity} - {vuln.location.file_path}:{vuln.location.start_line}"
                        ):
                            st.write(f"**Description:** {vuln.description}")
                            st.write(f"**Impact:** {vuln.impact}")
                            st.write(f"**Remediation:** {vuln.remediation}")
                            st.write(
                                f"**CWE ID:** [{vuln.cwe_id}](https://cwe.mitre.org/data/definitions/{vuln.cwe_id}.html)"
                            )
                            st.write(f"**OWASP Category:** {vuln.owasp_category}")
                            st.write(f"**CVSS Score:** {vuln.cvss_score}")
                            if vuln.references:
                                st.write("**References:**")
                                for ref in vuln.references:
                                    st.write(f"- [{ref}]({ref})")
                            if vuln.proof_of_concept:
                                st.write(
                                    "**Proof of Concept:**"
                                )  # Just write the heading
                                st.code(
                                    vuln.proof_of_concept, language="python"
                                )  # Display the code

                            if vuln.secure_code_example:
                                st.write(
                                    "**Secure Code Example:**"
                                )  # Just write the heading
                                st.code(
                                    vuln.secure_code_example, language="python"
                                )  # Display the code

                    st.subheader("Chained Vulnerabilities")
                    for chain in report.chained_vulnerabilities:
                        with st.expander(
                            f"Chain - Combined Severity: {chain.combined_severity}"
                        ):
                            st.write(f"**Attack Path:** {chain.attack_path}")
                            st.write(f"**Likelihood:** {chain.likelihood}")
                            st.write("**Prerequisites:**")
                            for prereq in chain.prerequisites:
                                st.write(f"- {prereq}")
                            st.write(
                                f"**Mitigation Priority:** {chain.mitigation_priority}"
                            )

    else:
        st.error("Please provide either a code file or a repository URL.")
