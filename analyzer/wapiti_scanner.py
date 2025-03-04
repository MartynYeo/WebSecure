import os
import json
import time
import subprocess
import streamlit as st
from reportlab.lib.pagesizes import letter
from reportlab.lib import colors
from reportlab.pdfgen import canvas
from reportlab.platypus import SimpleDocTemplate, Paragraph
from reportlab.lib.styles import getSampleStyleSheet
from PyPDF2 import PdfReader, PdfWriter


def generate_pdf_report(wapiti_results):
    pdf_path = "./scans/wapiti_scan_report.pdf"

    # Ensure the "scans" directory exists
    if not os.path.exists("scans"):
        os.makedirs("scans")

    # Deletes the file if it already exists
    if os.path.exists(pdf_path):
        os.remove(pdf_path)

    c = canvas.Canvas(pdf_path, pagesize=letter)
    width, height = letter

    c.setFont("Helvetica-Bold", 18)
    c.setFillColor(colors.blue)
    c.drawString(100, height - 50, "Wapiti Scan Results")
    c.setFillColor(colors.black)

    y_position = height - 80  # Initial Y position

    # Extract vulnerabilities and classifications
    vulnerabilities = wapiti_results.get("vulnerabilities", {})
    classifications = wapiti_results.get("classifications", {})

    for vuln_type, vuln_list in vulnerabilities.items():
        if not vuln_list:  # Skip empty vulnerability types
            continue
        c.setFont("Helvetica-Bold", 14)
        c.setFillColor(colors.darkblue)
        c.drawString(100, y_position, f"Vulnerability Type: {vuln_type}")
        y_position -= 20

        for vuln in vuln_list:
            # Print the path, method, info, etc., with some structure
            c.setFont("Helvetica", 12)
            c.setFillColor(colors.black)

            # Path
            wrapped_text = f"Path: {vuln.get('path', 'N/A')}"
            y_position = _draw_text(c, wrapped_text, y_position, width)

            # Method
            wrapped_text = f"Method: {vuln.get('method', 'N/A')}"
            y_position = _draw_text(c, wrapped_text, y_position, width)

            # Info
            wrapped_text = f"Info: {vuln.get('info', 'N/A')}"
            y_position = _draw_text(c, wrapped_text, y_position, width)

            # Level
            wrapped_text = f"Level: {vuln.get('level', 'N/A')}"
            y_position = _draw_text(c, wrapped_text, y_position, width)

            # Parameter
            wrapped_text = f"Parameter: {vuln.get('parameter', 'N/A')}"
            y_position = _draw_text(c, wrapped_text, y_position, width)

            # Referer
            wrapped_text = f"Referer: {vuln.get('referer', 'N/A')}"
            y_position = _draw_text(c, wrapped_text, y_position, width)

            # Module
            wrapped_text = f"Module: {vuln.get('module', 'N/A')}"
            y_position = _draw_text(c, wrapped_text, y_position, width)

            # HTTP Request
            wrapped_text = f"HTTP Request: {vuln.get('http_request', 'N/A')}"
            y_position = _draw_text(c, wrapped_text, y_position, width)

            # CURL Command
            wrapped_text = f"CURL Command: {vuln.get('curl_command', 'N/A')}"
            y_position = _draw_text(c, wrapped_text, y_position, width)

            # Classification details
            classification = classifications.get(vuln_type, {})
            if classification:
                # Description
                wrapped_text = f"Description: {classification.get('desc', 'N/A')}"
                y_position = _draw_text(c, wrapped_text, y_position, width)

                # Solution
                wrapped_text = f"Solution: {classification.get('sol', 'N/A')}"
                y_position = _draw_text(c, wrapped_text, y_position, width)

                # References
                references = classification.get("ref", {})
                if references:
                    wrapped_text = "References:"
                    y_position = _draw_text(c, wrapped_text, y_position, width)
                    for ref_title, ref_url in references.items():
                        wrapped_text = f"- <a href='{ref_url}'>{ref_title}</a>"
                        y_position = _draw_text(c, wrapped_text, y_position, width)

            # Divider line
            c.setFont("Helvetica", 10)
            c.setFillColor(colors.grey)
            c.drawString(100, y_position, "-" * 50)
            y_position -= 20

            if y_position < 50:  # Avoid writing too low
                c.showPage()
                c.setFont("Helvetica", 12)
                y_position = height - 50

    c.save()


def _draw_text(canvas, text, y_position, page_width, margin=100):
    """Helper function to handle line wrapping and drawing text."""
    from reportlab.lib.pagesizes import letter
    from reportlab.platypus import Paragraph
    from reportlab.lib.styles import getSampleStyleSheet

    styles = getSampleStyleSheet()
    style = styles["Normal"]
    style.wordWrap = 'CJK'  # Enable word wrapping

    # Create a Paragraph object
    paragraph = Paragraph(text, style)
    _, height = paragraph.wrap(page_width - 2 * margin, y_position)

    if y_position - height < 50:  # Avoid writing too low
        canvas.showPage()
        y_position = letter[1] - 50
        canvas.setFont("Helvetica", 12)  # Reset font after new page

    paragraph.drawOn(canvas, margin, y_position - height)
    y_position -= height + 14  # Move down by the height of the paragraph plus some padding

    return y_position


def run_wapiti(report_manager, target_url, scan_depth=1):
    try:
        st.write(f"Starting Wapiti scan on: {target_url} with depth: {scan_depth}")
        # Set the PYTHONIOENCODING environment variable to utf-8
        env = os.environ.copy()
        env["PYTHONIOENCODING"] = "utf-8"

        # Specify the modules to run for injection and broken access control vulnerabilities
        modules = [
            "crlf",
            "exec",
            "ldap",
            "log4shell",
            "sql",
            "spring4shell",
            "ssrf",
            "timesql",
            "xss",
            "xxe",  # Injection-related modules
            "csrf",
            "file",
            "htaccess",
            "http_headers",
            "redirect",
            "takeover",
            "upload",  # BAC-related modules
        ]

        # Ensure the scans directory exists
        os.makedirs("scans", exist_ok=True)

        # Initialize the progress bar
        progress_bar = st.progress(0)
        progress = 0

        # Run the Wapiti scan in a subprocess
        process = subprocess.Popen(
            [
                "wapiti",
                "-u",
                target_url,
                "-f",
                "json",
                "-o",
                "./scans/wapiti_scan_results.json",
                "-m",
                ",".join(modules),
                "-v",
                "1",
                "-d",
                f"{scan_depth}",
            ],
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
            env=env,  # Pass the modified environment
        )

        # Monitor the progress of the scan
        while process.poll() is None:
            time.sleep(1)  # Wait for a second before checking the progress again
            # Update the progress bar (this is a simple example, you can implement a more accurate progress calculation)
            progress = min(progress + 5, 100)
            progress_bar.progress(progress)

        # Wait for the process to complete
        stdout, stderr = process.communicate()

        # Update the progress bar to 100% after the scan is complete
        progress_bar.progress(100)

        # Check if the process exited with an error
        if process.returncode != 0:
            st.error(f"Wapiti scan failed with return code {process.returncode}")
            st.error(f"Error message: {stderr}")
            return None

        st.write("Wapiti scan completed.")

        # Check if the result file exists
        results_file = "./scans/wapiti_scan_results.json"
        if not os.path.exists(results_file):
            st.error("Wapiti scan results file was not created.")
            return None

        # Check if the file has content
        if os.path.getsize(results_file) == 0:
            st.error("Wapiti scan results file is empty.")
            return None

        try:
            # Read the JSON results
            with open(results_file, "r", encoding="utf-8") as file:
                content = file.read()
                if not content.strip():
                    st.error("Wapiti scan results file contains no data.")
                    return None
                wapiti_results = json.loads(content)
        except json.JSONDecodeError as json_err:
            st.error(f"Invalid JSON in Wapiti results: {json_err}")
            return None

        # Extract the vulnerabilities and classifications sections
        vulnerabilities = wapiti_results.get("vulnerabilities", {})
        classifications = wapiti_results.get("classifications", {})

        # Filter out empty vulnerabilities
        filtered_vulnerabilities = {k: v for k, v in vulnerabilities.items() if v}

        # Display the filtered vulnerabilities section in a nicer format
        st.write("Vulnerabilities found:")

        if not filtered_vulnerabilities:
            st.info("No vulnerabilities were found.")
        else:
            for vuln_type, vuln_list in filtered_vulnerabilities.items():
                st.subheader(vuln_type)
                for vuln in vuln_list:
                    st.markdown(f"**Path:** {vuln.get('path', 'N/A')}")
                    st.markdown(f"**Method:** {vuln.get('method', 'N/A')}")
                    st.markdown(f"**Info:** {vuln.get('info', 'N/A')}")
                    st.markdown(f"**Level:** {vuln.get('level', 'N/A')}")
                    st.markdown(f"**Parameter:** {vuln.get('parameter', 'N/A')}")
                    st.markdown(f"**Referer:** {vuln.get('referer', 'N/A')}")
                    st.markdown(f"**Module:** {vuln.get('module', 'N/A')}")
                    st.markdown(f"**HTTP Request:**")
                    st.code(vuln.get("http_request", "N/A"))
                    st.markdown(f"**CURL Command:**")
                    st.code(vuln.get("curl_command", "N/A"))

                    # Display classification details
                    classification = classifications.get(vuln_type, {})
                    if classification:
                        st.markdown(f"**Description:** {classification.get('desc', 'N/A')}")
                        st.markdown(f"**Solution:** {classification.get('sol', 'N/A')}")
                        st.markdown(f"**References:**")
                        for ref_title, ref_url in classification.get("ref", {}).items():
                            st.markdown(f"- [{ref_title}]({ref_url})")

                    st.markdown("---")

        # Generate and append PDF report only if we have valid results
        try:
            generate_pdf_report(wapiti_results)
            report_manager.append_to_pdf("./scans/wapiti_scan_report.pdf")

        except Exception as pdf_error:
            st.error(f"Error generating PDF report: {pdf_error}")

        return filtered_vulnerabilities

    except subprocess.CalledProcessError as e:
        st.error(f"Wapiti scan failed: {str(e)}")
        if hasattr(e, "stderr"):
            st.error(f"Error details: {e.stderr}")
        return None
    except Exception as e:
        st.error(f"An error occurred during Wapiti scan: {str(e)}")
        import traceback

        st.error(traceback.format_exc())
        return None