from PyPDF2 import PdfReader, PdfWriter
import os


class ReportManager:
    def __init__(self, output_pdf_path):
        self.output_pdf_path = output_pdf_path
        self._initialize_pdf()

    def _initialize_pdf(self):
        """Creates an initial blank PDF if it doesn't exist."""

        # Deletes the file if it already exists
        if os.path.exists(self.output_pdf_path):
            os.remove(self.output_pdf_path)

        if not os.path.exists(self.output_pdf_path):
            pdf_writer = PdfWriter()
            with open(self.output_pdf_path, "wb") as output_pdf:
                pdf_writer.write(output_pdf)

    def append_to_pdf(self, new_pdf_path):
        """Appends the given PDF to the report."""
        if not os.path.exists(new_pdf_path):
            raise FileNotFoundError(f"File not found: {new_pdf_path}")

        pdf_writer = PdfWriter()
        existing_reader = PdfReader(self.output_pdf_path)
        new_reader = PdfReader(new_pdf_path)

        # Add existing report pages
        for page in existing_reader.pages:
            pdf_writer.add_page(page)

        # Add new report pages
        for page in new_reader.pages:
            pdf_writer.add_page(page)

        # Save the merged report
        with open(self.output_pdf_path, "wb") as output_pdf:
            pdf_writer.write(output_pdf)


# Example Usage
# report_manager = ReportManager("./scans/consolidated_scan_results.pdf")
# report_manager.append_to_pdf("./scans/wapiti_scan_report.pdf")
