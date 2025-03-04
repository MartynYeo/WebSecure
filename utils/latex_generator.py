# utils/latex_generator.py
import jinja2
from models.vulnerability import VulnerabilityReport

class LatexGenerator:
    def __init__(self, template_path: str = "report_template.tex"):
        """
        Initializes the LatexGenerator with the path to the Jinja2 template.

        Args:
            template_path: Path to the LaTeX template file.
        """
        self.template_path = template_path
        self.template_env = jinja2.Environment(
            loader=jinja2.FileSystemLoader(searchpath="./"),  # Assumes template is in the same directory
            autoescape=jinja2.select_autoescape(['tex'])
        )
        self.template = self.template_env.get_template(self.template_path)

    def generate_report(self, report: VulnerabilityReport) -> str:
        """
        Generates a LaTeX report from a VulnerabilityReport.

        Args:
            report: The VulnerabilityReport object.

        Returns:
            str: The LaTeX report as a string.
        """
        # Render the template with the report data
        latex_report = self.template.render(report=report)
        return latex_report