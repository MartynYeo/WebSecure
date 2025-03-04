import requests
import re
import random
import string
import logging
from bs4 import BeautifulSoup
from urllib.parse import urljoin, urlparse
from report_manager import ReportManager
import time
import os

# Configure logging
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')
logger = logging.getLogger(__name__)

class BrokenAccessScanner:
    def __init__(self):
        self.visited_urls = set()
        self.forms = []
        self.authenticated_paths = []
        self.roles = ["admin", "user", "guest"]
        self.auth_headers = {}
        self.cookies = {}
        self.session = requests.Session()
        self.session.headers.update({
            'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.124 Safari/537.36'
        })
        # Add a list to track login attempts
        self.login_attempts = []
        # Add a variable to track successful login credentials
        self.successful_login = None
        
    def generate_random_credentials(self):
        """Generate random username and password for registration attempts"""
        username = ''.join(random.choices(string.ascii_lowercase + string.digits, k=8))
        password = ''.join(random.choices(string.ascii_letters + string.digits + string.punctuation, k=12))
        return username, password
        
    def discover_endpoints(self, base_url, depth=1):
        """Crawl the website to discover endpoints and forms"""
        if depth <= 0 or base_url in self.visited_urls:
            return
            
        self.visited_urls.add(base_url)
        logger.info(f"Discovering endpoints at: {base_url}")
        
        try:
            response = self.session.get(base_url, timeout=10)
            if response.status_code != 200:
                return
                
            soup = BeautifulSoup(response.text, 'html.parser')
            
            # Collect forms
            for form in soup.find_all('form'):
                form_data = {
                    'action': form.get('action', ''),
                    'method': form.get('method', 'get').lower(),
                    'inputs': [(input_tag.get('name'), input_tag.get('type', 'text')) 
                              for input_tag in form.find_all('input') if input_tag.get('name')]
                }
                
                # Identify potential login forms
                if any(field[0] and field[0].lower() in ['password', 'pass', 'pwd'] for field in form_data['inputs']):
                    form_data['is_login'] = True
                    
                # Full URL for the form action
                if form_data['action']:
                    form_data['action'] = urljoin(base_url, form_data['action'])
                else:
                    form_data['action'] = base_url
                    
                self.forms.append(form_data)
                
            # Collect links for further crawling
            if depth > 0:
                for a_tag in soup.find_all('a', href=True):
                    link = a_tag['href']
                    if link.startswith(('#', 'javascript:', 'mailto:')):
                        continue
                        
                    full_url = urljoin(base_url, link)
                    # Only follow links to the same domain
                    if urlparse(full_url).netloc == urlparse(base_url).netloc:
                        self.discover_endpoints(full_url, depth - 1)
        
        except Exception as e:
            logger.error(f"Error discovering endpoints at {base_url}: {str(e)}")
            
    def attempt_login(self, credentials=None):
        """Try to login with provided or common credentials"""
        login_forms = [form for form in self.forms if form.get('is_login', False)]
        
        if not login_forms:
            logger.info("No login forms discovered")
            self.login_attempts.append({"status": "failed", "reason": "No login forms discovered"})
            return False
            
        # Try common credentials if none provided
        if not credentials:
            common_credentials = [
                {'username': 'admin', 'password': 'admin'},
                {'username': 'admin', 'password': 'password'},
                {'username': 'user', 'password': 'password'},
                {'username': 'test', 'password': 'test'}
            ]
            credentials = common_credentials
        
        for login_form in login_forms:
            for cred in credentials:
                logger.info(f"Attempting login with credentials: {cred['username']}")
                attempt_info = {
                    "username": cred['username'],
                    "password": cred['password'],
                    "form_action": login_form['action'],
                    "method": login_form['method'],
                    "timestamp": time.strftime("%Y-%m-%d %H:%M:%S"),
                    "status": "pending"
                }
                
                # Prepare form data
                form_data = {}
                for input_name, input_type in login_form['inputs']:
                    if input_type == 'password':
                        form_data[input_name] = cred['password']
                    elif input_name.lower() in ['username', 'user', 'email', 'login']:
                        form_data[input_name] = cred['username']
                    else:
                        form_data[input_name] = ''
                
                try:
                    if login_form['method'] == 'post':
                        response = self.session.post(login_form['action'], data=form_data, timeout=10, allow_redirects=True)
                    else:
                        response = self.session.get(login_form['action'], params=form_data, timeout=10, allow_redirects=True)
                    
                    # Check if login seems successful
                    if 'logout' in response.text.lower() or 'welcome' in response.text.lower() or 'dashboard' in response.text.lower():
                        logger.info(f"Login successful with {cred['username']}")
                        self.auth_headers = dict(self.session.headers)
                        self.cookies = dict(self.session.cookies)
                        attempt_info["status"] = "success"
                        attempt_info["response_code"] = response.status_code
                        self.login_attempts.append(attempt_info)
                        self.successful_login = attempt_info
                        return True
                    else:
                        attempt_info["status"] = "failed"
                        attempt_info["response_code"] = response.status_code
                        attempt_info["reason"] = "Invalid credentials or login failed"
                        self.login_attempts.append(attempt_info)
                
                except Exception as e:
                    logger.error(f"Error attempting login: {str(e)}")
                    attempt_info["status"] = "error"
                    attempt_info["reason"] = str(e)
                    self.login_attempts.append(attempt_info)
        
        logger.info("All login attempts failed")
        return False
    
    def identify_restricted_resources(self, base_url, depth=1):
        """Identify potentially restricted resources"""
        # Common restricted paths
        common_restricted_paths = [
            '/admin', '/dashboard', '/profile', '/account', '/settings',
            '/manage', '/users', '/api', '/private', '/protected', '/secure',
            '/backend', '/control', '/panel', '/staff', '/config', '/configuration'
        ]
        
        for path in common_restricted_paths:
            full_url = urljoin(base_url, path)
            try:
                response = requests.head(full_url, timeout=5)
                # If the response is not 404, it might be a restricted resource
                if response.status_code != 404:
                    self.authenticated_paths.append(full_url)
            except Exception:
                continue
        
        # Also add discovered paths that look restricted
        for url in self.visited_urls:
            path = urlparse(url).path.lower()
            if any(restricted in path for restricted in ['admin', 'dashboard', 'profile', 'account', 'setting', 'manage', 'user', 'api', 'private']):
                self.authenticated_paths.append(url)
    
    def test_broken_access(self, report_manager):
        """Test for broken access control vulnerabilities"""
        vulnerable_endpoints = []
        
        # Create a new session without authentication
        unauth_session = requests.Session()
        unauth_session.headers.update({
            'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.124 Safari/537.36'
        })
        
        # Test direct access to authenticated paths
        logger.info("Testing direct access to authenticated paths")
        for path in self.authenticated_paths:
            try:
                # Try accessing with unauthenticated session
                unauth_response = unauth_session.get(path, timeout=10, allow_redirects=False)
                
                # If we can access without authentication
                if unauth_response.status_code in [200, 302, 307]:
                    # Now try with authenticated session for comparison
                    auth_response = None
                    if self.cookies:
                        auth_session = requests.Session()
                        auth_session.headers.update(self.auth_headers)
                        auth_session.cookies.update(self.cookies)
                        auth_response = auth_session.get(path, timeout=10, allow_redirects=False)
                    
                    # If content is similar, we might have broken access control
                    if not auth_response or len(unauth_response.content) > 0.7 * len(auth_response.content):
                        vulnerable_endpoints.append({
                            'url': path,
                            'type': 'Direct Access',
                            'status_code': unauth_response.status_code,
                            'details': 'Unauthenticated access to potentially restricted resource'
                        })
                        logger.warning(f"Potential broken access control at: {path}")
            
            except Exception as e:
                logger.error(f"Error testing access to {path}: {str(e)}")
        
        # Test for IDOR vulnerabilities
        logger.info("Testing for IDOR vulnerabilities")
        for url in self.visited_urls:
            # Look for URLs with IDs in them
            id_pattern = re.compile(r'(\?|&|/)(?:id|user_id|account|profile)=(\d+)', re.IGNORECASE)
            match = id_pattern.search(url)
            
            if match:
                try:
                    orig_id = match.group(2)
                    # Try to access with a different ID
                    modified_id = str(int(orig_id) + 1)
                    modified_url = url.replace(f"{match.group(1)}{match.group(2)}", f"{match.group(1)}{modified_id}")
                    
                    response = unauth_session.get(modified_url, timeout=10)
                    
                    # If successful, might be an IDOR vulnerability
                    if response.status_code == 200 and len(response.content) > 100:
                        vulnerable_endpoints.append({
                            'url': modified_url,
                            'type': 'IDOR',
                            'status_code': response.status_code,
                            'details': f'Successfully accessed resource by changing ID from {orig_id} to {modified_id}'
                        })
                        logger.warning(f"Potential IDOR at: {modified_url}")
                
                except Exception as e:
                    logger.error(f"Error testing IDOR at {url}: {str(e)}")
        
        # Generate report
        self._generate_report(report_manager, vulnerable_endpoints)
        return vulnerable_endpoints
        
    def _generate_report(self, report_manager, vulnerabilities):
        """Generate report of broken access control vulnerabilities"""
        # Ensure the scans directory exists
        output_dir = "./scans"
        os.makedirs(output_dir, exist_ok=True)
        
        # Start building the findings content with login information
        findings = "# Broken Access Control Scan Report\n\n"
        
        # Add authentication information
        findings += "## Authentication Information\n\n"
        findings += "### Login Attempts\n\n"
        
        if self.login_attempts:
            for i, attempt in enumerate(self.login_attempts, 1):
                findings += f"**Attempt {i}:**\n"
                findings += f"- Username: `{attempt.get('username', 'N/A')}`\n"
                findings += f"- Password: `{attempt.get('password', 'N/A')}`\n"
                findings += f"- Status: {attempt.get('status', 'N/A')}\n"
                if 'timestamp' in attempt:
                    findings += f"- Time: {attempt.get('timestamp')}\n"
                if 'reason' in attempt:
                    findings += f"- Details: {attempt.get('reason')}\n"
                findings += "\n"
        else:
            findings += "No login attempts were made.\n\n"
        
        # Add successful login details if available
        if self.successful_login:
            findings += "### Successful Authentication\n\n"
            findings += f"- **Username:** `{self.successful_login.get('username')}`\n"
            findings += f"- **Password:** `{self.successful_login.get('password')}`\n"
            findings += f"- **Form Action:** {self.successful_login.get('form_action')}\n"
            findings += f"- **Method:** {self.successful_login.get('method').upper()}\n"
            findings += f"- **Time:** {self.successful_login.get('timestamp')}\n\n"
        else:
            findings += "### Authentication Status\n\n"
            findings += "No successful logins were achieved.\n\n"
        
        # Add vulnerability information
        findings += "## Vulnerability Scan Results\n\n"
        
        if not vulnerabilities:
            findings += "No broken access control vulnerabilities detected.\n\n"
        else:
            findings += f"**{len(vulnerabilities)} broken access control vulnerabilities detected:**\n\n"
            for i, vuln in enumerate(vulnerabilities, 1):
                findings += f"### {i}. {vuln['type']} Vulnerability\n"
                findings += f"- **URL**: {vuln['url']}\n"
                findings += f"- **Status Code**: {vuln['status_code']}\n"
                findings += f"- **Details**: {vuln['details']}\n\n"
        
        # Add recommendations        
        findings += "\n## Recommendations\n\n"
        findings += "1. Implement proper access control checks on all sensitive resources\n"
        findings += "2. Use authorization frameworks or libraries that enforce role-based access control\n"
        findings += "3. Deny access by default and require explicit grants\n"
        findings += "4. Don't rely on obscurity or hiding of endpoints for security\n"
        findings += "5. Implement re-authentication for sensitive operations\n"
        findings += "6. Use random, unpredictable values for resource identifiers instead of sequential IDs\n"
        findings += "7. Ensure all API endpoints have proper authorization checks\n"
        findings += "8. Implement strict password policies and account lockout mechanisms\n"
        findings += "9. Monitor and log access control failures\n"
        
        # Create the PDF report file
        logger.info("Creating Broken Access Control scan report")
        
        try:
            # Based on the available methods in your ReportManager, we need to use:
            # - append_to_pdf to add content
            # Your ReportManager already has an output_pdf_path property
            
            # Create the individual report PDF
            from fpdf import FPDF
            pdf = FPDF()
            pdf.add_page()
            pdf.set_font("Arial", size=12)
            
            # Add title
            pdf.set_font("Arial", 'B', 16)
            pdf.cell(200, 10, "Broken Access Control Scan Report", ln=True, align='C')
            pdf.ln(10)
            
            # Add content
            pdf.set_font("Arial", size=12)
            
            # Split the findings into paragraphs and add to PDF
            paragraphs = findings.split('\n\n')
            for para in paragraphs:
                if para.startswith('### '):  # Subsection header
                    pdf.set_font("Arial", 'B', 14)
                    pdf.multi_cell(0, 10, para.replace('### ', '').strip())
                    pdf.set_font("Arial", size=12)
                elif para.startswith('## '):  # Section header
                    pdf.set_font("Arial", 'B', 15)
                    pdf.multi_cell(0, 10, para.replace('## ', '').strip())
                    pdf.set_font("Arial", size=12)
                elif para.startswith('# '):  # Main header
                    pdf.set_font("Arial", 'B', 16)
                    pdf.multi_cell(0, 10, para.replace('# ', '').strip())
                    pdf.set_font("Arial", size=12)
                else:
                    # Handle bullet points
                    for line in para.split('\n'):
                        if line.startswith('- '):
                            pdf.set_x(20)  # Indent
                            pdf.multi_cell(0, 10, line[2:])  # Remove the bullet point
                        elif line.startswith('**'):  # Bold text
                            pdf.set_font("Arial", 'B', 12)
                            pdf.multi_cell(0, 10, line.replace('**', ''))
                            pdf.set_font("Arial", size=12)
                        else:
                            pdf.multi_cell(0, 10, line)
                
                pdf.ln(5)
            
            # Save the individual report
            individual_pdf_path = os.path.join(output_dir, "broken access control_scan_report.pdf")
            pdf.output(individual_pdf_path)
            logger.info(f"Individual report saved to: {individual_pdf_path}")

            # Try to contribute to the consolidated report if this method is available
            if hasattr(report_manager, 'append_to_pdf'):
                logger.info("Adding findings to consolidated report")
                # Use the existing method in your ReportManager
                report_manager.append_to_pdf(findings)
                logger.info("Added to consolidated report successfully")
        
        except Exception as e:
            logger.error(f"Error generating PDF report: {str(e)}")
            # Fallback to text file
            try:
                text_file_path = os.path.join(output_dir, "brokenaccess_findings.txt")
                with open(text_file_path, "w") as f:
                    f.write(findings)
                logger.info(f"Findings saved to text file: {text_file_path}")
            except Exception as write_err:
                logger.error(f"Failed to write findings to file: {write_err}")
        
        # Always log the findings
        logger.info("Scan findings summary:")
        logger.info(findings[:500] + "..." if len(findings) > 500 else findings)

def run_broken_access_scan(report_manager, target_url, scan_depth=1):
    """Main function to run the broken access control scan"""
    try:
        scanner = BrokenAccessScanner()
        
        # Step 1: Discover endpoints and forms
        scanner.discover_endpoints(target_url, scan_depth)
        
        # Step 2: Try to login
        login_success = scanner.attempt_login()
        
        # Step 3: Identify potentially restricted resources
        scanner.identify_restricted_resources(target_url, scan_depth)
        
        # Step 4: Test for broken access control
        vulnerabilities = scanner.test_broken_access(report_manager)
        
        # Return results summary
        num_vulns = len(vulnerabilities)
        login_info = ""
        if scanner.successful_login:
            login_info = f" (Successfully logged in as '{scanner.successful_login.get('username')}')"
            
        if num_vulns == 0:
            return f"No broken access control vulnerabilities detected.{login_info}"
        else:
            return f"Detected {num_vulns} potential broken access control vulnerabilities.{login_info} See PDF report for details."
    
    except Exception as e:
        logger.error(f"Error running broken access scan: {str(e)}")
        return f"Error running broken access scan: {str(e)}"