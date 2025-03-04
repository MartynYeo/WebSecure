import httpx
from bs4 import BeautifulSoup
from urllib.parse import urljoin, urlparse
from pathlib import Path
import asyncio
import time
import urllib.robotparser  # For robots.txt


class WebCrawler:
    def __init__(self, timeout=10, delay=1):  # Add delay for rate limiting
        self.timeout = timeout
        self.delay = delay  # Delay between requests (in seconds)
        self.visited_urls = set()
        self.robot_parsers = {}  # Cache robot parsers

    async def crawl(self, start_url: str, max_depth: int = 2) -> dict:
        """Crawls a website and extracts code."""
        self.start_url = start_url # Store it
        return await self._crawl_recursive(start_url, max_depth, 0)

    async def _crawl_recursive(self, url: str, max_depth: int, current_depth: int) -> dict:
        """Recursively crawls a website (private helper)."""

        if current_depth > max_depth or url in self.visited_urls:
            return {}

        if not self._can_fetch(url):
            print(f"Skipping (robots.txt): {url}")
            return {}

        self.visited_urls.add(url)
        print(f"Crawling: {url}")

        try:
            async with httpx.AsyncClient(timeout=self.timeout, follow_redirects=True) as client:
                response = await client.get(url)
                response.raise_for_status()

            await asyncio.sleep(self.delay)  # Rate limiting

            content_type = response.headers.get("content-type", "")
            scraped_data = {}

            if "text/html" in content_type:
                soup = BeautifulSoup(response.text, 'html.parser')
                scraped_data[url] = response.text

                # Extract and follow links
                for link in soup.find_all('a', href=True):
                    absolute_url = urljoin(url, link['href'])
                    if urlparse(absolute_url).netloc == urlparse(self.start_url).netloc:
                        scraped_data.update(await self._crawl_recursive(absolute_url, max_depth, current_depth + 1))

                # Extract inline JavaScript
                for script in soup.find_all('script', src=False):
                    if script.string:
                        scraped_data[f"{url}#inline_script_{len(scraped_data)}"] = script.string

                # Extract linked JavaScript files
                for script in soup.find_all("script", src=True):
                    script_url = urljoin(url, script["src"])
                    if urlparse(script_url).netloc == urlparse(self.start_url).netloc:
                        script_content = await self._fetch_resource(script_url)
                        if script_content:
                            scraped_data[script_url] = script_content

                # Extract linked CSS files
                for link in soup.find_all("link", rel="stylesheet"):
                    css_url = urljoin(url, link["href"])
                    if urlparse(css_url).netloc == urlparse(self.start_url).netloc:
                        css_content = await self._fetch_resource(css_url)
                        if css_content:
                            scraped_data[css_url] = css_content
                # Basic Form Interaction (VERY simplified)
                for form in soup.find_all("form"):
                  form_data = await self._process_form(url, form)
                  if form_data:
                    scraped_data.update(form_data)


            elif "application/javascript" in content_type or "text/javascript" in content_type:
                scraped_data[url] = response.text

            return scraped_data


        except httpx.RequestError as e:
            print(f"Request error: {e}")
            return {}
        except httpx.HTTPStatusError as e:
            print(f"HTTP error ({e.response.status_code}): {e}")
            return {}
        except Exception as e:
            print(f"An error occurred: {e}")
            return {}


    async def _fetch_resource(self, url: str) -> str | None:
        """Fetches a single resource (JS, CSS)."""
        if not self._can_fetch(url):
            print(f"Skipping (robots.txt): {url}")
            return None

        try:
            async with httpx.AsyncClient(timeout=self.timeout, follow_redirects=True) as client:
                response = await client.get(url)
                response.raise_for_status()
                await asyncio.sleep(self.delay)  # Rate limiting
                return response.text
        except httpx.RequestError as e:
            print(f"Request error: {e}")
            return None
        except httpx.HTTPStatusError as e:
            print(f"HTTP error ({e.response.status_code}): {e}")
            return None
        except Exception as e:
          print(f"Fetch Resource Error: {e}")
          return None

    def _can_fetch(self, url: str) -> bool:
        """Checks robots.txt for permission to fetch a URL."""
        parsed_url = urlparse(url)
        base_url = f"{parsed_url.scheme}://{parsed_url.netloc}"

        if base_url not in self.robot_parsers:
            rp = urllib.robotparser.RobotFileParser()
            try:
                # Fetch and parse robots.txt
                async with httpx.AsyncClient() as client:  # Use async client
                    response = await client.get(urljoin(base_url, "/robots.txt"))
                    if response.status_code == 200:
                        rp.parse(response.text.splitlines())
                    else:
                        # If robots.txt is not found, assume it's okay to crawl
                        rp.parse(["User-agent: *", "Allow: /"])
            except Exception as e:
                print(f"Error fetching robots.txt: {e}")
                # If there's an error, assume it's okay (be cautious)
                rp.parse(["User-agent: *", "Allow: /"])

            self.robot_parsers[base_url] = rp

        return self.robot_parsers[base_url].can_fetch("*", url)

    async def _process_form(self, url:str, form) -> dict: # New
      """Processes a form and simulates submission (basic example)"""
      form_data = {}
      action = form.get("action")
      method = form.get("method", "get").lower() # Default to GET
      absolute_action_url = urljoin(url, action) if action else url

      # Extract input fields
      inputs = form.find_all(["input", "textarea", "select"])
      form_values = {}
      for input_field in inputs:
        name = input_field.get("name")
        if name:
          # Provide default values (THIS IS WHERE YOU'D DO FUZZING)
          if input_field.name == "textarea":
            form_values[name] = "Test input"
          elif input_field.name == "select":
            # Get the first option if available
            option = input_field.find("option")
            form_values[name] = option.get("value", "") if option else ""
          elif input_field.get("type") == "checkbox":
            form_values[name] = "on" # Simple checkbox handling
          elif input_field.get("type") == "radio":
            # Handle radio buttons (select only if it's in the form)
            if input_field.get("checked") is not None:
              form_values[name] = input_field.get("value", "on")

          else: # text, email, password, etc.
            form_values[name] = "testinput"

      # Submit the form (using httpx)
      try:
        async with httpx.AsyncClient(timeout=self.timeout, follow_redirects=True) as client:
          if method == "post":
            response = await client.post(absolute_action_url, data=form_values)
          else: # Assume GET
            response = await client.get(absolute_action_url, params=form_values)
          response.raise_for_status()
          await asyncio.sleep(self.delay)
          form_data[f"{absolute_action_url}#form_response"] = response.text
          return form_data

      except Exception as e:
        print(f"Form submission error: {e}")
        return {}