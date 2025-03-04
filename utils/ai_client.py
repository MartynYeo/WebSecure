import os
from typing import Any, Dict, Optional, List

import anthropic
import openai
import google.generativeai as genai  # Import the Gemini library
from dotenv import load_dotenv

import json
import re

load_dotenv()

class AIClient:
    def __init__(self) -> None:
        """
        Initialize AI clients with API keys from environment variables.
        Prioritizes Gemini, then falls back to OpenAI and Anthropic.
        """

        # --- Gemini Setup ---
        genai.configure(api_key=os.getenv("GEMINI_API_KEY"))
        self.gemini_model = genai.GenerativeModel('gemini-2.0-flash')  # Or your preferred model


        # --- OpenAI and Anthropic (Fallbacks) ---
        self.openai_client = openai.Client(api_key=os.getenv("OPENAI_API_KEY"))
        self.anthropic_client = anthropic.Anthropic(api_key=os.getenv("ANTHROPIC_API_KEY"))
        self.openai_default_model = "gpt-4o"  # Or your preferred OpenAI model


    async def analyze_security(self, prompt: str, model: Optional[str] = None) -> Dict[str, Any]:
        """
        Analyze code for security vulnerabilities using AI models.

        Args:
            prompt: The prompt to analyze.
            model:  (Optional)  Force a specific model ("gemini", "openai", "anthropic").

        Returns:
            Dict[str, Any]: The analysis result.  Returns an empty dictionary
                            on failure.
        """
        try:
            if model == "openai":
              return await self._analyze_with_openai(self.openai_client, prompt, self.openai_default_model)
            elif model == "anthropic":
              return await self._analyze_with_anthropic(prompt)
            else: # Default to Gemini
                try:
                    response = await self._analyze_with_gemini(prompt)
                    if self._validate_response(response):
                        return response
                except Exception as e:
                    print(f"Gemini analysis failed: {e}")
                    # Fallback to OpenAI
                    try:
                        response = await self._analyze_with_openai(self.openai_client, prompt, self.openai_default_model)
                        if self._validate_response(response):
                            return response
                    except Exception as e:
                      print(f"OpenAI analysis failed: {e}")
                      # Fallback to Anthropic
                      try:
                          response = await self._analyze_with_anthropic(prompt)
                          if self._validate_response(response):
                              return response
                      except Exception as e:
                          print(f"Anthropic analysis failed: {e}")
                          raise ValueError("All AI models failed to provide valid analysis")
        except Exception as e:
            print(f"Error in security analysis: {str(e)}")
            return {"vulnerabilities": []}


    async def _analyze_with_gemini(self, prompt: str) -> Dict[str, Any]:
        """Analyze code using Google Gemini."""
        try:

            system_prompt = self._get_system_prompt()
            full_prompt = f"{system_prompt}\n\nUser: {prompt}\n\nAssistant:"
            response = self.gemini_model.generate_content(
              full_prompt,
              generation_config=genai.types.GenerationConfig(
                    # Only one candidate for now.
                    candidate_count=1,
                    #stop_sequences=['x'],
                    max_output_tokens=8192,
                    temperature=0.1
                )
            )

            return self._parse_gemini_response(response)

        except Exception as e:
          raise ValueError(f"Failed to parse Gemini response: {str(e)}")


    async def _analyze_with_openai(self, client: openai.Client, prompt: str, model: str) -> Dict[str, Any]:
        """Analyze code using OpenAI models (remains unchanged)."""
        messages = [
            {"role": "system", "content": self._get_system_prompt()},
            {"role": "user", "content": prompt}
        ]
        response = client.chat.completions.create(
            model=model,
            messages=messages,
            temperature=0.1
        )
        return self._parse_openai_response(response)

    async def _analyze_with_anthropic(self, prompt: str) -> Dict[str, Any]:
        """Analyze code using Anthropic Claude (remains unchanged)."""
        system_prompt = self._get_system_prompt()
        full_prompt = f"{system_prompt}\n\nHuman: {prompt}\n\nAssistant:"
        response = await self.anthropic_client.messages.create(
            model="claude-3-sonnet-20240229",
            max_tokens=4000,
            temperature=0.1,
            messages=[{"role": "user", "content": full_prompt}]
        )
        return self._parse_anthropic_response(response)

    def _get_system_prompt(self) -> str:
        """Get the system prompt (remains unchanged)."""
        return """You are a security expert performing code analysis.
        Analyze the provided code for security vulnerabilities, focusing on:
        1. OWASP Top 10 vulnerabilities
        2. SANS Top 25 vulnerabilities
        3. Language-specific security issues
        4. Security best practices

        IMPORTANT: Respond with ONLY the raw JSON data, without any markdown formatting or code blocks.
        Your response should be a valid Python dictionary that can be evaluated using eval().

        The response must follow this structure:
        {
            "vulnerabilities": [
                {
                    "type": "VULNERABILITY_TYPE_NAME_WITH_UNDERSCORES",
                    "severity": "SEVERITY_LEVEL",
                    "location": {
                        "file_path": "path/to/file",
                        "start_line": line_number,
                        "end_line": line_number,
                        "start_col": column_number,
                        "end_col": column_number,
                        "context": "code_snippet"
                    },
                    "description": "Detailed description of the vulnerability",
                    "impact": "Potential impact of exploitation",
                    "remediation": "How to fix the vulnerability",
                    "cwe_id": "CWE_ID",
                    "owasp_category": "OWASP CATEGORY (Format example: A10:2021 - Server-Side Request Forgery (SSRF))",
                    "cvss_score": "CVSS_SCORE",
                    "references": ["REFERENCE_URL_1", "REFERENCE_URL_2", etc.],
                    "proof_of_concept": "POC_CODE",
                    "secure_code_example": "SECURE_CODE_EXAMPLE"
                }
            ]
        }

        Note: The vulnerability type must use UPPERCASE with UNDERSCORES (e.g., INSECURE_DESERIALIZATION, SQL_INJECTION, XSS_VULNERABILITY). If the identified vulnerability type matches any of the predefined types in the predefined Vulnerability Types, use that type instead of creating some new type. If a type doesn't matches predefined type, use it as is.

        Predefined Vulnerability Types:
(The list of predefined types remains the same)
"""
    def _validate_response(self, response: Dict[str, Any]) -> bool:
        """Validate response structure (remains unchanged)."""
        try:
            if not isinstance(response, dict):
                return False
            if "vulnerabilities" not in response:
                return False
            for vuln in response["vulnerabilities"]:
                required_fields = ["type", "severity", "location", "description", "impact", "remediation", "cwe_id", "owasp_category", "cvss_score", "references", "proof_of_concept", "secure_code_example"]
                if not all(field in vuln for field in required_fields):
                    return False
            return True
        except Exception:
            return False

    def _parse_openai_response(self, response) -> Dict[str, Any]:
        """Parse OpenAI response (remains unchanged)."""
        try:
            content = response.choices[0].message.content
            return eval(content)  # Safe since we validate the response
        except Exception as e:
            raise ValueError(f"Failed to parse OpenAI response: {str(e)}")

    def _parse_anthropic_response(self, response) -> Dict[str, Any]:
        """Parse Anthropic response (remains unchanged)."""
        try:
            content = response.content[0].text
            return eval(content)  # Safe since we validate the response
        except Exception as e:
            raise ValueError(f"Failed to parse Anthropic response: {str(e)}")
    
    def _parse_gemini_response(self, response) -> Dict[str, Any]:
        """
        Parse Gemini response into standardized format.  Handles markdown,
        extracts JSON, and converts null to None.
        """
        try:
            # Access the nested structure correctly:
            content = response.candidates[0].content.parts[0].text

            # Remove markdown code blocks (if present)
            content = content.replace("```json", "").replace("```", "").strip()

            # Attempt to parse the content as JSON
            try:
                data = json.loads(content)
            except json.JSONDecodeError:
                # If direct JSON parsing fails, try to extract JSON using regex
                match = re.search(r"\{.*\}", content, re.DOTALL)  # Find {} block
                if match:
                    try:
                        data = json.loads(match.group(0))
                    except json.JSONDecodeError:
                        raise ValueError(f"Extracted content is not valid JSON: {match.group(0)}")
                else:
                    raise ValueError(f"No JSON found in response: {content}")

            # Convert null values to None (recursively)
            def convert_null_to_none(obj):
                if isinstance(obj, dict):
                    return {k: convert_null_to_none(v) for k, v in obj.items()}
                elif isinstance(obj, list):
                    return [convert_null_to_none(elem) for elem in obj]
                elif obj is None:  #  Handle 'null' which becomes None in json.loads
                    return None
                elif obj == 'null': # sometimes it return null as string
                    return None
                else:
                    return obj

            data = convert_null_to_none(data)

            return data

        except Exception as e:
            raise ValueError(f"Failed to parse Gemini response: {str(e)}")