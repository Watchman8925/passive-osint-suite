"""
Pattern Matching and Security Analysis Module
Provides comprehensive pattern matching using Yara and custom security analysis
"""

import os
import subprocess
import logging
from typing import Dict, List, Optional, Any
import re

logger = logging.getLogger(__name__)


class PatternMatchingEngine:
    """Pattern matching engine using Yara and custom security analysis"""

    def __init__(self):
        self.tools = {
            "yara": self._check_tool("yara"),
            "yarac": self._check_tool("yarac"),
            "strings": self._check_tool("strings"),
            "grep": self._check_tool("grep"),
        }

        # Common security patterns
        self.security_patterns = {
            "api_keys": [
                r'api[_-]?key[_-]?id["\s]*[:=]\s*["\']([A-Za-z0-9\-_\.]{20,})["\']',
                r'api[_-]?key["\s]*[:=]\s*["\']([A-Za-z0-9\-_\.]{20,})["\']',
                r'API[_-]?KEY["\s]*[:=]\s*["\']([A-Za-z0-9\-_\.]{20,})["\']',
            ],
            "secret_keys": [
                r'secret[_-]?key["\s]*[:=]\s*["\']([A-Za-z0-9\-_\.]{20,})["\']',
                r'SECRET[_-]?KEY["\s]*[:=]\s*["\']([A-Za-z0-9\-_\.]{20,})["\']',
            ],
            "tokens": [
                r'token["\s]*[:=]\s*["\']([A-Za-z0-9\-_\.]{20,})["\']',
                r"Bearer\s+([A-Za-z0-9\-_\.]{20,})",
                r"Authorization:\s*Bearer\s+([A-Za-z0-9\-_\.]{20,})",
            ],
            "passwords": [
                r'password["\s]*[:=]\s*["\']([^"\']{3,})["\']',
                r'PASSWORD["\s]*[:=]\s*["\']([^"\']{3,})["\']',
                r'passwd["\s]*[:=]\s*["\']([^"\']{3,})["\']',
            ],
            "private_keys": [
                r"-----BEGIN\s+(RSA\s+)?PRIVATE\s+KEY-----",
                r"-----BEGIN\s+EC\s+PRIVATE\s+KEY-----",
                r"-----BEGIN\s+OPENSSH\s+PRIVATE\s+KEY-----",
            ],
            "aws_credentials": [
                r'AWS_ACCESS_KEY_ID["\s]*[:=]\s*["\']([A-Z0-9]{20})["\']',
                r'AWS_SECRET_ACCESS_KEY["\s]*[:=]\s*["\']([A-Za-z0-9/\+=]{40})["\']',
            ],
            "database_urls": [
                r'(mongodb|mysql|postgresql)://[^"\'\s]+',
                r'jdbc:[^"\'\s]+',
                r'DATABASE_URL["\s]*[:=]\s*["\']([^"\']+)["\']',
            ],
        }

    def _check_tool(self, tool_name: str) -> bool:
        """Check if a tool is available"""
        try:
            subprocess.run(
                [tool_name, "--help" if tool_name != "strings" else "--help"],
                capture_output=True,
                timeout=5,
            )
            return True
        except (
            subprocess.TimeoutExpired,
            FileNotFoundError,
            subprocess.CalledProcessError,
        ):
            return False

    def yara_scan_file(
        self, file_path: str, rules_path: Optional[str] = None
    ) -> Dict[str, Any]:
        """
        Scan a file with Yara rules

        Args:
            file_path: Path to the file to scan
            rules_path: Path to Yara rules file (optional)

        Returns:
            Dictionary containing Yara scan results
        """
        if not self.tools["yara"]:
            return {"error": "Yara not available"}

        if not os.path.exists(file_path):
            return {"error": f"File not found: {file_path}"}

        try:
            cmd = ["yara", "-f", "-w"]  # Fast mode, no warnings

            if rules_path and os.path.exists(rules_path):
                cmd.extend([rules_path, file_path])
            else:
                # Use default rules if available
                default_rules = "/usr/share/yara/rules"
                if os.path.exists(default_rules):
                    cmd.extend(["-r", default_rules, file_path])
                else:
                    return {"error": "No Yara rules available"}

            result = subprocess.run(cmd, capture_output=True, text=True, timeout=120)

            matches = []
            if result.returncode == 0 and result.stdout:
                lines = result.stdout.strip().split("\n")
                for line in lines:
                    if line.strip():
                        matches.append(line.strip())

            return {
                "success": True,
                "file_path": file_path,
                "matches": matches,
                "match_count": len(matches),
                "rules_used": rules_path or "default",
            }

        except subprocess.TimeoutExpired:
            return {"error": "Yara scan timeout"}

    def yara_scan_directory(
        self, directory_path: str, rules_path: Optional[str] = None
    ) -> Dict[str, Any]:
        """
        Scan all files in a directory with Yara

        Args:
            directory_path: Path to the directory to scan
            rules_path: Path to Yara rules file (optional)

        Returns:
            Dictionary containing batch Yara scan results
        """
        if not os.path.exists(directory_path):
            return {"error": f"Directory not found: {directory_path}"}

        results: Dict[str, Any] = {
            "directory": directory_path,
            "files_scanned": 0,
            "total_matches": 0,
            "results": [],
        }

        for root, dirs, files in os.walk(directory_path):
            for file in files:
                file_path = os.path.join(root, file)

                # Skip very large files
                try:
                    if os.path.getsize(file_path) > 100 * 1024 * 1024:  # 100MB
                        continue
                except OSError:
                    continue

                scan_result = self.yara_scan_file(file_path, rules_path)
                if scan_result.get("success") and scan_result.get("match_count", 0) > 0:
                    results["results"].append(scan_result)
                    results["total_matches"] += scan_result["match_count"]

                results["files_scanned"] += 1

                # Limit to prevent overload
                if results["files_scanned"] >= 1000:
                    break

        return results

    def extract_strings_from_file(
        self, file_path: str, min_length: int = 4
    ) -> Dict[str, Any]:
        """
        Extract strings from binary files

        Args:
            file_path: Path to the file to analyze
            min_length: Minimum string length

        Returns:
            Dictionary containing extracted strings
        """
        if not self.tools["strings"]:
            return {"error": "strings tool not available"}

        if not os.path.exists(file_path):
            return {"error": f"File not found: {file_path}"}

        try:
            result = subprocess.run(
                ["strings", "-n", str(min_length), file_path],
                capture_output=True,
                text=True,
                timeout=60,
            )

            strings = []
            if result.returncode == 0 and result.stdout:
                lines = result.stdout.strip().split("\n")
                strings = [line.strip() for line in lines if line.strip()]

            return {
                "success": True,
                "file_path": file_path,
                "strings_extracted": len(strings),
                "strings": strings[:1000],  # Limit for performance
            }

        except subprocess.TimeoutExpired:
            return {"error": "String extraction timeout"}

    def find_secrets_in_text(self, text: str) -> Dict[str, Any]:
        """
        Find secrets and sensitive data in text using regex patterns

        Args:
            text: Text to analyze

        Returns:
            Dictionary containing found secrets
        """
        findings: Dict[str, Any] = {"total_findings": 0, "categories": {}}

        for category, patterns in self.security_patterns.items():
            category_findings = []

            for pattern in patterns:
                matches = re.findall(pattern, text, re.IGNORECASE | re.MULTILINE)
                if matches:
                    # Clean up matches (remove duplicates, limit length)
                    unique_matches = list(set(matches))
                    clean_matches = []
                    for match in unique_matches:
                        if isinstance(match, tuple):
                            match = "".join(match)
                        if (
                            len(match) > 10 and len(match) < 200
                        ):  # Reasonable length limits
                            clean_matches.append(match)

                    if clean_matches:
                        category_findings.extend(clean_matches)

            if category_findings:
                findings["categories"][category] = {
                    "count": len(category_findings),
                    "findings": category_findings[:50],  # Limit per category
                }
                findings["total_findings"] += len(category_findings)

        return findings

    def analyze_javascript_file(self, js_content: str) -> Dict[str, Any]:
        """
        Analyze JavaScript content for endpoints and secrets (LinkFinder-style)

        Args:
            js_content: JavaScript content to analyze

        Returns:
            Dictionary containing JavaScript analysis results
        """
        analysis: Dict[str, Any] = {
            "endpoints": [],
            "secrets": {},
            "functions": [],
            "comments": [],
        }

        # Find URLs/endpoints
        url_patterns = [
            r'["\']((?:https?://|/)[^"\']+)["\']',
            r'["\'](\./[^"\']+)["\']',
            r'["\'](\.\./[^"\']+)["\']',
            r'["\'](/api/[^"\']+)["\']',
            r'["\'](/v[0-9]+/[^"\']+)["\']',
        ]

        for pattern in url_patterns:
            matches = re.findall(pattern, js_content)
            analysis["endpoints"].extend(matches)

        # Remove duplicates
        analysis["endpoints"] = list(set(analysis["endpoints"]))

        # Find secrets in JS
        analysis["secrets"] = self.find_secrets_in_text(js_content)

        # Find function definitions
        func_pattern = r"function\s+([a-zA-Z_$][a-zA-Z0-9_$]*)\s*\("
        functions = re.findall(func_pattern, js_content)
        analysis["functions"] = list(set(functions))

        # Find comments
        comment_patterns = [
            r"/\*[\s\S]*?\*/",  # Multi-line comments
            r"//.*$",  # Single-line comments
        ]

        for pattern in comment_patterns:
            comments = re.findall(pattern, js_content, re.MULTILINE)
            analysis["comments"].extend(comments)

        return analysis

    def analyze_webpage_content(self, html_content: str) -> Dict[str, Any]:
        """
        Analyze HTML content for secrets and endpoints

        Args:
            html_content: HTML content to analyze

        Returns:
            Dictionary containing webpage analysis results
        """
        analysis: Dict[str, Any] = {
            "secrets": {},
            "endpoints": [],
            "forms": [],
            "scripts": [],
            "links": [],
        }

        # Find secrets
        analysis["secrets"] = self.find_secrets_in_text(html_content)

        # Find endpoints in HTML
        endpoint_patterns = [
            r'href=["\']([^"\']+)["\']',
            r'src=["\']([^"\']+)["\']',
            r'action=["\']([^"\']+)["\']',
            r'data-url=["\']([^"\']+)["\']',
        ]

        for pattern in endpoint_patterns:
            matches = re.findall(pattern, html_content, re.IGNORECASE)
            analysis["endpoints"].extend(matches)

        # Find forms
        form_pattern = r"<form[^>]*>.*?</form>"
        forms = re.findall(form_pattern, html_content, re.DOTALL | re.IGNORECASE)
        analysis["forms"] = forms

        # Find script sources
        script_pattern = r'<script[^>]*src=["\']([^"\']+)["\'][^>]*>'
        scripts = re.findall(script_pattern, html_content, re.IGNORECASE)
        analysis["scripts"] = scripts

        # Find links
        link_pattern = r'<a[^>]*href=["\']([^"\']+)["\'][^>]*>'
        links = re.findall(link_pattern, html_content, re.IGNORECASE)
        analysis["links"] = links

        # Remove duplicates
        analysis["endpoints"] = list(set(analysis["endpoints"]))

        return analysis

    def grep_search_patterns(
        self, search_path: str, patterns: List[str]
    ) -> Dict[str, Any]:
        """
        Search for patterns in files using grep

        Args:
            search_path: Path to search in
            patterns: List of regex patterns to search for

        Returns:
            Dictionary containing grep search results
        """
        if not self.tools["grep"]:
            return {"error": "grep not available"}

        if not os.path.exists(search_path):
            return {"error": f"Search path not found: {search_path}"}

        results: Dict[str, Any] = {
            "search_path": search_path,
            "patterns_searched": patterns,
            "results": {},
        }

        for pattern in patterns:
            try:
                result = subprocess.run(
                    ["grep", "-r", "-n", "-i", pattern, search_path],
                    capture_output=True,
                    text=True,
                    timeout=120,
                )

                matches = []
                if (
                    result.returncode in [0, 1] and result.stdout
                ):  # 0 = matches, 1 = no matches
                    lines = result.stdout.strip().split("\n")
                    for line in lines:
                        if line.strip():
                            matches.append(line.strip())

                results["results"][pattern] = {
                    "success": True,
                    "matches": matches,
                    "count": len(matches),
                }

            except subprocess.TimeoutExpired:
                results["results"][pattern] = {"error": "Search timeout"}

        return results

    def comprehensive_security_analysis(self, target_path: str) -> Dict[str, Any]:
        """
        Perform comprehensive security analysis on a file or directory

        Args:
            target_path: Path to file or directory to analyze

        Returns:
            Dictionary containing comprehensive security analysis
        """
        analysis: Dict[str, Any] = {
            "target": target_path,
            "timestamp": None,  # Would be set by caller
            "analyses": {},
        }

        if os.path.isfile(target_path):
            # File analysis
            file_ext = os.path.splitext(target_path)[1].lower()

            # Yara scan
            analysis["analyses"]["yara_scan"] = self.yara_scan_file(target_path)

            # String extraction for binaries
            if file_ext in [".exe", ".dll", ".bin", ".so", ""]:
                analysis["analyses"]["strings"] = self.extract_strings_from_file(
                    target_path
                )

            # Content analysis for text files
            try:
                with open(target_path, "r", encoding="utf-8", errors="ignore") as f:
                    content = f.read(1024 * 1024)  # Limit to 1MB

                    if file_ext in [".js", ".jsx", ".ts", ".tsx"]:
                        analysis["analyses"]["javascript_analysis"] = (
                            self.analyze_javascript_file(content)
                        )
                    elif file_ext in [".html", ".htm"]:
                        analysis["analyses"]["webpage_analysis"] = (
                            self.analyze_webpage_content(content)
                        )
                    else:
                        analysis["analyses"]["secrets_scan"] = (
                            self.find_secrets_in_text(content)
                        )

            except (UnicodeDecodeError, IOError):
                analysis["analyses"]["content_analysis"] = {
                    "error": "Could not read file content"
                }

        elif os.path.isdir(target_path):
            # Directory analysis
            analysis["analyses"]["yara_directory_scan"] = self.yara_scan_directory(
                target_path
            )

            # Search for common sensitive patterns
            sensitive_patterns = [
                "password.*=",
                "api.*key.*=",
                "secret.*=",
                "token.*=",
                "Bearer.*",
            ]
            analysis["analyses"]["sensitive_pattern_search"] = (
                self.grep_search_patterns(target_path, sensitive_patterns)
            )

        return analysis
