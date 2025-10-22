"""Pattern matching and security analysis utilities."""

from __future__ import annotations

import logging
import os
import re
import subprocess
import threading
from typing import Any, Dict, Iterable, List, Optional, Sequence

logger = logging.getLogger(__name__)


class PatternMatchingEngine:
    """Pattern matching engine using Yara and custom security analysis."""

    DEFAULT_MAX_FILES = 1000
    DEFAULT_MAX_FILE_SIZE = 100 * 1024 * 1024

    def __init__(
        self,
        *,
        max_files: int = DEFAULT_MAX_FILES,
        max_file_size: int = DEFAULT_MAX_FILE_SIZE,
    ) -> None:
        self.max_files = max_files
        self.max_file_size = max_file_size
        self._tool_cache: Dict[str, bool] = {}

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

    @staticmethod
    def _check_tool(tool_name: str) -> bool:
        """Check if a tool is available."""

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

    def _tool_available(self, tool_name: str) -> bool:
        """Determine lazily whether a tool is available on the system."""

        if tool_name not in self._tool_cache:
            self._tool_cache[tool_name] = self._check_tool(tool_name)
        return self._tool_cache[tool_name]

    @staticmethod
    def _normalise_paths(paths: Optional[Sequence[str]]) -> Optional[Iterable[str]]:
        if not paths:
            return None
        return {os.path.realpath(path) for path in paths}

    @staticmethod
    def _should_skip_path(
        file_path: str,
        allowed: Optional[Iterable[str]],
        denied: Optional[Iterable[str]],
    ) -> bool:
        real_path = os.path.realpath(file_path)
        if denied and any(real_path.startswith(prefix) for prefix in denied):
            return True
        if allowed and not any(real_path.startswith(prefix) for prefix in allowed):
            return True
        return False

    def yara_scan_file(
        self, file_path: str, rules_path: Optional[str] = None
    ) -> Dict[str, Any]:
        """Scan a file with Yara rules."""

        if not self._tool_available("yara"):
            return {"error": "Yara not available"}

        if not os.path.exists(file_path):
            return {"error": f"File not found: {file_path}"}

        try:
            cmd = ["yara", "-f", "-w"]  # Fast mode, no warnings

            if rules_path and os.path.exists(rules_path):
                cmd.extend([rules_path, file_path])
            else:
                default_rules = "/usr/share/yara/rules"
                if os.path.exists(default_rules):
                    cmd.extend(["-r", default_rules, file_path])
                else:
                    return {"error": "No Yara rules available"}

            result = subprocess.run(cmd, capture_output=True, text=True, timeout=120)

            matches: List[str] = []
            if result.returncode == 0 and result.stdout:
                lines = result.stdout.strip().split("\n")
                matches = [line.strip() for line in lines if line.strip()]

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
        self,
        directory_path: str,
        rules_path: Optional[str] = None,
        *,
        allowed_roots: Optional[Sequence[str]] = None,
        denylist: Optional[Sequence[str]] = None,
        cancel_event: Optional[threading.Event] = None,
        max_files: Optional[int] = None,
    ) -> Dict[str, Any]:
        """Scan all files in a directory with Yara."""

        if not self._tool_available("yara"):
            return {"error": "Yara not available"}

        if not os.path.exists(directory_path):
            return {"error": f"Directory not found: {directory_path}"}

        results: Dict[str, Any] = {
            "directory": directory_path,
            "files_scanned": 0,
            "total_matches": 0,
            "results": [],
        }

        allowed = self._normalise_paths(allowed_roots)
        denied = self._normalise_paths(denylist)
        file_limit = max_files if max_files is not None else self.max_files

        for root, _, files in os.walk(directory_path):
            for file_name in files:
                file_path = os.path.join(root, file_name)

                if cancel_event and cancel_event.is_set():
                    results["cancelled"] = True
                    return results

                if self._should_skip_path(file_path, allowed, denied):
                    continue

                try:
                    if os.path.getsize(file_path) > self.max_file_size:
                        continue
                except OSError:
                    continue

                scan_result = self.yara_scan_file(file_path, rules_path)
                if scan_result.get("success") and scan_result.get("match_count", 0) > 0:
                    entry = dict(scan_result)
                    entry["file_path"] = os.path.relpath(file_path, directory_path)
                    results["results"].append(entry)
                    results["total_matches"] += scan_result["match_count"]

                results["files_scanned"] += 1

                if cancel_event and cancel_event.is_set():
                    results["cancelled"] = True
                    return results

                if results["files_scanned"] >= file_limit:
                    results["truncated"] = True
                    return results

        return results

    def extract_strings_from_file(
        self, file_path: str, min_length: int = 4
    ) -> Dict[str, Any]:
        """Extract strings from binary files."""

        if not self._tool_available("strings"):
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

            strings: List[str] = []
            if result.returncode == 0 and result.stdout:
                lines = result.stdout.strip().split("\n")
                strings = [line.strip() for line in lines if line.strip()]

            return {
                "success": True,
                "file_path": file_path,
                "strings_extracted": len(strings),
                "strings": strings[:1000],
            }

        except subprocess.TimeoutExpired:
            return {"error": "String extraction timeout"}

    def find_secrets_in_text(self, text: str) -> Dict[str, Any]:
        """Find secrets and sensitive data in text using regex patterns."""

        findings: Dict[str, Any] = {"total_findings": 0, "categories": {}}

        for category, patterns in self.security_patterns.items():
            category_findings: List[str] = []

            for pattern in patterns:
                matches = re.findall(pattern, text, re.IGNORECASE | re.MULTILINE)
                if matches:
                    unique_matches = list(
                        {
                            match if isinstance(match, str) else "".join(match)
                            for match in matches
                        }
                    )
                    clean_matches = [
                        match
                        for match in unique_matches
                        if isinstance(match, str) and 10 < len(match) < 200
                    ]

                    if clean_matches:
                        category_findings.extend(clean_matches)

            if category_findings:
                findings["categories"][category] = {
                    "count": len(category_findings),
                    "findings": category_findings[:50],
                }
                findings["total_findings"] += len(category_findings)

        return findings

    def analyze_javascript_file(self, js_content: str) -> Dict[str, Any]:
        """Analyze JavaScript content for endpoints and secrets."""

        analysis: Dict[str, Any] = {
            "endpoints": [],
            "secrets": {},
            "functions": [],
            "comments": [],
        }

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

        analysis["endpoints"] = list(set(analysis["endpoints"]))
        analysis["secrets"] = self.find_secrets_in_text(js_content)

        func_pattern = r"function\s+([a-zA-Z_$][a-zA-Z0-9_$]*)\s*\("
        functions = re.findall(func_pattern, js_content)
        analysis["functions"] = list(set(functions))

        comment_patterns = [
            r"/\*[\s\S]*?\*/",
            r"//.*$",
        ]

        for pattern in comment_patterns:
            comments = re.findall(pattern, js_content, re.MULTILINE)
            analysis["comments"].extend(comments)

        return analysis

    def analyze_webpage_content(self, html_content: str) -> Dict[str, Any]:
        """Analyze HTML content for secrets and endpoints."""

        analysis: Dict[str, Any] = {
            "secrets": {},
            "endpoints": [],
            "forms": [],
            "scripts": [],
            "links": [],
        }

        analysis["secrets"] = self.find_secrets_in_text(html_content)

        endpoint_patterns = [
            r'href=["\']([^"\']+)["\']',
            r'src=["\']([^"\']+)["\']',
            r'action=["\']([^"\']+)["\']',
            r'data-url=["\']([^"\']+)["\']',
        ]

        for pattern in endpoint_patterns:
            matches = re.findall(pattern, html_content, re.IGNORECASE)
            analysis["endpoints"].extend(matches)

        form_pattern = r"<form[^>]*>.*?</form>"
        forms = re.findall(form_pattern, html_content, re.DOTALL | re.IGNORECASE)
        analysis["forms"] = forms

        script_pattern = r'<script[^>]*src=["\']([^"\']+)["\'][^>]*>'
        scripts = re.findall(script_pattern, html_content, re.IGNORECASE)
        analysis["scripts"] = scripts

        link_pattern = r'<a[^>]*href=["\']([^"\']+)["\'][^>]*>'
        links = re.findall(link_pattern, html_content, re.IGNORECASE)
        analysis["links"] = links

        analysis["endpoints"] = list(set(analysis["endpoints"]))

        return analysis

    def grep_search_patterns(
        self, search_path: str, patterns: List[str]
    ) -> Dict[str, Any]:
        """Search for patterns in files using grep."""

        if not self._tool_available("grep"):
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

                matches: List[str] = []
                if result.returncode in [0, 1] and result.stdout:
                    lines = result.stdout.strip().split("\n")
                    matches = [line.strip() for line in lines if line.strip()]

                results["results"][pattern] = {
                    "success": True,
                    "matches": matches,
                    "count": len(matches),
                }

            except subprocess.TimeoutExpired:
                results["results"][pattern] = {"error": "Search timeout"}

        return results

    def comprehensive_security_analysis(self, target_path: str) -> Dict[str, Any]:
        """Perform comprehensive security analysis on a file or directory."""

        analysis: Dict[str, Any] = {
            "target": target_path,
            "timestamp": None,
            "analyses": {},
        }

        if os.path.isfile(target_path):
            file_ext = os.path.splitext(target_path)[1].lower()

            analysis["analyses"]["yara_scan"] = self.yara_scan_file(target_path)

            if file_ext in [".exe", ".dll", ".bin", ".so", ""]:
                analysis["analyses"]["strings"] = self.extract_strings_from_file(
                    target_path
                )

            try:
                with open(
                    target_path, "r", encoding="utf-8", errors="ignore"
                ) as handle:
                    content = handle.read(1024 * 1024)

                if file_ext in [".js", ".jsx", ".ts", ".tsx"]:
                    analysis["analyses"]["javascript_analysis"] = (
                        self.analyze_javascript_file(content)
                    )
                elif file_ext in [".html", ".htm"]:
                    analysis["analyses"]["webpage_analysis"] = (
                        self.analyze_webpage_content(content)
                    )
                else:
                    analysis["analyses"]["secrets_scan"] = self.find_secrets_in_text(
                        content
                    )

            except (UnicodeDecodeError, IOError):
                analysis["analyses"]["content_analysis"] = {
                    "error": "Could not read file content",
                }

        elif os.path.isdir(target_path):
            analysis["analyses"]["yara_directory_scan"] = self.yara_scan_directory(
                target_path
            )

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
