"""
Code Analysis and Repository Intelligence Module
Provides comprehensive code analysis using GitLeaks, TruffleHog, and Ripgrep
"""

import json
import logging
import os
import subprocess
import tempfile
from typing import Any, Dict, List

logger = logging.getLogger(__name__)


class CodeAnalysisEngine:
    """Code analysis engine using open source tools"""

    def __init__(self):
        self.tools = {
            "gitleaks": self._check_tool("gitleaks"),
            "trufflehog": self._check_tool("trufflehog"),
            "ripgrep": self._check_tool("rg"),
            "theharvester": self._check_tool("theharvester"),
            "sherlock": self._check_tool("sherlock"),
            "binwalk": self._check_tool("binwalk"),
        }

    def _get_tool_env(self) -> Dict[str, str]:
        """Get environment with proper PATH for tools"""
        env = os.environ.copy()
        extra_paths = [
            os.path.expanduser("~/go/bin"),
            os.path.expanduser("~/bin"),
            os.path.join(os.getcwd(), "theHarvester", "bin"),
        ]
        original_path = env.get("PATH", "")
        env["PATH"] = (
            ":".join([*extra_paths, original_path])
            if original_path
            else ":".join(extra_paths)
        )
        return env

    def _check_tool(self, tool_name: str) -> bool:
        """Check if a tool is available"""
        try:
            cmd = self._get_tool_command(tool_name)
            result = self._run_tool(cmd, timeout=10, capture_output=True)
            # For binwalk, return code 1 is OK (shows help/version)
            if tool_name == "binwalk":
                return result.returncode in [0, 1] and len(result.stderr) > 0
            return result.returncode == 0
        except (
            subprocess.TimeoutExpired,
            FileNotFoundError,
            subprocess.CalledProcessError,
        ):
            return False

    def _get_tool_command(self, tool_name: str) -> List[str]:
        """Get the command list for a tool"""
        if tool_name == "gitleaks":
            return [os.path.expanduser("~/go/bin/gitleaks"), "--version"]
        elif tool_name == "trufflehog":
            return [os.path.expanduser("~/bin/trufflehog"), "--version"]
        elif tool_name == "rg":
            return ["rg", "--version"]
        elif tool_name == "theharvester":
            theharvester_script = os.path.join(
                os.getcwd(), "theHarvester", "theHarvester.py"
            )
            return ["python3", theharvester_script, "-d", "example.com", "-l", "1"]
        elif tool_name == "sherlock":
            return ["sherlock", "--help"]
        elif tool_name == "binwalk":
            return ["/usr/bin/binwalk"]
        else:
            return [tool_name]

    def _run_tool(
        self, cmd: List[str], timeout: int = 300, **kwargs
    ) -> subprocess.CompletedProcess:
        """Run a tool with proper environment"""
        return subprocess.run(cmd, env=self._get_tool_env(), timeout=timeout, **kwargs)

    def scan_git_repository(
        self, repo_path: str, scan_type: str = "all"
    ) -> Dict[str, Any]:
        """
        Scan a git repository for secrets and sensitive data

        Args:
            repo_path: Path to the git repository
            scan_type: Type of scan ('gitleaks', 'trufflehog', 'both', 'all')

        Returns:
            Dictionary containing scan results
        """
        if not os.path.exists(repo_path):
            return {"error": f"Repository not found: {repo_path}"}

        if not os.path.exists(os.path.join(repo_path, ".git")):
            return {"error": f"Not a git repository: {repo_path}"}

        results: Dict[str, Any] = {"repository": repo_path, "scans": {}}

        # GitLeaks scan
        if (scan_type in ["gitleaks", "both", "all"]) and self.tools["gitleaks"]:
            try:
                with tempfile.NamedTemporaryFile(
                    mode="w", suffix=".json", delete=False
                ) as f:
                    config_file = f.name

                result = self._run_tool(
                    [
                        os.path.expanduser("~/go/bin/gitleaks"),
                        "detect",
                        "--source",
                        repo_path,
                        "--report-format",
                        "json",
                        "--report-path",
                        config_file,
                        "--verbose",
                    ],
                    capture_output=True,
                    text=True,
                )

                findings = []
                if os.path.exists(config_file):
                    try:
                        with open(config_file, "r") as f:
                            data = json.load(f)
                            findings = data if isinstance(data, list) else [data]
                    except json.JSONDecodeError:
                        pass
                    finally:
                        os.unlink(config_file)

                results["scans"]["gitleaks"] = {
                    "success": result.returncode == 0,
                    "findings": findings,
                    "count": len(findings),
                }

            except subprocess.TimeoutExpired:
                results["scans"]["gitleaks"] = {"error": "GitLeaks scan timeout"}

        # TruffleHog scan
        if (scan_type in ["trufflehog", "both", "all"]) and self.tools["trufflehog"]:
            try:
                result = self._run_tool(
                    [
                        os.path.expanduser("~/bin/trufflehog"),
                        "filesystem",
                        repo_path,
                        "--json",
                    ],
                    capture_output=True,
                    text=True,
                )

                findings = []
                if result.returncode == 0 and result.stdout:
                    lines = result.stdout.strip().split("\n")
                    for line in lines:
                        if line.strip():
                            try:
                                finding = json.loads(line)
                                findings.append(finding)
                            except json.JSONDecodeError:
                                continue

                results["scans"]["trufflehog"] = {
                    "success": result.returncode == 0,
                    "findings": findings,
                    "count": len(findings),
                }

            except subprocess.TimeoutExpired:
                results["scans"]["trufflehog"] = {"error": "TruffleHog scan timeout"}

        return results

    def search_code_patterns(
        self,
        search_path: str,
        patterns: List[str],
        case_sensitive: bool = False,
        context: int = 3,
    ) -> Dict[str, Any]:
        """
        Search for patterns in code using Ripgrep

        Args:
            search_path: Path to search in
            patterns: List of regex patterns to search for
            case_sensitive: Whether search should be case sensitive
            context: Number of context lines to include

        Returns:
            Dictionary containing search results
        """
        if not self.tools["ripgrep"]:
            return {"error": "Ripgrep not available"}

        if not os.path.exists(search_path):
            return {"error": f"Search path not found: {search_path}"}

        results: Dict[str, Any] = {
            "search_path": search_path,
            "patterns_searched": patterns,
            "results": {},  # This will hold pattern -> result mappings
        }

        for pattern in patterns:
            try:
                cmd = ["rg", "--json", "--context", str(context)]
                if not case_sensitive:
                    cmd.append("--ignore-case")
                cmd.extend([pattern, search_path])

                result = self._run_tool(
                    cmd, capture_output=True, text=True, timeout=120
                )

                matches = []
                if (
                    result.returncode in [0, 1] and result.stdout
                ):  # 0 = matches found, 1 = no matches
                    lines = result.stdout.strip().split("\n")
                    for line in lines:
                        if line.strip():
                            try:
                                match_data = json.loads(line)
                                if match_data.get("type") == "match":
                                    matches.append(match_data)
                            except json.JSONDecodeError:
                                continue

                results["results"][pattern] = {
                    "success": True,
                    "matches": matches,
                    "count": len(matches),
                }

            except subprocess.TimeoutExpired:
                results["results"][pattern] = {
                    "error": f"Search timeout for pattern: {pattern}"
                }

        return results

    def analyze_codebase_structure(self, repo_path: str) -> Dict[str, Any]:
        """
        Analyze the structure and composition of a codebase

        Args:
            repo_path: Path to the repository

        Returns:
            Dictionary containing codebase analysis
        """
        if not os.path.exists(repo_path):
            return {"error": f"Repository not found: {repo_path}"}

        analysis = {
            "repository": repo_path,
            "structure": {},
            "languages": {},
            "file_types": {},
        }

        # Analyze directory structure
        structure = {}
        for root, dirs, files in os.walk(repo_path):
            # Skip .git directory
            if ".git" in root:
                continue

            level = root.replace(repo_path, "").count(os.sep)
            if level < 4:  # Only go 3 levels deep
                rel_path = os.path.relpath(root, repo_path)
                structure[rel_path] = {"directories": len(dirs), "files": len(files)}

        analysis["structure"] = structure

        # Analyze languages and file types
        languages: Dict[str, int] = {}
        file_types: Dict[str, int] = {}

        for root, dirs, files in os.walk(repo_path):
            if ".git" in root:
                continue

            for file in files:
                _, ext = os.path.splitext(file)

                # Count file types
                if ext in file_types:
                    file_types[ext] += 1
                else:
                    file_types[ext] = 1

                # Basic language detection
                if ext in [".py", ".python"]:
                    lang = "Python"
                elif ext in [".js", ".javascript"]:
                    lang = "JavaScript"
                elif ext in [".ts", ".typescript"]:
                    lang = "TypeScript"
                elif ext in [".java"]:
                    lang = "Java"
                elif ext in [".cpp", ".cc", ".cxx", ".c++"]:
                    lang = "C++"
                elif ext in [".c"]:
                    lang = "C"
                elif ext in [".go"]:
                    lang = "Go"
                elif ext in [".rs"]:
                    lang = "Rust"
                elif ext in [".rb"]:
                    lang = "Ruby"
                elif ext in [".php"]:
                    lang = "PHP"
                elif ext in [".html"]:
                    lang = "HTML"
                elif ext in [".css"]:
                    lang = "CSS"
                elif ext in [".sql"]:
                    lang = "SQL"
                elif ext in [".sh", ".bash"]:
                    lang = "Shell"
                elif ext in [".yml", ".yaml"]:
                    lang = "YAML"
                elif ext in [".json"]:
                    lang = "JSON"
                elif ext in [".xml"]:
                    lang = "XML"
                elif ext in [".md", ".markdown"]:
                    lang = "Markdown"
                else:
                    lang = "Other"

                if lang in languages:
                    languages[lang] += 1
                else:
                    languages[lang] = 1

        analysis["languages"] = languages
        analysis["file_types"] = file_types

        return analysis

    def find_sensitive_patterns(self, search_path: str) -> Dict[str, Any]:
        """
        Search for common sensitive patterns in code

        Args:
            search_path: Path to search in

        Returns:
            Dictionary containing sensitive pattern findings
        """
        sensitive_patterns = [
            r'password\s*[:=]\s*["\'][^"\']+["\']',  # password = "value"
            r'api[_-]?key\s*[:=]\s*["\'][^"\']+["\']',  # api_key = "value"
            r'secret[_-]?key\s*[:=]\s*["\'][^"\']+["\']',  # secret_key = "value"
            r'token\s*[:=]\s*["\'][^"\']+["\']',  # token = "value"
            r"aws[_-]?access[_-]?key[_-]?id",  # AWS access key
            r"aws[_-]?secret[_-]?access[_-]?key",  # AWS secret key
            r"private[_-]?key",  # Private key references
            r"database[_-]?url",  # Database URLs
            r"connection[_-]?string",  # Connection strings
            r"Bearer\s+[A-Za-z0-9\-_\.]+",  # Bearer tokens
            r"Authorization:\s*Basic\s+[A-Za-z0-9+/=]+",  # Basic auth
            r"-----BEGIN\s+(RSA\s+)?PRIVATE\s+KEY-----",  # Private key blocks
            r"-----BEGIN\s+CERTIFICATE-----",  # Certificate blocks
        ]

        return self.search_code_patterns(
            search_path, sensitive_patterns, case_sensitive=False
        )

    def comprehensive_repo_analysis(self, repo_path: str) -> Dict[str, Any]:
        """
        Perform comprehensive analysis of a git repository

        Args:
            repo_path: Path to the repository

        Returns:
            Dictionary containing all analysis results
        """
        analysis: Dict[str, Any] = {
            "repository": repo_path,
            "timestamp": None,  # Would be set by caller
            "results": {},
        }

        # Structure analysis
        analysis["results"]["structure"] = self.analyze_codebase_structure(repo_path)

        # Secret scanning
        analysis["results"]["secrets"] = self.scan_git_repository(repo_path)

        # Sensitive pattern search
        analysis["results"]["sensitive_patterns"] = self.find_sensitive_patterns(
            repo_path
        )

        return analysis
