"""
Free Tools OSINT Module
Provides local analysis tools and free intelligence gathering capabilities
No API keys or external dependencies required
"""

from utils.osint_utils import OSINTUtils
import os
import hashlib
import re
from typing import Dict, List, Optional, Any
from datetime import datetime
import platform
import socket
import ipaddress


class FreeToolsOSINT(OSINTUtils):
    """Free tools for OSINT gathering without API dependencies"""

    def __init__(self):
        super().__init__()
        self.system_info = self._get_system_info()

    def _get_system_info(self) -> Dict[str, str]:
        """Get basic system information"""
        return {
            'platform': platform.system(),
            'platform_version': platform.version(),
            'architecture': platform.machine(),
            'python_version': platform.python_version()
        }

    def extract_file_metadata(self, file_path: str) -> Dict[str, Any]:
        """
        Extract metadata from files using built-in Python capabilities
        Enhanced version with more comprehensive analysis
        """
        if not os.path.exists(file_path):
            return {'error': 'File does not exist'}

        metadata = {
            'file_path': file_path,
            'file_name': os.path.basename(file_path),
            'directory': os.path.dirname(file_path),
            'exists': True,
            'analysis_timestamp': datetime.now().isoformat()
        }

        try:
            # Basic file stats
            stat_info = os.stat(file_path)
            metadata.update({
                'size_bytes': stat_info.st_size,
                'size_human': self._format_file_size(stat_info.st_size),
                'created_timestamp': datetime.fromtimestamp(stat_info.st_ctime).isoformat(),
                'modified_timestamp': datetime.fromtimestamp(stat_info.st_mtime).isoformat(),
                'accessed_timestamp': datetime.fromtimestamp(stat_info.st_atime).isoformat(),
                'permissions': oct(stat_info.st_mode)[-3:],
                'is_file': os.path.isfile(file_path),
                'is_directory': os.path.isdir(file_path),
                'is_link': os.path.islink(file_path)
            })

            # File extension and type detection
            _, ext = os.path.splitext(file_path)
            metadata['extension'] = ext.lower()

            # MIME type detection (basic)
            metadata['mime_type'] = self._guess_mime_type(file_path)

            # Hash calculations
            metadata['hashes'] = self._calculate_file_hashes(file_path)

            # Content analysis for text files
            if self._is_text_file(file_path):
                content_analysis = self._analyze_text_content(file_path)
                metadata['content_analysis'] = content_analysis

        except Exception as e:
            metadata['error'] = str(e)

        return metadata

    def _format_file_size(self, size_bytes: int) -> str:
        """Format file size in human readable format"""
        size = float(size_bytes)
        for unit in ['B', 'KB', 'MB', 'GB', 'TB']:
            if size < 1024.0:
                return f"{size:.1f} {unit}"
            size /= 1024.0
        return f"{size:.1f} TB"

    def _guess_mime_type(self, file_path: str) -> str:
        """Basic MIME type guessing based on extension"""
        mime_types = {
            '.txt': 'text/plain',
            '.html': 'text/html',
            '.htm': 'text/html',
            '.css': 'text/css',
            '.js': 'application/javascript',
            '.json': 'application/json',
            '.xml': 'application/xml',
            '.pdf': 'application/pdf',
            '.doc': 'application/msword',
            '.docx': 'application/vnd.openxmlformats-officedocument.wordprocessingml.document',
            '.xls': 'application/vnd.ms-excel',
            '.xlsx': 'application/vnd.openxmlformats-officedocument.spreadsheetml.sheet',
            '.ppt': 'application/vnd.ms-powerpoint',
            '.pptx': 'application/vnd.openxmlformats-officedocument.presentationml.presentation',
            '.jpg': 'image/jpeg',
            '.jpeg': 'image/jpeg',
            '.png': 'image/png',
            '.gif': 'image/gif',
            '.bmp': 'image/bmp',
            '.mp4': 'video/mp4',
            '.avi': 'video/x-msvideo',
            '.mp3': 'audio/mpeg',
            '.wav': 'audio/wav',
            '.zip': 'application/zip',
            '.rar': 'application/x-rar-compressed',
            '.7z': 'application/x-7z-compressed'
        }

        _, ext = os.path.splitext(file_path.lower())
        return mime_types.get(ext, 'application/octet-stream')

    def _calculate_file_hashes(self, file_path: str) -> Dict[str, str]:
        """Calculate various file hashes"""
        hashes = {}
        try:
            with open(file_path, 'rb') as f:
                data = f.read()

            hashes['md5'] = hashlib.md5(data).hexdigest()
            hashes['sha1'] = hashlib.sha1(data).hexdigest()
            hashes['sha256'] = hashlib.sha256(data).hexdigest()
            hashes['sha512'] = hashlib.sha512(data).hexdigest()

        except Exception as e:
            hashes['error'] = str(e)

        return hashes

    def _is_text_file(self, file_path: str, sample_size: int = 1024) -> bool:
        """Check if file is likely a text file"""
        try:
            with open(file_path, 'rb') as f:
                sample = f.read(sample_size)

            # Check for null bytes (binary files often have them)
            if b'\x00' in sample:
                return False

            # Try to decode as UTF-8
            try:
                sample.decode('utf-8')
                return True
            except UnicodeDecodeError:
                return False

        except Exception:
            return False

    def _analyze_text_content(self, file_path: str, max_lines: int = 100) -> Dict[str, Any]:
        """Analyze text file content"""
        analysis = {
            'line_count': 0,
            'word_count': 0,
            'character_count': 0,
            'encoding': 'unknown',
            'contains_email': False,
            'contains_url': False,
            'contains_ip': False,
            'sample_lines': []
        }

        try:
            with open(file_path, 'r', encoding='utf-8', errors='ignore') as f:
                content = f.read()
                lines = content.split('\n')

                analysis['line_count'] = len(lines)
                analysis['character_count'] = len(content)
                analysis['word_count'] = len(content.split())
                analysis['encoding'] = 'utf-8'

                # Check for patterns
                analysis['contains_email'] = bool(re.search(r'\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Z|a-z]{2,}\b', content))
                analysis['contains_url'] = bool(re.search(r'http[s]?://(?:[a-zA-Z]|[0-9]|[$-_@.&+]|[!*\\(\\),]|(?:%[0-9a-fA-F][0-9a-fA-F]))+', content))
                analysis['contains_ip'] = bool(re.search(r'\b\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}\b', content))

                # Sample lines (respect max_lines)
                sample_count = min(max_lines, 10, len(lines))
                analysis['sample_lines'] = lines[:sample_count]

        except Exception as e:
            analysis['error'] = str(e)

        return analysis
    def local_dns_lookup(self, hostname: str) -> Dict[str, Any]:
        """Perform local DNS lookup without external tools"""
        result: Dict[str, Any] = {
            'hostname': hostname,
            'resolved': False,
            'results': {}
        }

        try:
            ip_address = None
            # A record lookup
            try:
                ip_address = socket.gethostbyname(hostname)
                result['results']['A'] = ip_address
                result['resolved'] = True
            except socket.gaierror:
                result['results']['A'] = 'Not found'

            # Reverse DNS lookup
            try:
                if result['resolved'] and ip_address is not None:
                    reverse_name = socket.gethostbyaddr(ip_address)[0]
                    result['results']['PTR'] = reverse_name
                else:
                    result['results']['PTR'] = 'Not found'
            except socket.herror:
                result['results']['PTR'] = 'Not found'

            # Additional checks
            result['results']['is_valid_hostname'] = self._is_valid_hostname(hostname)
            result['results']['is_ip_address'] = self._is_ip_address(hostname)

        except Exception as e:
            result['error'] = str(e)

        return result

    def _is_valid_hostname(self, hostname: str) -> bool:
        """Check if hostname is valid"""
        if not hostname or len(hostname) > 253:
            return False

        # Remove trailing dot
        if hostname[-1] == '.':
            hostname = hostname[:-1]

        # Check each label
        labels = hostname.split('.')
        for label in labels:
            if not label or len(label) > 63:
                return False
            if not re.match(r'^[a-zA-Z0-9]([a-zA-Z0-9-]*[a-zA-Z0-9])?$', label):
                return False

        return True

    def _is_ip_address(self, string: str) -> bool:
        """Check if string is a valid IP address"""
        try:
            ipaddress.ip_address(string)
            return True
        except ValueError:
            return False
    def local_port_scan(self, target: str, ports: Optional[List[int]] = None) -> Dict[str, Any]:
        """
        Perform basic local port scanning using socket connections
        Note: This is very basic and may not work through firewalls
        """
        if ports is None:
            ports = [21, 22, 23, 25, 53, 80, 110, 143, 443, 993, 995]

        result: Dict[str, Any] = {
            'target': target,
            'scan_timestamp': datetime.now().isoformat(),
            'ports_scanned': ports,
            'results': {}
        }

        for port in ports:
            try:
                sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                sock.settimeout(1)
                result_code = sock.connect_ex((target, port))
                sock.close()

                result['results'][port] = {
                    'open': result_code == 0,
                    'service': self._guess_service(port)
                }

            except Exception as e:
                result['results'][port] = {
                    'open': False,
                    'error': str(e)
                }

        return result

    def _guess_service(self, port: int) -> str:
        """Guess service name based on port number"""
        services = {
            21: 'FTP',
            22: 'SSH',
            23: 'Telnet',
            25: 'SMTP',
            53: 'DNS',
            80: 'HTTP',
            110: 'POP3',
            143: 'IMAP',
            443: 'HTTPS',
            993: 'IMAPS',
            995: 'POP3S'
        }
        return services.get(port, 'Unknown')
    def analyze_url_locally(self, url: str) -> Dict[str, Any]:
        """Analyze URL components without external requests"""
        from urllib.parse import urlparse, parse_qs

        result: Dict[str, Any] = {
            'original_url': url,
            'analysis_timestamp': datetime.now().isoformat()
        }

        try:
            parsed = urlparse(url)

            # Populate parsed fields explicitly to keep typing as Dict[str, Any]
            result['scheme'] = parsed.scheme
            result['netloc'] = parsed.netloc
            result['hostname'] = parsed.hostname
            result['port'] = parsed.port
            result['path'] = parsed.path
            result['query'] = parsed.query
            result['fragment'] = parsed.fragment
            result['is_valid'] = True

            # Extract query parameters
            if parsed.query:
                result['query_params'] = parse_qs(parsed.query)
            # Security analysis
            security_analysis = self._analyze_url_security(url, parsed)
            result['security_analysis'] = security_analysis

            # Domain analysis
            if parsed.hostname:
                domain_analysis = self._analyze_domain_locally(parsed.hostname)
                result['domain_analysis'] = domain_analysis

        except Exception as e:
            result['error'] = str(e)
            result['is_valid'] = False

        return result

    def _analyze_url_security(self, url: str, parsed_url) -> Dict[str, Any]:
        """Analyze URL for potential security issues"""
        analysis = {
            'uses_https': parsed_url.scheme == 'https',
            'has_suspicious_chars': bool(re.search(r'[<>]', url)),
            'has_unicode_chars': any(ord(c) > 127 for c in url),
            'is_ip_address': self._is_ip_address(parsed_url.hostname or ''),
            'suspicious_keywords': []
        }

        suspicious_keywords = ['admin', 'login', 'password', 'bank', 'paypal', 'secure']
        url_lower = url.lower()

        for keyword in suspicious_keywords:
            if keyword in url_lower:
                analysis['suspicious_keywords'].append(keyword)

        return analysis

    def _analyze_domain_locally(self, domain: str) -> Dict[str, Any]:
        """Analyze domain locally without external lookups"""
        analysis = {
            'domain': domain,
            'length': len(domain),
            'is_valid': self._is_valid_hostname(domain),
            'tld': None,
            'subdomains': []
        }

        if '.' in domain:
            parts = domain.split('.')
            analysis['tld'] = parts[-1]
            if len(parts) > 2:
                analysis['subdomains'] = parts[:-2]

        # Check for suspicious patterns
        analysis['suspicious_patterns'] = self._check_domain_suspicious_patterns(domain)

        return analysis

    def _check_domain_suspicious_patterns(self, domain: str) -> List[str]:
        """Check domain for suspicious patterns"""
        patterns = []

        # Check for numbers in domain (potential typosquatting)
        if re.search(r'\d', domain):
            patterns.append('contains_numbers')

        # Check for repeated characters
        if re.search(r'(.)\1{2,}', domain):
            patterns.append('repeated_characters')

        # Check for suspicious TLDs
        suspicious_tlds = ['tk', 'ml', 'ga', 'cf', 'gq']
        if domain.split('.')[-1] in suspicious_tlds:
            patterns.append('suspicious_tld')

        return patterns

    def extract_patterns_from_text(self, text: str) -> Dict[str, List[str]]:
        """Extract various patterns from text using regex"""
        patterns = {
            'emails': re.findall(r'\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Z|a-z]{2,}\b', text),
            'urls': re.findall(r'http[s]?://(?:[a-zA-Z]|[0-9]|[$-_@.&+]|[!*\\(\\),]|(?:%[0-9a-fA-F][0-9a-fA-F]))+', text),
            'ip_addresses': re.findall(r'\b\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}\b', text),
            'phone_numbers': re.findall(r'\b\d{3}[-.]?\d{3}[-.]?\d{4}\b', text),
            'credit_cards': re.findall(r'\b\d{4}[- ]?\d{4}[- ]?\d{4}[- ]?\d{4}\b', text),
            'ssn_patterns': re.findall(r'\b\d{3}[-]?\d{2}[-]?\d{4}\b', text),
            'bitcoin_addresses': re.findall(r'\b[13][a-km-zA-HJ-NP-Z1-9]{25,34}\b', text),
            'ethereum_addresses': re.findall(r'\b0x[a-fA-F0-9]{40}\b', text)
        }

        # Remove duplicates
        for key in patterns:
            patterns[key] = list(set(patterns[key]))

        return patterns

    def system_network_info(self) -> Dict[str, Any]:
        """Get local system network information"""
        info = {
            'hostname': socket.gethostname(),
            'analysis_timestamp': datetime.now().isoformat(),
            'network_interfaces': {}
        }

        try:
            # Get local IP addresses
            hostname = socket.gethostname()
            local_ip = socket.gethostbyname(hostname)
            info['local_ip'] = local_ip

            # Try to get public IP (this may not work in all environments)
            try:
                # This is a simple way - in practice you'd use a service
                s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
                s.connect(("8.8.8.8", 80))
                public_ip = s.getsockname()[0]
                s.close()
                info['public_ip_guess'] = public_ip
            except Exception:
                info['public_ip_guess'] = 'Unable to determine'

        except Exception as e:
            info['error'] = str(e)

        return info

    def comprehensive_file_analysis(self, file_path: str) -> Dict[str, Any]:
        """Perform comprehensive file analysis"""
        analysis: Dict[str, Any] = {
            'file_path': file_path,
            'analysis_timestamp': datetime.now().isoformat(),
            'metadata': {},
            'content_analysis': {},
            'security_analysis': {}
        }

        # Get metadata
        analysis['metadata'] = self.extract_file_metadata(file_path)

        # Content analysis if it's a text file
        if self._is_text_file(file_path):
            with open(file_path, 'r', encoding='utf-8', errors='ignore') as f:
                content = f.read()

            analysis['content_analysis'] = {
                'patterns': self.extract_patterns_from_text(content),
                'line_count': len(content.split('\n')),
                'word_count': len(content.split()),
                'character_count': len(content)
            }

        # Security analysis
        analysis['security_analysis'] = self._analyze_file_security(file_path)

        return analysis

    def _analyze_file_security(self, file_path: str) -> Dict[str, Any]:
        """Analyze file for security concerns"""
        analysis: Dict[str, Any] = {
            'is_executable': False,
            'has_suspicious_permissions': False,
            'file_size_concern': False
        }

        try:
            # Check if executable
            import stat
            file_stat = os.stat(file_path)
            analysis['is_executable'] = bool(file_stat.st_mode & stat.S_IEXEC)

            # Check permissions (world writable is suspicious)
            permissions = oct(file_stat.st_mode)[-3:]
            analysis['has_suspicious_permissions'] = permissions[-1] in ['2', '6', '7']

            # Check file size (very large files might be suspicious)
            analysis['file_size_concern'] = file_stat.st_size > 100 * 1024 * 1024  # 100MB

        except Exception as e:
            analysis['error'] = str(e)

        return analysis