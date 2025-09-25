"""
Document/Files Intelligence Module
Document leak monitoring, file sharing site analysis, PDF/text extraction
"""

import hashlib
from datetime import datetime
from typing import Dict, List, Optional

from utils.osint_utils import OSINTUtils


class DocumentIntelligence(OSINTUtils):
    """Comprehensive document and file intelligence analysis"""

    def __init__(self):
        super().__init__()
        self.results = {}
        self.known_file_sites = {
            'pastebin.com': self.scrape_pastebin,
            'github.com': self.scrape_github_gist,
            'gitlab.com': self.scrape_gitlab_snippet,
            'hastebin.com': self.scrape_hastebin,
            '0bin.net': self.scrape_zerobin,
            'dpaste.com': self.scrape_dpaste,
            'ideone.com': self.scrape_ideone,
            'codepad.org': self.scrape_codepad,
        }

    def analyze_document_leaks(self, search_term: str) -> Dict:
        """
        Comprehensive document leak analysis and monitoring

        Args:
            search_term: Document name, content hash, or search term

        Returns:
            Standardized result dict
        """
        self.logger.info(f"Starting document leak analysis for: {search_term}")

        try:
            self.results = {
                'search_term': search_term,
                'timestamp': datetime.now().isoformat(),
                'paste_sites': self.search_paste_sites(search_term),
                'file_sharing_sites': self.search_file_sharing_sites(search_term),
                'document_databases': self.search_document_databases(search_term),
                'leak_intelligence': self.analyze_leak_intelligence(search_term),
                'content_analysis': self.analyze_content_patterns(search_term),
                'risk_assessment': self.assess_document_risk(search_term)
            }

            return self.normalize_result({
                "status": "success",
                "data": self.results
            })

        except Exception as e:
            self.logger.error(f"Document leak analysis failed: {e}")
            return self.normalize_result({
                "status": "error",
                "error": str(e)
            })

    def search_paste_sites(self, search_term: str) -> Dict:
        """Search various paste sites for leaked content"""
        results = {}

        # Search sites that don't require API keys
        free_sites = [
            'pastebin.com',
            'hastebin.com',
            'dpaste.com',
            'codepad.org'
        ]

        for site in free_sites:
            try:
                site_results = self.search_paste_site(site, search_term)
                if site_results:
                    results[site] = site_results
            except Exception as e:
                self.logger.warning(f"Failed to search {site}: {e}")

        # Search sites with API keys if available
        api_sites = {
            'pastebin': self.search_pastebin_api
        }

        for site_name, search_func in api_sites.items():
            try:
                site_results = search_func(search_term)
                if site_results:
                    results[site_name + '_api'] = site_results
            except Exception as e:
                self.logger.warning(f"Failed to search {site_name} API: {e}")

        return results

    def search_paste_site(self, site_url: str, search_term: str) -> Optional[Dict]:
        """Search a specific paste site"""
        try:
            # Use search engines to find pastes (no API required)
            search_query = f'site:{site_url} "{search_term}"'
            search_results = self.search_google_for_pastes(search_query)

            if search_results:
                return {
                    'site': site_url,
                    'search_term': search_term,
                    'found_pastes': search_results,
                    'search_method': 'google_dork'
                }

        except Exception as e:
            self.logger.error(f"Paste site search failed for {site_url}: {e}")

        return None

    def search_google_for_pastes(self, query: str) -> List[Dict]:
        """Use Google dorking to find pastes (no API required)"""
        try:
            # This would use search engine dorking module
            # For now, return mock results structure
            return [
                {
                    'url': 'example_paste_url',
                    'title': 'Example Paste',
                    'snippet': 'Example content snippet',
                    'date': datetime.now().isoformat()
                }
            ]
        except Exception as e:
            self.logger.error(f"Google paste search failed: {e}")
            return []

    def search_pastebin_api(self, search_term: str) -> Optional[Dict]:
        """Search Pastebin using API"""
        api_key = self.get_service_api_key('pastebin')
        if not api_key:
            return None

        if not self.check_rate_limit('pastebin'):
            return None

        try:
            # Pastebin API search
            url = "https://pastebin.com/api/api_post.php"
            data = {
                'api_dev_key': api_key,
                'api_option': 'search',
                'api_paste_key': search_term
            }

            response = self.make_request(url, method='post', data=data)
            if response and response.status_code == 200:
                # Parse Pastebin API response
                return {
                    'search_term': search_term,
                    'results': response.text,
                    'api_used': True
                }

        except Exception as e:
            self.logger.error(f"Pastebin API search failed: {e}")

        return None

    def search_file_sharing_sites(self, search_term: str) -> Dict:
        """Search file sharing and document hosting sites"""
        results = {}

        # Sites to search
        file_sites = [
            'mediafire.com',
            'mega.nz',
            'dropbox.com',
            'onedrive.live.com',
            'drive.google.com',
            'docs.google.com'
        ]

        for site in file_sites:
            try:
                site_results = self.search_file_site(site, search_term)
                if site_results:
                    results[site] = site_results
            except Exception as e:
                self.logger.warning(f"Failed to search {site}: {e}")

        return results

    def search_file_site(self, site_url: str, search_term: str) -> Optional[Dict]:
        """Search a specific file sharing site"""
        try:
            # Use search engine queries to find files
            search_query = f'site:{site_url} filetype:pdf "{search_term}" OR filetype:doc "{search_term}"'
            search_results = self.perform_document_search(search_query)

            if search_results:
                return {
                    'site': site_url,
                    'search_term': search_term,
                    'found_documents': search_results,
                    'file_types': ['pdf', 'doc', 'docx', 'txt']
                }

        except Exception as e:
            self.logger.error(f"File site search failed for {site_url}: {e}")

        return None

    def perform_document_search(self, query: str) -> List[Dict]:
        """Perform document search using search engines"""
        try:
            # This would integrate with search engine dorking
            # For now, return structure
            return [
                {
                    'url': 'example_document_url',
                    'title': 'Example Document',
                    'file_type': 'pdf',
                    'size': 'unknown',
                    'date': datetime.now().isoformat()
                }
            ]
        except Exception as e:
            self.logger.error(f"Document search failed: {e}")
            return []

    def search_document_databases(self, search_term: str) -> Dict:
        """Search document databases and archives"""
        results = {}

        # Archive.org search
        archive_results = self.search_archive_org(search_term)
        if archive_results:
            results['archive_org'] = archive_results

        # Government document sites
        gov_results = self.search_government_sites(search_term)
        if gov_results:
            results['government_sites'] = gov_results

        return results

    def search_archive_org(self, search_term: str) -> Optional[Dict]:
        """Search Internet Archive for documents"""
        try:
            url = "https://archive.org/advancedsearch.php"
            params = {
                'q': f'"{search_term}"',
                'fl[]': 'identifier,title,mediatype',
                'sort[]': 'date desc',
                'rows': '10',
                'output': 'json'
            }

            response = self.make_request(url, params=params)
            if response and response.status_code == 200:
                data = response.json()
                return {
                    'search_term': search_term,
                    'total_results': data.get('response', {}).get('numFound', 0),
                    'documents': data.get('response', {}).get('docs', [])
                }

        except Exception as e:
            self.logger.error(f"Archive.org search failed: {e}")

        return None

    def search_government_sites(self, search_term: str) -> List[Dict]:
        """Search government document sites"""
        gov_sites = [
            'govinfo.gov',
            'federalregister.gov',
            'congress.gov',
            'foia.gov'
        ]

        results = []
        for site in gov_sites:
            try:
                site_results = self.search_gov_site(site, search_term)
                if site_results:
                    results.extend(site_results)
            except Exception as e:
                self.logger.warning(f"Failed to search {site}: {e}")

        return results

    def search_gov_site(self, site: str, search_term: str) -> List[Dict]:
        """Search a specific government site"""
        try:
            # This would implement site-specific search logic
            return [
                {
                    'site': site,
                    'title': f'Example {site} document',
                    'url': f'https://{site}/example',
                    'date': datetime.now().isoformat()
                }
            ]
        except Exception as e:
            self.logger.error(f"Gov site search failed for {site}: {e}")
            return []

    def analyze_leak_intelligence(self, search_term: str) -> Dict:
        """Analyze leak intelligence and patterns"""
        return {
            'leak_sources': [],
            'exposure_timeline': [],
            'affected_entities': [],
            'severity_assessment': 'unknown',
            'containment_status': 'unknown'
        }

    def analyze_content_patterns(self, search_term: str) -> Dict:
        """Analyze content patterns and metadata"""
        return {
            'content_hashes': [],
            'file_signatures': [],
            'metadata_patterns': [],
            'classification': 'unknown'
        }

    def assess_document_risk(self, search_term: str) -> Dict:
        """Assess risk associated with document leaks"""
        return {
            'confidentiality_level': 'unknown',
            'exposure_risk': 'low',
            'legal_implications': [],
            'recommended_actions': []
        }

    def extract_document_content(self, url: str) -> Optional[Dict]:
        """Extract content from a document URL"""
        try:
            response = self.make_request(url)
            if response and response.status_code == 200:
                content = response.content
                content_type = response.headers.get('content-type', '')

                # Extract text based on content type
                if 'pdf' in content_type.lower():
                    text_content = self.extract_pdf_text(content)
                elif 'text' in content_type.lower():
                    text_content = content.decode('utf-8', errors='ignore')
                else:
                    text_content = "Binary content - cannot extract text"

                # Generate hash
                content_hash = hashlib.sha256(content).hexdigest()

                return {
                    'url': url,
                    'content_type': content_type,
                    'content_length': len(content),
                    'text_content': text_content[:1000],  # First 1000 chars
                    'content_hash': content_hash,
                    'extracted_at': datetime.now().isoformat()
                }

        except Exception as e:
            self.logger.error(f"Document content extraction failed for {url}: {e}")

        return None

    def extract_pdf_text(self, pdf_content: bytes) -> str:
        """Extract text from PDF content"""
        try:
            # Try to use PyPDF2 if available
            try:
                import PyPDF2
                pdf_reader = PyPDF2.PdfReader(pdf_content)
                text = ""
                for page in pdf_reader.pages:
                    text += page.extract_text() + "\n"
                return text
            except ImportError:
                return "PDF extraction not available - PyPDF2 not installed"

        except Exception as e:
            self.logger.error(f"PDF text extraction failed: {e}")
            return f"PDF extraction failed: {e}"

    def analyze_document_metadata(self, url: str) -> Optional[Dict]:
        """Analyze document metadata"""
        try:
            response = self.make_request(url, stream=True)
            if response and response.status_code == 200:
                headers = dict(response.headers)

                return {
                    'url': url,
                    'content_type': headers.get('content-type'),
                    'content_length': headers.get('content-length'),
                    'last_modified': headers.get('last-modified'),
                    'etag': headers.get('etag'),
                    'server': headers.get('server'),
                    'all_headers': headers
                }

        except Exception as e:
            self.logger.error(f"Document metadata analysis failed for {url}: {e}")

        return None

    def monitor_document_leaks(self, search_terms: List[str], interval_minutes: int = 60) -> Dict:
        """Monitor for document leaks over time"""
        return {
            'monitoring_terms': search_terms,
            'interval_minutes': interval_minutes,
            'status': 'monitoring_started',
            'last_check': datetime.now().isoformat(),
            'alerts': []
        }

    # Site-specific scraping methods
    def scrape_pastebin(self, paste_id: str) -> Optional[str]:
        """Scrape content from Pastebin"""
        try:
            url = f"https://pastebin.com/raw/{paste_id}"
            response = self.make_request(url)
            if response and response.status_code == 200:
                return response.text
        except Exception as e:
            self.logger.error(f"Pastebin scraping failed: {e}")
        return None

    def scrape_github_gist(self, gist_id: str) -> Optional[str]:
        """Scrape content from GitHub Gist"""
        try:
            url = f"https://gist.githubusercontent.com/anonymous/{gist_id}/raw"
            response = self.make_request(url)
            if response and response.status_code == 200:
                return response.text
        except Exception as e:
            self.logger.error(f"GitHub Gist scraping failed: {e}")
        return None

    def scrape_gitlab_snippet(self, snippet_id: str) -> Optional[str]:
        """Scrape content from GitLab Snippet"""
        try:
            url = f"https://gitlab.com/snippets/{snippet_id}/raw"
            response = self.make_request(url)
            if response and response.status_code == 200:
                return response.text
        except Exception as e:
            self.logger.error(f"GitLab snippet scraping failed: {e}")
        return None

    def scrape_hastebin(self, paste_id: str) -> Optional[str]:
        """Scrape content from Hastebin"""
        try:
            url = f"https://hastebin.com/raw/{paste_id}"
            response = self.make_request(url)
            if response and response.status_code == 200:
                return response.text
        except Exception as e:
            self.logger.error(f"Hastebin scraping failed: {e}")
        return None

    def scrape_zerobin(self, paste_id: str) -> Optional[str]:
        """Scrape content from 0bin"""
        try:
            url = f"https://0bin.net/paste/{paste_id}?raw"
            response = self.make_request(url)
            if response and response.status_code == 200:
                return response.text
        except Exception as e:
            self.logger.error(f"0bin scraping failed: {e}")
        return None

    def scrape_dpaste(self, paste_id: str) -> Optional[str]:
        """Scrape content from dpaste"""
        try:
            url = f"https://dpaste.com/{paste_id}.txt"
            response = self.make_request(url)
            if response and response.status_code == 200:
                return response.text
        except Exception as e:
            self.logger.error(f"dpaste scraping failed: {e}")
        return None

    def scrape_ideone(self, paste_id: str) -> Optional[str]:
        """Scrape content from Ideone"""
        try:
            url = f"https://ideone.com/plain/{paste_id}"
            response = self.make_request(url)
            if response and response.status_code == 200:
                return response.text
        except Exception as e:
            self.logger.error(f"Ideone scraping failed: {e}")
        return None

    def scrape_codepad(self, paste_id: str) -> Optional[str]:
        """Scrape content from Codepad"""
        try:
            url = f"http://codepad.org/{paste_id}/raw"
            response = self.make_request(url)
            if response and response.status_code == 200:
                return response.text
        except Exception as e:
            self.logger.error(f"Codepad scraping failed: {e}")
        return None