"""
Patent Database Passive Intelligence Module
Search patent databases for intellectual property intelligence
"""

from utils.osint_utils import OSINTUtils


class PatentPassive(OSINTUtils):
    def __init__(self):
        super().__init__()
        self.sources = {
            'google_patents': {
                'name': 'Google Patents',
                'url': 'https://patents.google.com',
                'search_url': 'https://patents.google.com/?q={query}'
            },
            'uspto': {
                'name': 'USPTO Patent Database',
                'url': 'https://patft.uspto.gov',
                'search_url': 'https://patft.uspto.gov/netahtml/PTO/search-adv.htm'
            },
            'espacenet': {
                'name': 'Espacenet',
                'url': 'https://worldwide.espacenet.com',
                'search_url': 'https://worldwide.espacenet.com/patent/search?q={query}'
            },
            'wipo': {
                'name': 'WIPO PATENTSCOPE',
                'url': 'https://patentscope.wipo.int',
                'search_url': 'https://patentscope.wipo.int/search/en/search.jsf'
            }
        }

    def search_patent_databases(self, query, limit=10):
        """
        Search across multiple patent databases for intellectual property intelligence
        """
        results = {
            'query': query,
            'sources_searched': len(self.sources),
            'total_results': 0,
            'patents': [],
            'assignees': [],
            'inventors': []
        }

        for source_key, source_info in self.sources.items():
            try:
                source_results = self.search_single_patent_source(source_key, query, limit)
                if source_results['status'] == 'success':
                    results['patents'].extend(source_results.get('patents', []))
                    results['assignees'].extend(source_results.get('assignees', []))
                    results['inventors'].extend(source_results.get('inventors', []))
                    results['total_results'] += source_results.get('count', 0)
            except Exception as e:
                self.logger.warning(f"Error searching {source_info['name']}: {e}")

        # Remove duplicates and limit results
        results['patents'] = self._deduplicate_patents(results['patents'][:limit*2])
        results['assignees'] = list(set(results['assignees']))[:limit]
        results['inventors'] = list(set(results['inventors']))[:limit]

        return results

    def search_single_patent_source(self, source, query, limit=10):
        """
        Search a specific patent database
        """
        if source == 'google_patents':
            return self.search_google_patents(query, limit)
        elif source == 'uspto':
            return self.search_uspto(query, limit)
        elif source == 'espacenet':
            return self.search_espacenet(query, limit)
        elif source == 'wipo':
            return self.search_wipo(query, limit)
        else:
            return {'status': 'error', 'error': f'Unknown source: {source}'}

    def search_google_patents(self, query, limit=10):
        """Search Google Patents"""
        import urllib.parse
        from bs4 import BeautifulSoup

        search_url = f"https://patents.google.com/?q={urllib.parse.quote(query)}"
        patents = []

        try:
            resp = self.request_with_fallback('get', search_url, timeout=15, allow_fallback=True)
            if resp.status_code == 200:
                soup = BeautifulSoup(resp.text, 'html.parser')

                # Find patent results
                results = soup.select('.result')

                for result in results[:limit]:
                    patent = {}

                    # Title and patent number
                    title_elem = result.select_one('.result-title')
                    if title_elem:
                        patent['title'] = title_elem.text.strip()

                    # Patent number
                    number_elem = result.select_one('.result-number')
                    if number_elem:
                        patent['patent_number'] = number_elem.text.strip()

                    # Assignee
                    assignee_elem = result.select_one('.result-assignee')
                    if assignee_elem:
                        patent['assignee'] = assignee_elem.text.strip()

                    # Filing date
                    date_elem = result.select_one('.result-date')
                    if date_elem:
                        patent['filing_date'] = date_elem.text.strip()

                    # Abstract
                    abstract_elem = result.select_one('.result-abstract')
                    if abstract_elem:
                        patent['abstract'] = abstract_elem.text.strip()

                    if patent.get('title'):
                        patents.append(patent)

                return {
                    'status': 'success',
                    'count': len(patents),
                    'patents': patents,
                    'assignees': [p.get('assignee', '') for p in patents if p.get('assignee')],
                    'inventors': []
                }
            else:
                return {'status': 'error', 'error': f'HTTP {resp.status_code}'}

        except Exception as e:
            return {'status': 'error', 'error': str(e)}

    def search_uspto(self, query, limit=10):
        """Search USPTO Patent Database"""
        import urllib.parse
        from bs4 import BeautifulSoup

        # USPTO uses a more complex search interface
        # This is a simplified version - in practice, USPTO search is complex
        search_url = f"https://patft.uspto.gov/netacgi/nph-Parser?Sect1=PTO2&Sect2=HITOFF&p=1&u=%2Fnetahtml%2FPTO%2Fsearch-adv.htm&r=0&f=S&l=50&Query={urllib.parse.quote(query)}"
        patents = []

        try:
            resp = self.request_with_fallback('get', search_url, timeout=15, allow_fallback=True)
            if resp.status_code == 200:
                soup = BeautifulSoup(resp.text, 'html.parser')

                # Find patent results (this selector may need adjustment)
                results = soup.select('table tr')

                for result in results[1:limit+1]:  # Skip header row
                    patent = {}

                    cells = result.select('td')
                    if len(cells) >= 3:
                        patent['patent_number'] = cells[1].text.strip()
                        patent['title'] = cells[2].text.strip()

                    if patent.get('title'):
                        patents.append(patent)

                return {
                    'status': 'success',
                    'count': len(patents),
                    'patents': patents,
                    'assignees': [],
                    'inventors': []
                }
            else:
                return {'status': 'error', 'error': f'HTTP {resp.status_code}'}

        except Exception as e:
            return {'status': 'error', 'error': str(e)}

    def search_espacenet(self, query, limit=10):
        """Search Espacenet"""
        import urllib.parse
        from bs4 import BeautifulSoup

        search_url = f"https://worldwide.espacenet.com/patent/search?q={urllib.parse.quote(query)}"
        patents = []

        try:
            resp = self.request_with_fallback('get', search_url, timeout=15, allow_fallback=True)
            if resp.status_code == 200:
                soup = BeautifulSoup(resp.text, 'html.parser')

                # Find patent results
                results = soup.select('.patent-result, .result-item')

                for result in results[:limit]:
                    patent = {}

                    # Title
                    title_elem = result.select_one('.title, .patent-title')
                    if title_elem:
                        patent['title'] = title_elem.text.strip()

                    # Patent number
                    number_elem = result.select_one('.number, .patent-number')
                    if number_elem:
                        patent['patent_number'] = number_elem.text.strip()

                    # Applicant
                    applicant_elem = result.select_one('.applicant, .assignee')
                    if applicant_elem:
                        patent['assignee'] = applicant_elem.text.strip()

                    if patent.get('title'):
                        patents.append(patent)

                return {
                    'status': 'success',
                    'count': len(patents),
                    'patents': patents,
                    'assignees': [p.get('assignee', '') for p in patents if p.get('assignee')],
                    'inventors': []
                }
            else:
                return {'status': 'error', 'error': f'HTTP {resp.status_code}'}

        except Exception as e:
            return {'status': 'error', 'error': str(e)}

    def search_wipo(self, query, limit=10):
        """Search WIPO PATENTSCOPE"""
        # WIPO search is complex, simplified version
        search_url = "https://patentscope.wipo.int/search/en/search.jsf"

        try:
            # For WIPO, we might need to POST search data
            # This is a simplified GET version
            resp = self.request_with_fallback('get', search_url, timeout=15, allow_fallback=True)
            if resp.status_code == 200:
                # WIPO search requires form submission, this is just a placeholder
                return {
                    'status': 'success',
                    'count': 0,
                    'patents': [],
                    'assignees': [],
                    'inventors': [],
                    'note': 'WIPO search requires form submission - implement POST request'
                }
            else:
                return {'status': 'error', 'error': f'HTTP {resp.status_code}'}

        except Exception as e:
            return {'status': 'error', 'error': str(e)}

    def get_patent_details(self, patent_number, source='google_patents'):
        """
        Get detailed information about a specific patent
        """
        if source == 'google_patents':
            return self.get_google_patent_details(patent_number)
        else:
            return {'status': 'error', 'error': f'Detailed search not implemented for {source}'}

    def get_google_patent_details(self, patent_number):
        """Get detailed patent information from Google Patents"""
        from bs4 import BeautifulSoup

        url = f"https://patents.google.com/patent/{patent_number}/en"
        try:
            resp = self.request_with_fallback('get', url, timeout=15, allow_fallback=True)
            if resp.status_code == 200:
                soup = BeautifulSoup(resp.text, 'html.parser')

                details = {
                    'patent_number': patent_number,
                    'title': '',
                    'abstract': '',
                    'description': '',
                    'claims': '',
                    'inventors': [],
                    'assignee': '',
                    'filing_date': '',
                    'publication_date': '',
                    'patent_citations': [],
                    'non_patent_citations': []
                }

                # Extract title
                title_elem = soup.select_one('h1')
                if title_elem:
                    details['title'] = title_elem.text.strip()

                # Extract abstract
                abstract_elem = soup.select_one('.abstract')
                if abstract_elem:
                    details['abstract'] = abstract_elem.text.strip()

                # Extract inventors
                inventor_elems = soup.select('.inventor')
                details['inventors'] = [inv.text.strip() for inv in inventor_elems]

                # Extract assignee
                assignee_elem = soup.select_one('.assignee')
                if assignee_elem:
                    details['assignee'] = assignee_elem.text.strip()

                return {'status': 'success', 'patent_details': details}
            else:
                return {'status': 'error', 'error': f'HTTP {resp.status_code}'}

        except Exception as e:
            return {'status': 'error', 'error': str(e)}

    def _deduplicate_patents(self, patents):
        """Remove duplicate patents based on patent number"""
        seen_numbers = set()
        unique_patents = []

        for patent in patents:
            number = patent.get('patent_number', '').strip()
            if number and number not in seen_numbers:
                seen_numbers.add(number)
                unique_patents.append(patent)

        return unique_patents