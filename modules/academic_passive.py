"""
Academic and Research Paper Passive Intelligence Module
Search academic databases and research repositories for intelligence gathering
"""

from utils.osint_utils import OSINTUtils
from bs4 import BeautifulSoup
import urllib.parse


class AcademicPassive(OSINTUtils):
    def __init__(self):
        super().__init__()
        self.sources = {
            'google_scholar': {
                'name': 'Google Scholar',
                'url': 'https://scholar.google.com',
                'search_url': 'https://scholar.google.com/scholar?q={query}'
            },
            'semanticscholar': {
                'name': 'Semantic Scholar',
                'url': 'https://www.semanticscholar.org',
                'search_url': 'https://www.semanticscholar.org/search?q={query}'
            },
            'arxiv': {
                'name': 'arXiv',
                'url': 'https://arxiv.org',
                'search_url': 'https://arxiv.org/search/?query={query}&searchtype=all'
            },
            'pubmed': {
                'name': 'PubMed',
                'url': 'https://pubmed.ncbi.nlm.nih.gov',
                'search_url': 'https://pubmed.ncbi.nlm.nih.gov/?term={query}'
            },
            'researchgate': {
                'name': 'ResearchGate',
                'url': 'https://www.researchgate.net',
                'search_url': 'https://www.researchgate.net/search/publication?q={query}'
            },
            'academia_edu': {
                'name': 'Academia.edu',
                'url': 'https://www.academia.edu',
                'search_url': 'https://www.academia.edu/search?q={query}'
            }
        }

    def search_academic_sources(self, query, limit=10):
        """
        Search across multiple academic and research sources for papers and publications
        """
        results = {
            'query': query,
            'sources_searched': len(self.sources),
            'total_results': 0,
            'papers': [],
            'authors': [],
            'institutions': []
        }

        for source_key, source_info in self.sources.items():
            try:
                source_results = self.search_single_source(source_key, query, limit)
                if source_results['status'] == 'success':
                    results['papers'].extend(source_results.get('papers', []))
                    results['authors'].extend(source_results.get('authors', []))
                    results['institutions'].extend(source_results.get('institutions', []))
                    results['total_results'] += source_results.get('count', 0)
            except Exception as e:
                self.logger.warning(f"Error searching {source_info['name']}: {e}")

        # Remove duplicates and limit results
        results['papers'] = self._deduplicate_papers(results['papers'][:limit*2])
        results['authors'] = list(set(results['authors']))[:limit]
        results['institutions'] = list(set(results['institutions']))[:limit]

        return results

    def search_single_source(self, source, query, limit=10):
        """
        Search a specific academic source
        """
        if source == 'google_scholar':
            return self.search_google_scholar(query, limit)
        elif source == 'semanticscholar':
            return self.search_semantic_scholar(query, limit)
        elif source == 'arxiv':
            return self.search_arxiv(query, limit)
        elif source == 'pubmed':
            return self.search_pubmed(query, limit)
        elif source == 'researchgate':
            return self.search_researchgate(query, limit)
        elif source == 'academia_edu':
            return self.search_academia_edu(query, limit)
        else:
            return {'status': 'error', 'error': f'Unknown source: {source}'}

    def search_google_scholar(self, query, limit=10):
        """Search Google Scholar"""

        search_url = f"https://scholar.google.com/scholar?q={urllib.parse.quote(query)}"
        papers = []

        try:
            resp = self.request_with_fallback('get', search_url, timeout=15, allow_fallback=True)
            if resp.status_code == 200:
                soup = BeautifulSoup(resp.text, 'html.parser')

                # Find paper results
                results = soup.select('.gs_r, .gs_ri')

                for result in results[:limit]:
                    paper = {}

                    # Title and link
                    title_elem = result.select_one('.gs_rt a')
                    if title_elem:
                        paper['title'] = title_elem.text.strip()
                        paper['url'] = title_elem.get('href')

                    # Authors
                    author_elem = result.select_one('.gs_a')
                    if author_elem:
                        paper['authors'] = author_elem.text.strip()

                    # Abstract/snippet
                    snippet_elem = result.select_one('.gs_rs')
                    if snippet_elem:
                        paper['snippet'] = snippet_elem.text.strip()

                    # Citation count
                    cite_elem = result.select_one('.gs_fl a')
                    if cite_elem and 'Cited by' in cite_elem.text:
                        paper['citations'] = cite_elem.text.replace('Cited by ', '')

                    if paper.get('title'):
                        papers.append(paper)

                return {
                    'status': 'success',
                    'count': len(papers),
                    'papers': papers,
                    'authors': [p.get('authors', '') for p in papers if p.get('authors')],
                    'institutions': []
                }
            else:
                return {'status': 'error', 'error': f'HTTP {resp.status_code}'}

        except Exception as e:
            return {'status': 'error', 'error': str(e)}

    def search_semantic_scholar(self, query, limit=10):
        """Search Semantic Scholar"""

        search_url = f"https://www.semanticscholar.org/search?q={urllib.parse.quote(query)}"
        papers = []

        try:
            resp = self.request_with_fallback('get', search_url, timeout=15, allow_fallback=True)
            if resp.status_code == 200:
                soup = BeautifulSoup(resp.text, 'html.parser')

                # Find paper results
                results = soup.select('.cl-paper-row, .paper')

                for result in results[:limit]:
                    paper = {}

                    # Title
                    title_elem = result.select_one('.cl-paper-title, .title')
                    if title_elem:
                        paper['title'] = title_elem.text.strip()

                    # Authors
                    author_elem = result.select_one('.cl-paper-authors, .authors')
                    if author_elem:
                        paper['authors'] = author_elem.text.strip()

                    # Venue/year
                    venue_elem = result.select_one('.cl-paper-venue, .venue')
                    if venue_elem:
                        paper['venue'] = venue_elem.text.strip()

                    if paper.get('title'):
                        papers.append(paper)

                return {
                    'status': 'success',
                    'count': len(papers),
                    'papers': papers,
                    'authors': [p.get('authors', '') for p in papers if p.get('authors')],
                    'institutions': []
                }
            else:
                return {'status': 'error', 'error': f'HTTP {resp.status_code}'}

        except Exception as e:
            return {'status': 'error', 'error': str(e)}

    def search_arxiv(self, query, limit=10):
        """Search arXiv"""

        search_url = f"https://arxiv.org/search/?query={urllib.parse.quote(query)}&searchtype=all"
        papers = []

        try:
            resp = self.request_with_fallback('get', search_url, timeout=15, allow_fallback=True)
            if resp.status_code == 200:
                soup = BeautifulSoup(resp.text, 'html.parser')

                # Find paper results
                results = soup.select('.arxiv-result')

                for result in results[:limit]:
                    paper = {}

                    # Title
                    title_elem = result.select_one('.title')
                    if title_elem:
                        paper['title'] = title_elem.text.strip()

                    # Authors
                    author_elem = result.select_one('.authors')
                    if author_elem:
                        paper['authors'] = author_elem.text.strip()

                    # Abstract link
                    abstract_link = result.select_one('.abstract-link')
                    if abstract_link:
                        paper['url'] = 'https://arxiv.org' + abstract_link.get('href')

                    # Date
                    date_elem = result.select_one('.submitted-date')
                    if date_elem:
                        paper['date'] = date_elem.text.strip()

                    if paper.get('title'):
                        papers.append(paper)

                return {
                    'status': 'success',
                    'count': len(papers),
                    'papers': papers,
                    'authors': [p.get('authors', '') for p in papers if p.get('authors')],
                    'institutions': []
                }
            else:
                return {'status': 'error', 'error': f'HTTP {resp.status_code}'}

        except Exception as e:
            return {'status': 'error', 'error': str(e)}

    def search_pubmed(self, query, limit=10):
        """Search PubMed"""

        search_url = f"https://pubmed.ncbi.nlm.nih.gov/?term={urllib.parse.quote(query)}"
        papers = []

        try:
            resp = self.request_with_fallback('get', search_url, timeout=15, allow_fallback=True)
            if resp.status_code == 200:
                soup = BeautifulSoup(resp.text, 'html.parser')

                # Find paper results
                results = soup.select('.docsum-content')

                for result in results[:limit]:
                    paper = {}

                    # Title
                    title_elem = result.select_one('.docsum-title')
                    if title_elem:
                        paper['title'] = title_elem.text.strip()

                    # Authors
                    author_elem = result.select_one('.docsum-authors')
                    if author_elem:
                        paper['authors'] = author_elem.text.strip()

                    # Journal
                    journal_elem = result.select_one('.docsum-journal-citation')
                    if journal_elem:
                        paper['journal'] = journal_elem.text.strip()

                    if paper.get('title'):
                        papers.append(paper)

                return {
                    'status': 'success',
                    'count': len(papers),
                    'papers': papers,
                    'authors': [p.get('authors', '') for p in papers if p.get('authors')],
                    'institutions': []
                }
            else:
                return {'status': 'error', 'error': f'HTTP {resp.status_code}'}

        except Exception as e:
            return {'status': 'error', 'error': str(e)}

    def search_researchgate(self, query, limit=10):
        """Search ResearchGate"""

        search_url = f"https://www.researchgate.net/search/publication?q={urllib.parse.quote(query)}"
        papers = []

        try:
            resp = self.request_with_fallback('get', search_url, timeout=15, allow_fallback=True)
            if resp.status_code == 200:
                soup = BeautifulSoup(resp.text, 'html.parser')

                # Find publication results
                results = soup.select('.publication')

                for result in results[:limit]:
                    paper = {}

                    # Title
                    title_elem = result.select_one('.publication-title')
                    if title_elem:
                        paper['title'] = title_elem.text.strip()

                    # Authors
                    author_elem = result.select_one('.publication-authors')
                    if author_elem:
                        paper['authors'] = author_elem.text.strip()

                    if paper.get('title'):
                        papers.append(paper)

                return {
                    'status': 'success',
                    'count': len(papers),
                    'papers': papers,
                    'authors': [p.get('authors', '') for p in papers if p.get('authors')],
                    'institutions': []
                }
            else:
                return {'status': 'error', 'error': f'HTTP {resp.status_code}'}

        except Exception as e:
            return {'status': 'error', 'error': str(e)}

    def search_academia_edu(self, query, limit=10):
        """Search Academia.edu"""

        search_url = f"https://www.academia.edu/search?q={urllib.parse.quote(query)}"
        papers = []

        try:
            resp = self.request_with_fallback('get', search_url, timeout=15, allow_fallback=True)
            if resp.status_code == 200:
                soup = BeautifulSoup(resp.text, 'html.parser')

                # Find document results
                results = soup.select('.document')

                for result in results[:limit]:
                    paper = {}

                    # Title
                    title_elem = result.select_one('.document-title')
                    if title_elem:
                        paper['title'] = title_elem.text.strip()

                    # Authors
                    author_elem = result.select_one('.document-authors')
                    if author_elem:
                        paper['authors'] = author_elem.text.strip()

                    if paper.get('title'):
                        papers.append(paper)

                return {
                    'status': 'success',
                    'count': len(papers),
                    'papers': papers,
                    'authors': [p.get('authors', '') for p in papers if p.get('authors')],
                    'institutions': []
                }
            else:
                return {'status': 'error', 'error': f'HTTP {resp.status_code}'}

        except Exception as e:
            return {'status': 'error', 'error': str(e)}

    def _deduplicate_papers(self, papers):
        """Remove duplicate papers based on title"""
        seen_titles = set()
        unique_papers = []

        for paper in papers:
            title = paper.get('title', '').lower().strip()
            if title and title not in seen_titles:
                seen_titles.add(title)
                unique_papers.append(paper)

        return unique_papers