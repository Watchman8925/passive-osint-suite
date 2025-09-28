"""
Bitbucket Passive Intelligence Module
Search public Bitbucket repositories and projects for intelligence gathering
"""

from utils.osint_utils import OSINTUtils
from bs4 import BeautifulSoup


class BitbucketPassive(OSINTUtils):
    def __init__(self):
        super().__init__()
        self.base_url = "https://bitbucket.org"
        self.results = {}

    def search_repositories(self, keyword, limit=20):
        """
        Search Bitbucket for public repositories matching a keyword (no login, OPSEC safe).
        Returns repository information including URLs, descriptions, and metadata.
        """
        url = f"{self.base_url}/search?q={keyword}&type=repositories"
        repositories = []

        try:
            resp = self.request_with_fallback('get', url, timeout=20, allow_fallback=True)
            if resp and resp.status_code == 200:
                soup = BeautifulSoup(resp.text, "html.parser")

                # Find repository results
                repo_cards = soup.select(".search-result, .repo-result, .repository")

                for card in repo_cards[:limit]:
                    repo_info = {}

                    # Extract repository name and URL
                    title_link = card.select_one("a[href*='/'], h3 a")
                    if title_link:
                        repo_info['name'] = title_link.text.strip()
                        href = title_link.get('href')
                        if href:
                            href_str = str(href)
                            if not href_str.startswith('http'):
                                repo_info['url'] = self.base_url + href_str
                            else:
                                repo_info['url'] = href_str

                    # Extract description
                    desc_elem = card.select_one("p, .description")
                    if desc_elem:
                        repo_info['description'] = desc_elem.text.strip()

                    # Extract owner/workspace
                    owner_elem = card.select_one(".owner, .workspace")
                    if owner_elem:
                        repo_info['owner'] = owner_elem.text.strip()

                    # Extract language
                    lang_elem = card.select_one(".language, .lang")
                    if lang_elem:
                        repo_info['language'] = lang_elem.text.strip()

                    # Extract last updated
                    updated_elem = card.select_one(".updated, .date")
                    if updated_elem:
                        repo_info['last_updated'] = updated_elem.text.strip()

                    if repo_info.get('name'):
                        repositories.append(repo_info)

                return {
                    "status": "success",
                    "total_found": len(repositories),
                    "repositories": repositories
                }
            else:
                status_code = resp.status_code if resp else "unknown"
                return {"status": "error", "error": f"HTTP {status_code}"}

        except Exception as e:
            return {"status": "error", "error": str(e)}

    def search_users(self, username, limit=10):
        """
        Search for Bitbucket users (passive, no authentication required)
        """
        url = f"{self.base_url}/search?q={username}&type=users"
        users = []

        try:
            resp = self.request_with_fallback('get', url, timeout=15, allow_fallback=True)
            if resp and resp.status_code == 200:
                soup = BeautifulSoup(resp.text, "html.parser")

                user_cards = soup.select(".user-result, .search-result")

                for card in user_cards[:limit]:
                    user_info = {}

                    name_link = card.select_one("a[href*='/'], h3 a")
                    if name_link:
                        user_info['username'] = name_link.text.strip()
                        href = name_link.get('href')
                        if href:
                            href_str = str(href)
                            if not href_str.startswith('http'):
                                user_info['profile_url'] = self.base_url + href_str
                            else:
                                user_info['profile_url'] = href_str

                    bio_elem = card.select_one(".bio, .description")
                    if bio_elem:
                        user_info['bio'] = bio_elem.text.strip()

                    location_elem = card.select_one(".location")
                    if location_elem:
                        user_info['location'] = location_elem.text.strip()

                    if user_info.get('username'):
                        users.append(user_info)

                return {
                    "status": "success",
                    "total_found": len(users),
                    "users": users
                }
            else:
                status_code = resp.status_code if resp else "unknown"
                return {"status": "error", "error": f"HTTP {status_code}"}

        except Exception as e:
            return {"status": "error", "error": str(e)}

    def get_repository_info(self, repo_url):
        """
        Extract detailed information from a specific Bitbucket repository page
        """
        try:
            resp = self.request_with_fallback('get', repo_url, timeout=15, allow_fallback=True)
            if resp and resp.status_code == 200:
                soup = BeautifulSoup(resp.text, "html.parser")

                info = {
                    'url': repo_url,
                    'name': '',
                    'description': '',
                    'owner': '',
                    'language': '',
                    'size': '',
                    'last_commit': '',
                    'readme_preview': ''
                }

                # Extract repository name
                name_elem = soup.select_one("h1, .repo-name")
                if name_elem:
                    info['name'] = name_elem.text.strip()

                # Extract owner
                owner_elem = soup.select_one(".owner, .workspace")
                if owner_elem:
                    info['owner'] = owner_elem.text.strip()

                # Extract description
                desc_elem = soup.select_one(".description, p.summary")
                if desc_elem:
                    info['description'] = desc_elem.text.strip()

                # Extract language
                lang_elem = soup.select_one(".language, .lang")
                if lang_elem:
                    info['language'] = lang_elem.text.strip()

                # Extract README preview
                readme_elem = soup.select_one("#readme, .readme")
                if readme_elem:
                    # Get first few paragraphs
                    paragraphs = readme_elem.select("p")
                    preview = ' '.join([p.text.strip() for p in paragraphs[:3]])
                    info['readme_preview'] = preview[:500] + '...' if len(preview) > 500 else preview

                return {"status": "success", "repository_info": info}
            else:
                status_code = resp.status_code if resp else "unknown"
                return {"status": "error", "error": f"HTTP {status_code}"}

        except Exception as e:
            return {"status": "error", "error": str(e)}