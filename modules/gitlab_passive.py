"""
GitLab Passive Intelligence Module
Search public GitLab repositories and projects for intelligence gathering
"""

from utils.osint_utils import OSINTUtils
from bs4 import BeautifulSoup
import re


class GitLabPassive(OSINTUtils):
    def __init__(self):
        super().__init__()
        self.base_url = "https://gitlab.com"
        self.results = {}

    def search_repositories(self, keyword, limit=20):
        """
        Search GitLab for public repositories matching a keyword (no login, OPSEC safe).
        Returns repository information including URLs, descriptions, and metadata.
        """
        url = f"{self.base_url}/search?search={keyword}&scope=projects"
        repositories = []

        try:
            resp = self.request_with_fallback('get', url, timeout=20, allow_fallback=True)
            if resp and resp.status_code == 200:
                soup = BeautifulSoup(resp.text, "html.parser")

                # Find repository cards
                repo_cards = soup.select("li.project-row, .project-row")

                for card in repo_cards[:limit]:
                    repo_info = {}

                    # Extract repository name and URL
                    title_link = card.select_one("a.text-plain")
                    if title_link:
                        repo_info['name'] = title_link.text.strip()
                        href = title_link.get('href')
                        if href:
                            repo_info['url'] = self.base_url + str(href)

                    # Extract description
                    desc_elem = card.select_one("p.description, .description")
                    if desc_elem:
                        repo_info['description'] = desc_elem.text.strip()

                    # Extract metadata (stars, forks, etc.)
                    stats = card.select(".project-stats, .stats")
                    if stats:
                        for stat in stats:
                            text = stat.text.strip()
                            if 'star' in text.lower():
                                repo_info['stars'] = re.search(r'\d+', text)
                                repo_info['stars'] = repo_info['stars'].group() if repo_info['stars'] else '0'
                            elif 'fork' in text.lower():
                                repo_info['forks'] = re.search(r'\d+', text)
                                repo_info['forks'] = repo_info['forks'].group() if repo_info['forks'] else '0'

                    # Extract last updated
                    updated_elem = card.select_one(".updated-at, .time")
                    if updated_elem:
                        repo_info['last_updated'] = updated_elem.text.strip()

                    # Extract programming language
                    lang_elem = card.select_one(".language, .lang")
                    if lang_elem:
                        repo_info['language'] = lang_elem.text.strip()

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
        Search for GitLab users (passive, no authentication required)
        """
        url = f"{self.base_url}/search?search={username}&scope=users"
        users = []

        try:
            resp = self.request_with_fallback('get', url, timeout=15, allow_fallback=True)
            if resp and resp.status_code == 200:
                soup = BeautifulSoup(resp.text, "html.parser")

                user_cards = soup.select("li.user-row, .user-result")

                for card in user_cards[:limit]:
                    user_info = {}

                    name_link = card.select_one("a.user-link")
                    if name_link:
                        user_info['username'] = name_link.text.strip()
                        href = name_link.get('href')
                        if href:
                            user_info['profile_url'] = self.base_url + str(href)

                    bio_elem = card.select_one(".bio, .user-bio")
                    if bio_elem:
                        user_info['bio'] = bio_elem.text.strip()

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
        Extract detailed information from a specific GitLab repository page
        """
        try:
            resp = self.request_with_fallback('get', repo_url, timeout=15, allow_fallback=True)
            if resp and resp.status_code == 200:
                soup = BeautifulSoup(resp.text, "html.parser")

                info = {
                    'url': repo_url,
                    'name': '',
                    'description': '',
                    'stars': '0',
                    'forks': '0',
                    'language': '',
                    'license': '',
                    'last_commit': '',
                    'readme_preview': ''
                }

                # Extract repository name
                name_elem = soup.select_one("h1.project-title, .project-title")
                if name_elem:
                    info['name'] = name_elem.text.strip()

                # Extract description
                desc_elem = soup.select_one(".project-description, .description")
                if desc_elem:
                    info['description'] = desc_elem.text.strip()

                # Extract stats
                stats = soup.select(".project-stats .stat, .stats .stat")
                for stat in stats:
                    text = stat.text.strip()
                    if 'star' in text.lower():
                        stars_match = re.search(r'(\d+)', text)
                        info['stars'] = stars_match.group(1) if stars_match else '0'
                    elif 'fork' in text.lower():
                        forks_match = re.search(r'(\d+)', text)
                        info['forks'] = forks_match.group(1) if forks_match else '0'

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