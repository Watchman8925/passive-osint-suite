"""
Company and Organization Intelligence Module
Corporate investigation and business intelligence
"""

from datetime import datetime

import requests

from utils.osint_utils import OSINTUtils


class CompanyIntelligence(OSINTUtils):
    def __init__(self):
        super().__init__()
        self.results = {}

    def analyze_company(self, company_name, domain=None):
        """Comprehensive company analysis"""
        self.logger.info(f"Starting company analysis for: {company_name}")

        self.results = {
            "company_name": company_name,
            "domain": domain,
            "timestamp": datetime.now().isoformat(),
            "company_info": self.get_company_info(company_name),
            "domain_analysis": self.analyze_company_domain(domain) if domain else {},
            "social_presence": self.find_company_social_presence(company_name, domain),
            "employees": self.find_employees(company_name, domain),
            "financial_info": self.get_financial_info(company_name),
            "news_mentions": self.get_news_mentions(company_name),
            "technology_stack": self.get_technology_stack(domain) if domain else {},
            "opencorporates_data": self.get_opencorporates_data(company_name),
        }

        return self.results

    def get_company_info(self, company_name):
        """Get basic company information"""
        company_data = {
            "clearbit": self.get_clearbit_company_info(company_name),
            "fullcontact": self.get_fullcontact_company_info(company_name),
            "abstract_api": self.get_abstractapi_company_info(company_name),
        }
        return company_data

    def get_clearbit_company_info(self, company_name):
        """Get company info from Clearbit"""
        api_key = self.get_api_key("CLEARBIT_API_KEY")
        if not api_key:
            return {"error": "No API key"}

        try:
            url = "https://company.clearbit.com/v2/companies/find"
            params = {"name": company_name}
            headers = {"Authorization": f"Bearer {api_key}"}

            response = self.make_request(url, headers=headers, params=params)
            if response and response.status_code == 200:
                data = response.json()
                return {
                    "name": data.get("name"),
                    "domain": data.get("domain"),
                    "description": data.get("description"),
                    "founded_year": data.get("foundedYear"),
                    "employees": data.get("metrics", {}).get("employees"),
                    "estimated_annual_revenue": data.get("metrics", {}).get(
                        "estimatedAnnualRevenue"
                    ),
                    "industry": data.get("category", {}).get("industry"),
                    "location": data.get("geo", {}),
                    "social_handles": data.get("twitter", {}),
                    "logo": data.get("logo"),
                    "phone": data.get("phone"),
                    "tech_stack": data.get("tech", []),
                }
            elif response.status_code == 202:
                return {"status": "lookup_queued"}

        except Exception as e:
            self.logger.error(f"Clearbit company lookup failed: {e}")
            return {"error": str(e)}

    def get_fullcontact_company_info(self, company_name):
        """Get company info from FullContact"""
        api_key = self.get_api_key("FULLCONTACT_API_KEY")
        if not api_key:
            return {"error": "No API key"}

        try:
            url = "https://api.fullcontact.com/v3/company.enrich"
            headers = {
                "Authorization": f"Bearer {api_key}",
                "Content-Type": "application/json",
            }
            data = {"domain": company_name}

            response = self.utils.tor_post(url, headers=headers, json=data, timeout=30)
            if response.status_code == 200:
                return response.json()

        except Exception as e:
            self.logger.error(f"FullContact company lookup failed: {e}")
            return {"error": str(e)}

    def get_abstractapi_company_info(self, company_name):
        """Get company info from AbstractAPI"""
        api_key = self.get_api_key("ABSTRACTAPI_COMPANY_ENRICHMENT")
        if not api_key:
            return {"error": "No API key"}

        try:
            url = "https://companyenrichment.abstractapi.com/v1/"
            params = {
                "api_key": api_key,
                "domain": (
                    company_name if "." in company_name else f"{company_name}.com"
                ),
            }

            response = self.make_request(url, params=params)
            if response:
                return response.json()

        except Exception as e:
            self.logger.error(f"AbstractAPI company lookup failed: {e}")
            return {"error": str(e)}

    def analyze_company_domain(self, domain):
        """Analyze company domain"""
        if not domain:
            return {}

        # Use the injected domain_recon instance
        return self.domain_recon.analyze_domain(domain)

    def find_company_social_presence(self, company_name, domain=None):
        """Find company social media presence"""
        social_profiles = {}

        # Generate potential usernames
        username_variants = [
            company_name.lower().replace(" ", ""),
            company_name.lower().replace(" ", "_"),
            company_name.lower().replace(" ", "-"),
        ]

        if domain:
            domain_name = domain.split(".")[0]
            username_variants.append(domain_name.lower())

        platforms = {
            "linkedin": "https://linkedin.com/company/",
            "twitter": "https://twitter.com/",
            "facebook": "https://facebook.com/",
            "instagram": "https://instagram.com/",
            "youtube": "https://youtube.com/c/",
            "github": "https://github.com/",
        }

        for platform, base_url in platforms.items():
            for username in username_variants:
                try:
                    url = f"{base_url}{username}"
                    response = self.make_request(url, timeout=10)
                    if response and response.status_code == 200:
                        social_profiles[platform] = url
                        break  # Found valid profile, move to next platform
                except (requests.RequestException, ConnectionError, TimeoutError):
                    continue

        return social_profiles

    def find_employees(self, company_name, domain=None):
        """Find company employees"""
        employees_data = {
            "hunter_emails": self.get_hunter_company_emails(domain) if domain else {},
            "linkedin_employees": self.find_linkedin_employees(company_name),
        }
        return employees_data

    def get_hunter_company_emails(self, domain):
        """Get company emails from Hunter.io"""
        api_key = self.get_api_key("HUNTER_API_KEY")
        if not api_key:
            return {"error": "No API key"}

        try:
            url = "https://api.hunter.io/v2/domain-search"
            params = {"domain": domain, "api_key": api_key, "limit": 50}

            response = self.make_request(url, params=params)
            if response:
                data = response.json()

                emails_info = {
                    "domain": data.get("data", {}).get("domain"),
                    "organization": data.get("data", {}).get("organization"),
                    "pattern": data.get("data", {}).get("pattern"),
                    "total_emails": len(data.get("data", {}).get("emails", [])),
                    "employees": [],
                }

                for email_data in data.get("data", {}).get("emails", []):
                    employee = {
                        "email": email_data.get("value"),
                        "first_name": email_data.get("first_name"),
                        "last_name": email_data.get("last_name"),
                        "position": email_data.get("position"),
                        "department": email_data.get("department"),
                        "phone": email_data.get("phone_number"),
                        "linkedin": email_data.get("linkedin"),
                        "twitter": email_data.get("twitter"),
                    }
                    emails_info["employees"].append(employee)

                return emails_info

        except Exception as e:
            self.logger.error(f"Hunter company emails lookup failed: {e}")
            return {"error": str(e)}

    def find_linkedin_employees(self, company_name):
        """Find employees on LinkedIn (placeholder)"""
        # This would require LinkedIn API access or web scraping
        # For now, return placeholder
        return {
            "status": "not_implemented",
            "note": "Requires LinkedIn API or scraping",
        }

    def get_financial_info(self, company_name):
        """Get financial information"""
        financial_data = {
            "opencorporates": self.get_opencorporates_data(company_name),
            "sec_filings": self.search_sec_filings(company_name),
        }
        return financial_data

    def get_opencorporates_data(self, company_name):
        """Get data from OpenCorporates"""
        api_key = self.get_api_key("OPENCORPORATES_API_KEY")

        try:
            url = "https://api.opencorporates.com/v0.4/companies/search"
            params = {"q": company_name, "format": "json"}
            if api_key:
                params["api_token"] = api_key

            response = self.make_request(url, params=params)
            if response:
                data = response.json()

                companies = []
                for company in data.get("results", {}).get("companies", [])[
                    :10
                ]:  # Limit results
                    company_info = company.get("company", {})
                    companies.append(
                        {
                            "name": company_info.get("name"),
                            "company_number": company_info.get("company_number"),
                            "jurisdiction_code": company_info.get("jurisdiction_code"),
                            "incorporation_date": company_info.get(
                                "incorporation_date"
                            ),
                            "company_type": company_info.get("company_type"),
                            "status": company_info.get("current_status"),
                            "registered_address": company_info.get(
                                "registered_address_in_full"
                            ),
                            "opencorporates_url": company_info.get(
                                "opencorporates_url"
                            ),
                        }
                    )

                return {
                    "total_results": data.get("results", {}).get("total_count", 0),
                    "companies": companies,
                }

        except Exception as e:
            self.logger.error(f"OpenCorporates lookup failed: {e}")
            return {"error": str(e)}

    def search_sec_filings(self, company_name):
        """Search SEC filings (placeholder)"""
        # This would require SEC EDGAR API
        return {
            "status": "not_implemented",
            "note": "Requires SEC EDGAR API implementation",
        }

    def get_news_mentions(self, company_name):
        """Get news mentions"""
        news_data = {"google_news": self.search_google_news(company_name)}
        return news_data

    def search_google_news(self, company_name):
        """Search Google News"""
        api_key = self.get_api_key("GOOGLESEARCH_API_KEY")
        if not api_key:
            return {"error": "No API key"}

        try:
            # Use Google Custom Search API for news
            url = "https://www.googleapis.com/customsearch/v1"
            params = {
                "key": api_key,
                "q": f'"{company_name}" news',
                "num": 10,
                "sort": "date",
            }

            response = self.make_request(url, params=params)
            if response:
                data = response.json()

                news_items = []
                for item in data.get("items", []):
                    news_items.append(
                        {
                            "title": item.get("title"),
                            "link": item.get("link"),
                            "snippet": item.get("snippet"),
                            "display_link": item.get("displayLink"),
                        }
                    )

                return {
                    "total_results": data.get("searchInformation", {}).get(
                        "totalResults"
                    ),
                    "news_items": news_items,
                }

        except Exception as e:
            self.logger.error(f"Google News search failed: {e}")
            return {"error": str(e)}

    def get_technology_stack(self, domain):
        """Get company technology stack"""
        builtwith_key = self.get_api_key("BUILTWITH_API_KEY")

        if not builtwith_key:
            return {"error": "No API key"}

        try:
            url = "https://api.builtwith.com/v20/api.json"
            params = {"KEY": builtwith_key, "LOOKUP": domain}

            response = self.make_request(url, params=params)
            if response:
                data = response.json()

                technologies = {}
                for result in data.get("Results", []):
                    for path in result.get("Result", {}).get("Paths", []):
                        for tech in path.get("Technologies", []):
                            category = tech.get("Categories", [{}])[0].get(
                                "Name", "Unknown"
                            )
                            if category not in technologies:
                                technologies[category] = []
                            technologies[category].append(
                                {
                                    "name": tech.get("Name"),
                                    "version": tech.get("Version"),
                                    "description": tech.get("Description"),
                                }
                            )

                return technologies

        except Exception as e:
            self.logger.error(f"BuiltWith lookup failed: {e}")
            return {"error": str(e)}

    def generate_report(self):
        """Generate comprehensive company intelligence report"""
        if not self.results:
            return "No analysis results available"

        report = f"""
# Company Intelligence Report: {self.results['company_name']}
Generated: {self.results['timestamp']}

## Company Information
"""

        # Add basic company info
        company_info = self.results.get("company_info", {})
        clearbit_data = company_info.get("clearbit", {})

        if "name" in clearbit_data:
            report += f"Name: {clearbit_data.get('name')}\n"
            report += f"Domain: {clearbit_data.get('domain')}\n"
            report += f"Industry: {clearbit_data.get('industry')}\n"
            report += f"Founded: {clearbit_data.get('founded_year')}\n"
            report += f"Employees: {clearbit_data.get('employees')}\n"
            report += f"Description: {clearbit_data.get('description')}\n"

        # Add social presence
        social_presence = self.results.get("social_presence", {})
        if social_presence:
            report += "\n## Social Media Presence\n"
            for platform, url in social_presence.items():
                report += f"- {platform.title()}: {url}\n"

        # Add employee information
        employees = self.results.get("employees", {})
        hunter_data = employees.get("hunter_emails", {})

        if "total_emails" in hunter_data:
            report += "\n## Employee Information\n"
            report += f"Total Emails Found: {hunter_data['total_emails']}\n"
            report += f"Email Pattern: {hunter_data.get('pattern')}\n"

            if hunter_data.get("employees"):
                report += "\nKey Personnel:\n"
                for emp in hunter_data["employees"][:10]:  # Limit to first 10
                    name = f"{emp.get('first_name', '')} {emp.get('last_name', '')}".strip()
                    position = emp.get("position", "")
                    if name and position:
                        report += f"- {name} - {position}\n"

        # Add OpenCorporates data
        opencorporates = self.results.get("opencorporates_data", {})
        if "companies" in opencorporates and opencorporates["companies"]:
            report += "\n## Corporate Registrations\n"
            for company in opencorporates["companies"][:5]:  # Limit to first 5
                report += (
                    f"- {company.get('name')} ({company.get('jurisdiction_code')})\n"
                )
                if company.get("incorporation_date"):
                    report += f"  Incorporated: {company['incorporation_date']}\n"
                if company.get("status"):
                    report += f"  Status: {company['status']}\n"

        return report
