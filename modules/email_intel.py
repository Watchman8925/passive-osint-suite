"""
Email Intelligence Module
Comprehensive email investigation and analysis
"""

from datetime import datetime

from utils.osint_utils import OSINTUtils


class EmailIntelligence(OSINTUtils):
    def __init__(self):
        super().__init__()
        self.results = {}

    def analyze_email(self, email):
        """Comprehensive email analysis"""
        self.logger.info(f"Starting email analysis for: {email}")

        if not self.validate_input(email, "email"):
            self.logger.error(f"Invalid email format: {email}")
            return {"status": "error", "error": f"Invalid email format: {email}"}

        try:
            self.results = {
                "email": email,
                "timestamp": datetime.now().isoformat(),
                "domain_info": self.analyze_email_domain(email),
                "breach_data": self.check_data_breaches(email),
                "reputation": self.check_email_reputation(email),
                "social_profiles": self.find_social_profiles(email),
                "related_emails": self.find_related_emails(email),
                "hunter_info": self.get_hunter_info(email),
                "clearbit_info": self.get_clearbit_info(email),
            }

            return {"status": "success", "data": self.results}

        except Exception as e:
            self.logger.error(f"Email analysis failed: {e}")
            return {"status": "error", "error": str(e)}

    def analyze_email_domain(self, email):
        """Analyze the domain part of the email"""
        domain = email.split("@")[1]

        # Import and instantiate domain_recon module
        from .domain_recon import DomainRecon

        domain_recon = DomainRecon()
        domain_analysis = domain_recon.analyze_domain(domain)

        return {
            "domain": domain,
            "whois_info": domain_analysis.get("whois_info", {}),
            "dns_records": domain_analysis.get("dns_records", {}),
            "security_info": domain_analysis.get("security_info", {}),
        }

    def check_data_breaches(self, email):
        """Check for data breaches using multiple sources"""
        breach_data = {
            "haveibeenpwned": self.check_hibp(email),
            "dehashed": self.check_dehashed(email),
            "leakix": self.check_leakix(email),
        }
        return breach_data

    def check_hibp(self, email):
        """Check HaveIBeenPwned"""
        api_key = self.get_api_key("HAVEIBEENPWNED_API_KEY")
        if not api_key:
            return {"error": "No API key"}

        try:
            url = f"https://haveibeenpwned.com/api/v3/breachedaccount/{email}"
            headers = {"hibp-api-key": api_key, "User-Agent": "OSINT-Suite"}

            response = self.make_request(url, headers=headers)
            if response:
                if response.status_code == 200:
                    breaches = response.json()
                    return {
                        "found": True,
                        "breach_count": len(breaches),
                        "breaches": [
                            {
                                "name": b["Name"],
                                "date": b["BreachDate"],
                                "data_classes": b["DataClasses"],
                            }
                            for b in breaches
                        ],
                    }
                elif response.status_code == 404:
                    return {"found": False, "message": "No breaches found"}

        except Exception as e:
            self.logger.error(f"HIBP lookup failed: {e}")
            return {"error": str(e)}

    def check_dehashed(self, email):
        """Check Dehashed for breach data"""
        api_key = self.get_api_key("DEHASHED_API_KEY")
        username = self.get_api_key("DEHASHED_USERNAME")

        if not api_key or not username:
            return {"error": "No API credentials"}

        try:
            url = "https://api.dehashed.com/search"
            params = {"query": f"email:{email}"}
            auth = (username, api_key)

            response = self.utils.request_with_fallback(
                "get", url, params=params, timeout=30, allow_fallback=True, auth=auth
            )
            if response.status_code == 200:
                data = response.json()
                return {
                    "found": len(data.get("entries", [])) > 0,
                    "entry_count": len(data.get("entries", [])),
                    "entries": data.get("entries", [])[:10],  # Limit results
                }

        except Exception as e:
            self.logger.error(f"Dehashed lookup failed: {e}")
            return {"error": str(e)}

    def check_leakix(self, email):
        """Check LeakIX for exposed data"""
        api_key = self.get_api_key("LEAKIX_API_KEY")
        if not api_key:
            return {"error": "No API key"}

        try:
            url = "https://leakix.net/search"
            headers = {"api-key": api_key}
            params = {"q": email}

            response = self.make_request(url, headers=headers, params=params)
            if response:
                return response.json()

        except Exception as e:
            self.logger.error(f"LeakIX lookup failed: {e}")
            return {"error": str(e)}

    def check_email_reputation(self, email):
        """Check email reputation across multiple services"""
        reputation_data = {
            "emailrep": self.check_emailrep(email),
            "hunter_verification": self.verify_hunter(email),
        }
        return reputation_data

    def check_emailrep(self, email):
        """Check EmailRep.io"""
        api_key = self.get_api_key("EMAILREP_API_KEY")

        try:
            url = f"https://emailrep.io/{email}"
            headers = {}
            if api_key:
                headers["Key"] = api_key

            response = self.make_request(url, headers=headers)
            if response:
                return response.json()

        except Exception as e:
            self.logger.error(f"EmailRep lookup failed: {e}")
            return {"error": str(e)}

    def verify_hunter(self, email):
        """Verify email using Hunter.io"""
        api_key = self.get_api_key("HUNTER_API_KEY")
        if not api_key:
            return {"error": "No API key"}

        try:
            url = "https://api.hunter.io/v2/email-verifier"
            params = {"email": email, "api_key": api_key}

            response = self.make_request(url, params=params)
            if response:
                data = response.json()
                return {
                    "result": data.get("data", {}).get("result"),
                    "score": data.get("data", {}).get("score"),
                    "regexp": data.get("data", {}).get("regexp"),
                    "gibberish": data.get("data", {}).get("gibberish"),
                    "disposable": data.get("data", {}).get("disposable"),
                    "webmail": data.get("data", {}).get("webmail"),
                    "mx_records": data.get("data", {}).get("mx_records"),
                    "smtp_server": data.get("data", {}).get("smtp_server"),
                }

        except Exception as e:
            self.logger.error(f"Hunter verification failed: {e}")
            return {"error": str(e)}

    def find_social_profiles(self, email):
        """Find social media profiles associated with email"""
        # This would typically use services like Pipl, Spokeo, etc.
        # For now, we'll check some common patterns

        username = email.split("@")[0]
        social_profiles = {}

        # Common social media platforms
        platforms = {
            "github": f"https://github.com/{username}",
            "twitter": f"https://twitter.com/{username}",
            "linkedin": f"https://linkedin.com/in/{username}",
            "instagram": f"https://instagram.com/{username}",
            "reddit": f"https://reddit.com/user/{username}",
        }

        for platform, url in platforms.items():
            try:
                response = self.make_request(url, timeout=10)
                if response and response.status_code == 200:
                    social_profiles[platform] = {"url": url, "status": "found"}
            except Exception:
                continue

        return social_profiles

    def find_related_emails(self, email):
        """Find related email addresses"""
        domain = email.split("@")[1]

        # Use Hunter.io to find related emails
        api_key = self.get_api_key("HUNTER_API_KEY")
        if not api_key:
            return {"error": "No API key"}

        try:
            url = "https://api.hunter.io/v2/domain-search"
            params = {"domain": domain, "api_key": api_key}

            response = self.make_request(url, params=params)
            if response:
                data = response.json()
                emails = data.get("data", {}).get("emails", [])

                related_emails = []
                for email_data in emails:
                    related_emails.append(
                        {
                            "email": email_data.get("value"),
                            "first_name": email_data.get("first_name"),
                            "last_name": email_data.get("last_name"),
                            "position": email_data.get("position"),
                            "department": email_data.get("department"),
                            "confidence": email_data.get("confidence"),
                        }
                    )

                return {"total_emails": len(related_emails), "emails": related_emails}

        except Exception as e:
            self.logger.error(f"Related emails lookup failed: {e}")
            return {"error": str(e)}

    def get_hunter_info(self, email):
        """Get comprehensive Hunter.io information"""
        domain = email.split("@")[1]
        api_key = self.get_api_key("HUNTER_API_KEY")

        if not api_key:
            return {"error": "No API key"}

        hunter_data = {
            "domain_info": self.get_hunter_domain_info(domain, api_key),
            "email_finder": self.hunter_email_finder(email, api_key),
        }

        return hunter_data

    def get_hunter_domain_info(self, domain, api_key):
        """Get domain information from Hunter.io"""
        try:
            url = "https://api.hunter.io/v2/domain-search"
            params = {"domain": domain, "api_key": api_key, "limit": 10}

            response = self.make_request(url, params=params)
            if response:
                data = response.json()
                return {
                    "domain": data.get("data", {}).get("domain"),
                    "organization": data.get("data", {}).get("organization"),
                    "pattern": data.get("data", {}).get("pattern"),
                    "total_emails": data.get("data", {}).get("emails"),
                    "webmail": data.get("data", {}).get("webmail"),
                }

        except Exception as e:
            self.logger.error(f"Hunter domain info failed: {e}")
            return {"error": str(e)}

    def hunter_email_finder(self, email, api_key):
        """Use Hunter.io email finder"""
        try:
            domain = email.split("@")[1]
            first_name = (
                email.split("@")[0].split(".")[0] if "." in email.split("@")[0] else ""
            )
            last_name = (
                email.split("@")[0].split(".")[-1] if "." in email.split("@")[0] else ""
            )

            url = "https://api.hunter.io/v2/email-finder"
            params = {
                "domain": domain,
                "first_name": first_name,
                "last_name": last_name,
                "api_key": api_key,
            }

            response = self.make_request(url, params=params)
            if response:
                return response.json()

        except Exception as e:
            self.logger.error(f"Hunter email finder failed: {e}")
            return {"error": str(e)}

    def get_clearbit_info(self, email):
        """Get Clearbit information"""
        api_key = self.get_api_key("CLEARBIT_API_KEY")
        if not api_key:
            return {"error": "No API key"}

        try:
            url = f"https://person.clearbit.com/v2/people/find?email={email}"
            headers = {"Authorization": f"Bearer {api_key}"}

            response = self.make_request(url, headers=headers)
            if response and response.status_code == 200:
                data = response.json()
                return {
                    "name": data.get("name", {}),
                    "bio": data.get("bio"),
                    "avatar": data.get("avatar"),
                    "location": data.get("location"),
                    "employment": data.get("employment", {}),
                    "social": data.get("social", {}),
                    "github": data.get("github", {}),
                    "twitter": data.get("twitter", {}),
                    "linkedin": data.get("linkedin", {}),
                }
            elif response.status_code == 202:
                return {"status": "lookup_queued"}

        except Exception as e:
            self.logger.error(f"Clearbit lookup failed: {e}")
            return {"error": str(e)}

    def generate_report(self):
        """Generate comprehensive email intelligence report"""
        if not self.results:
            return "No analysis results available"

        report = f"""# Email Intelligence Report: {self.results["email"]}
Generated: {self.results["timestamp"]}

## Domain Analysis
"""
        domain_info = self.results.get("domain_info", {})
        if "domain" in domain_info:
            report += f"Domain: {domain_info['domain']}\n"

        # Add breach information
        breach_data = self.results.get("breach_data", {})
        hibp_data = breach_data.get("haveibeenpwned", {})

        report += "\n## Data Breach Information\n"
        if hibp_data.get("found"):
            report += (
                f"⚠️  Email found in {hibp_data.get('breach_count', 0)} data breaches:\n"
            )
            for breach in hibp_data.get("breaches", []):
                report += f"- {breach['name']} ({breach['date']})\n"
        else:
            report += "✅ No breaches found in HaveIBeenPwned\n"

        # Add reputation information
        reputation = self.results.get("reputation", {})
        hunter_verify = reputation.get("hunter_verification", {})

        report += "\n## Email Verification\n"
        if "result" in hunter_verify:
            report += f"Hunter.io Result: {hunter_verify['result']}\n"
            report += f"Deliverable Score: {hunter_verify.get('score', 'N/A')}\n"
            report += f"Disposable: {hunter_verify.get('disposable', 'N/A')}\n"
            report += f"Webmail: {hunter_verify.get('webmail', 'N/A')}\n"

        # Add social profiles
        social_profiles = self.results.get("social_profiles", {})
        if social_profiles:
            report += "\n## Social Media Profiles\n"
            for platform, info in social_profiles.items():
                if info.get("status") == "found":
                    report += f"- {platform.title()}: {info['url']}\n"

        return report
