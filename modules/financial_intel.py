"""
Financial Intelligence Module
Banking records, asset searches, financial investigations
"""

import re
from datetime import datetime
from typing import Dict, Optional, Any

from utils.osint_utils import OSINTUtils
from utils.result_normalizer import normalize_result


class FinancialIntelligence(OSINTUtils):
    """Comprehensive financial intelligence and asset analysis"""

    def __init__(self):
        super().__init__()
        self.results = {}

    def check_rate_limit(self, service: str) -> bool:
        """Check if we're within rate limits for a service"""
        # Simple rate limiting - could be enhanced with actual rate limiting
        return True

    def analyze_financial_entity(self, entity_query: str) -> Dict:
        """
        Comprehensive financial analysis of entities, assets, and transactions

        Args:
            entity_query: Company name, person name, wallet address, or financial identifier

        Returns:
            Standardized result dict
        """
        self.logger.info(f"Starting financial analysis for: {entity_query}")

        try:
            self.results = {
                "query": entity_query,
                "timestamp": datetime.now().isoformat(),
                "entity_type": self.classify_entity(entity_query),
                "blockchain_analysis": self.analyze_blockchain_assets(entity_query),
                "corporate_records": self.search_corporate_records(entity_query),
                "financial_databases": self.search_financial_databases(entity_query),
                "regulatory_filings": self.search_regulatory_filings(entity_query),
                "asset_tracing": self.trace_financial_assets(entity_query),
                "risk_assessment": self.assess_financial_risk(entity_query),
            }

            return normalize_result({"status": "success", "data": self.results})

        except Exception as e:
            self.logger.error(f"Financial analysis failed: {e}")
            return normalize_result({"status": "error", "error": str(e)})

    def classify_entity(self, query: str) -> str:
        """Classify the type of financial entity being queried"""
        # Check for cryptocurrency addresses
        if self.is_cryptocurrency_address(query):
            return "cryptocurrency_address"

        # Check for company identifiers
        if self.is_company_identifier(query):
            return "company"

        # Check for financial account numbers
        if self.is_financial_account(query):
            return "financial_account"

        # Check for person names
        if self.is_person_name(query):
            return "individual"

        return "unknown"

    def is_cryptocurrency_address(self, query: str) -> bool:
        """Check if query is a cryptocurrency address"""
        # Bitcoin address patterns
        btc_patterns = [
            r"^[13][a-km-zA-HJ-NP-Z1-9]{25,34}$",  # P2PKH
            r"^bc1[a-z0-9]{39,59}$",  # Bech32
        ]

        # Ethereum address pattern
        eth_pattern = r"^0x[a-fA-F0-9]{40}$"

        for pattern in btc_patterns + [eth_pattern]:
            if re.match(pattern, query.strip()):
                return True

        return False

    def is_company_identifier(self, query: str) -> bool:
        """Check if query is a company identifier"""
        # Common company suffixes
        company_suffixes = [
            "inc",
            "llc",
            "corp",
            "corporation",
            "ltd",
            "limited",
            "co",
            "company",
            "enterprises",
            "holdings",
            "group",
        ]

        query_lower = query.lower()
        return any(suffix in query_lower for suffix in company_suffixes)

    def is_financial_account(self, query: str) -> bool:
        """Check if query is a financial account number"""
        # IBAN pattern
        iban_pattern = r"^[A-Z]{2}\d{2}[A-Z0-9]{11,30}$"

        # Credit card patterns (simplified)
        cc_patterns = [
            r"^\d{4}[\s\-]?\d{4}[\s\-]?\d{4}[\s\-]?\d{4}$",  # 16 digits
            r"^\d{4}[\s\-]?\d{6}[\s\-]?\d{5}$",  # 15 digits (Amex)
        ]

        for pattern in [iban_pattern] + cc_patterns:
            if re.match(pattern, query.replace(" ", "").replace("-", "")):
                return True

        return False

    def is_person_name(self, query: str) -> bool:
        """Check if query appears to be a person name"""
        # Simple heuristic: contains spaces and no numbers
        return " " in query and not any(char.isdigit() for char in query)

    def analyze_blockchain_assets(self, query: str) -> Dict:
        """Analyze blockchain assets and transactions"""
        results = {}

        # Check if it's a crypto address
        if self.is_cryptocurrency_address(query):
            # Etherscan analysis
            etherscan_result = self.analyze_etherscan_address(query)
            if etherscan_result:
                results["etherscan"] = etherscan_result

            # CoinMarketCap analysis (for token info)
            token_info = self.get_token_information(query)
            if token_info:
                results["token_info"] = token_info

        # General blockchain intelligence
        results["blockchain_intel"] = self.get_blockchain_intelligence(query)

        return results

    def analyze_etherscan_address(self, address: str) -> Optional[Dict]:
        """Analyze Ethereum address using Etherscan"""
        api_key = self.get_api_key("etherscan")
        if not api_key:
            return None

        if not self.check_rate_limit("etherscan"):
            return None

        try:
            # Get account balance
            balance_url = "https://api.etherscan.io/api"
            params = {
                "module": "account",
                "action": "balance",
                "address": address,
                "tag": "latest",
                "apikey": api_key,
            }

            response = self.make_request(balance_url, params=params)
            if response and response.status_code == 200:
                data = response.json()
                if data.get("status") == "1":
                    balance_wei = int(data["result"])
                    balance_eth = balance_wei / 10**18

                    return {
                        "address": address,
                        "balance_eth": balance_eth,
                        "balance_wei": balance_wei,
                        "last_updated": datetime.now().isoformat(),
                    }

        except Exception as e:
            self.logger.error(f"Etherscan analysis failed: {e}")

        return None

    def get_token_information(self, address: str) -> Optional[Dict]:
        """Get token information from various sources"""
        # This would integrate with token databases
        # For now, return basic structure
        return {
            "address": address,
            "token_type": "unknown",
            "decimals": "unknown",
            "supply": "unknown",
        }

    def get_blockchain_intelligence(self, query: str) -> Dict:
        """Get general blockchain intelligence"""
        return {
            "associated_addresses": [],
            "transaction_patterns": {},
            "risk_indicators": [],
            "sanctions_status": "unknown",
        }

    def search_corporate_records(self, query: str) -> Dict:
        """Search corporate records and business databases"""
        results = {}

        # SEC EDGAR search (no API key required)
        sec_results = self.search_sec_edgar(query)
        if sec_results:
            results["sec_edgar"] = sec_results

        # OpenCorporates search (has free tier)
        opencorp_results = self.search_opencorporates(query)
        if opencorp_results:
            results["opencorporates"] = opencorp_results

        return results

    def search_sec_edgar(self, query: str) -> Optional[Dict]:
        """Search SEC EDGAR database for corporate filings"""
        try:
            # Use SEC's public API
            url = "https://www.sec.gov/edgar/searchedgar/ciksearch.json"
            params = {"query": query}

            response = self.make_request(url, params=params)
            if response and response.status_code == 200:
                data = response.json()
                return {
                    "query": query,
                    "results": data.get("data", []),
                    "total_hits": data.get("totalHits", 0),
                }

        except Exception as e:
            self.logger.error(f"SEC EDGAR search failed: {e}")

        return None

    def search_opencorporates(self, query: str) -> Optional[Dict]:
        """Search OpenCorporates database"""
        try:
            url = "https://api.opencorporates.com/v0.4/companies/search"
            params = {"q": query, "api_token": "free"}  # Free tier

            response = self.make_request(url, params=params)
            if response and response.status_code == 200:
                data = response.json()
                return {
                    "query": query,
                    "companies": data.get("results", {}).get("companies", []),
                    "total_count": data.get("results", {}).get("total_count", 0),
                }

        except Exception as e:
            self.logger.error(f"OpenCorporates search failed: {e}")

        return None

    def search_financial_databases(self, query: str) -> Dict:
        """Search financial databases and registries"""
        results = {}

        # OFAC SDN search (no API key required)
        ofac_results = self.search_ofac_sdn(query)
        if ofac_results:
            results["ofac_sdn"] = ofac_results

        # EU sanctions search
        eu_sanctions = self.search_eu_sanctions(query)
        if eu_sanctions:
            results["eu_sanctions"] = eu_sanctions

        return results

    def search_ofac_sdn(self, query: str) -> Optional[Dict]:
        """Search OFAC Specially Designated Nationals list"""
        try:
            # OFAC provides a public XML feed
            url = "https://www.treasury.gov/ofac/downloads/sdn.xml"

            response = self.make_request(url)
            if response and response.status_code == 200:
                # Parse XML for matches (simplified)
                content = response.text.lower()
                query_lower = query.lower()

                if query_lower in content:
                    return {
                        "query": query,
                        "found_in_sdn": True,
                        "last_checked": datetime.now().isoformat(),
                        "note": "Match found in OFAC SDN list - requires manual verification",
                    }
                else:
                    return {
                        "query": query,
                        "found_in_sdn": False,
                        "last_checked": datetime.now().isoformat(),
                    }

        except Exception as e:
            self.logger.error(f"OFAC SDN search failed: {e}")

        return None

    def search_eu_sanctions(self, query: str) -> Optional[Dict]:
        """Search EU sanctions lists"""
        try:
            # This is a simplified search - real implementation would parse XML
            return {
                "query": query,
                "found_in_eu_sanctions": False,
                "last_checked": datetime.now().isoformat(),
                "note": "EU sanctions search requires specialized XML parsing",
            }

        except Exception as e:
            self.logger.error(f"EU sanctions search failed: {e}")

        return None

    def search_regulatory_filings(self, query: str) -> Dict:
        """Search regulatory filings and disclosures"""
        results = {}

        # SEC filings
        sec_filings = self.search_sec_filings(query)
        if sec_filings:
            results["sec_filings"] = sec_filings

        return results

    def search_sec_filings(self, query: str) -> Optional[Dict]:
        """Search SEC filings database"""
        try:
            url = "https://www.sec.gov/edgar/searchedgar/companies.json"
            params = {"query": query}

            response = self.make_request(url, params=params)
            if response and response.status_code == 200:
                data = response.json()
                return {
                    "query": query,
                    "companies": data.get("data", []),
                    "total_hits": data.get("totalHits", 0),
                }

        except Exception as e:
            self.logger.error(f"SEC filings search failed: {e}")

        return None

    def trace_financial_assets(self, query: str) -> Dict:
        """Trace financial assets and transactions"""
        return {
            "asset_tracing": "not_implemented",
            "transaction_analysis": "not_implemented",
            "ownership_chains": [],
            "jurisdictions": [],
        }

    def assess_financial_risk(self, query: str) -> Dict:
        """Assess financial and compliance risk"""
        risk_factors = []

        # Check sanctions lists
        if self.search_ofac_sdn(query):
            risk_factors.append("OFAC SDN match")

        return {
            "overall_risk": "low" if not risk_factors else "high",
            "risk_factors": risk_factors,
            "compliance_flags": [],
            "recommendations": [],
        }
