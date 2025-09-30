"""
Pre-seeded OSINT Databases Module
Provides access to government and open source intelligence databases
No API keys required - uses publicly available data sources
"""

from utils.osint_utils import OSINTUtils
from typing import Dict, List, Optional, Any
from datetime import datetime


class PreSeededDatabases(OSINTUtils):
    """Access to pre-seeded and government OSINT databases"""

    def __init__(self):
        super().__init__()
        self.databases = {
            "us_cisa_known_exploited": {
                "name": "CISA Known Exploited Vulnerabilities",
                "url": "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json",
                "description": "Official CISA catalog of known exploited vulnerabilities",
                "category": "vulnerabilities",
            },
            "us_fbi_most_wanted": {
                "name": "FBI Most Wanted",
                "url": "https://api.fbi.gov/wanted/v1/list",
                "description": "FBI most wanted fugitives and terrorists",
                "category": "law_enforcement",
            },
            "us_treasury_sanctions": {
                "name": "OFAC Sanctions List",
                "url": "https://www.treasury.gov/ofac/downloads/sdnlist.txt",
                "description": "Office of Foreign Assets Control sanctions list",
                "category": "sanctions",
            },
            "europol_wanted": {
                "name": "Europol Most Wanted",
                "url": "https://www.europol.europa.eu/crime-areas-and-statistics/crime-areas/most-wanted",
                "description": "Europol most wanted criminals",
                "category": "law_enforcement",
            },
            "interpol_red_notices": {
                "name": "Interpol Red Notices",
                "url": "https://www.interpol.int/How-we-work/Notices/Red-Notices",
                "description": "Interpol international wanted persons",
                "category": "law_enforcement",
            },
            "us_fema_disaster_declarations": {
                "name": "FEMA Disaster Declarations",
                "url": "https://www.fema.gov/api/open/v2/DisasterDeclarationsSummaries",
                "description": "FEMA disaster declaration summaries",
                "category": "disaster_response",
            },
            "us_noaa_weather_alerts": {
                "name": "NOAA Weather Alerts",
                "url": "https://api.weather.gov/alerts/active",
                "description": "National Weather Service active alerts",
                "category": "weather",
            },
            "usgs_earthquake_feed": {
                "name": "USGS Earthquake Feed",
                "url": "https://earthquake.usgs.gov/earthquakes/feed/v1.0/summary/all_hour.geojson",
                "description": "Recent earthquake data from USGS",
                "category": "geological",
            },
            "nasa_neo_feed": {
                "name": "NASA Near Earth Objects",
                "url": "https://api.nasa.gov/neo/rest/v1/feed?api_key=DEMO_KEY",
                "description": "Near Earth Objects tracking (demo key)",
                "category": "space",
            },
            "cdc_health_alerts": {
                "name": "CDC Health Alerts",
                "url": "https://tools.cdc.gov/api/v2/resources/media",
                "description": "CDC health and safety alerts",
                "category": "health",
            },
        }

    def get_database_info(self, database_key: str) -> Optional[Dict]:
        """Get information about a specific database"""
        return self.databases.get(database_key)

    def list_databases(self, category: Optional[str] = None) -> List[Dict]:
        """List available databases, optionally filtered by category"""
        if category:
            return [db for db in self.databases.values() if db["category"] == category]
        return list(self.databases.values())

    def fetch_cisa_vulnerabilities(self) -> List[Dict]:
        """Fetch CISA known exploited vulnerabilities"""
        try:
            response = self.make_request(
                self.databases["us_cisa_known_exploited"]["url"], timeout=30
            )
            if response and response.status_code == 200:
                data = response.json()
                return data.get("vulnerabilities", [])
        except Exception as e:
            self.logger.error(f"Failed to fetch CISA vulnerabilities: {e}")
        return []

    def search_cisa_vulnerabilities(self, query: str) -> List[Dict]:
        """Search CISA vulnerabilities by CVE, vendor, or description"""
        vulnerabilities = self.fetch_cisa_vulnerabilities()
        query_lower = query.lower()

        results = []
        for vuln in vulnerabilities:
            if (
                query_lower in vuln.get("cveID", "").lower()
                or query_lower in vuln.get("vendorProject", "").lower()
                or query_lower in vuln.get("shortDescription", "").lower()
            ):
                results.append(vuln)

        return results

    def fetch_fbi_most_wanted(self) -> List[Dict]:
        """Fetch FBI most wanted list"""
        try:
            response = self.make_request(
                self.databases["us_fbi_most_wanted"]["url"], timeout=30
            )
            if response and response.status_code == 200:
                data = response.json()
                return data.get("items", [])
        except Exception as e:
            self.logger.error(f"Failed to fetch FBI most wanted: {e}")
        return []

    def search_fbi_most_wanted(
        self, name: Optional[str] = None, crime: Optional[str] = None
    ) -> List[Dict]:
        """Search FBI most wanted by name or crime type"""
        wanted_list = self.fetch_fbi_most_wanted()

        results = []
        for person in wanted_list:
            match = True

            if name:
                person_name = person.get("title", "").lower()
                if name.lower() not in person_name:
                    match = False

            if crime and match:
                person_crimes = " ".join(person.get("subjects", [])).lower()
                if crime.lower() not in person_crimes:
                    match = False

            if match:
                results.append(person)

        return results

    def fetch_ofac_sanctions(self) -> List[str]:
        """Fetch OFAC sanctions list (simplified text parsing)"""
        try:
            response = self.make_request(
                self.databases["us_treasury_sanctions"]["url"], timeout=30
            )
            if response and response.status_code == 200:
                # Parse the SDN list (simplified - in practice this is complex)
                lines = response.text.split("\n")
                sanctions = [
                    line.strip()
                    for line in lines
                    if line.strip() and not line.startswith(";")
                ]
                return sanctions[:1000]  # Limit for performance
        except Exception as e:
            self.logger.error(f"Failed to fetch OFAC sanctions: {e}")
        return []

    def search_ofac_sanctions(self, query: str) -> List[str]:
        """Search OFAC sanctions list"""
        sanctions = self.fetch_ofac_sanctions()
        query_lower = query.lower()

        return [entry for entry in sanctions if query_lower in entry.lower()]

    def fetch_fema_disasters(self) -> List[Dict]:
        """Fetch FEMA disaster declarations"""
        try:
            response = self.make_request(
                self.databases["us_fema_disaster_declarations"]["url"], timeout=30
            )
            if response and response.status_code == 200:
                data = response.json()
                return data.get("DisasterDeclarationsSummaries", [])
        except Exception as e:
            self.logger.error(f"Failed to fetch FEMA disasters: {e}")
        return []

    def search_fema_disasters(
        self, state: Optional[str] = None, disaster_type: Optional[str] = None
    ) -> List[Dict]:
        """Search FEMA disaster declarations"""
        disasters = self.fetch_fema_disasters()

        results = []
        for disaster in disasters:
            match = True

            if state and disaster.get("state") != state.upper():
                match = False

            if disaster_type and disaster.get("incidentType") != disaster_type:
                match = False

            if match:
                results.append(disaster)

        return results

    def fetch_noaa_weather_alerts(self) -> List[Dict]:
        """Fetch NOAA weather alerts"""
        try:
            response = self.make_request(
                self.databases["us_noaa_weather_alerts"]["url"], timeout=30
            )
            if response and response.status_code == 200:
                data = response.json()
                return data.get("features", [])
        except Exception as e:
            self.logger.error(f"Failed to fetch NOAA alerts: {e}")
        return []

    def fetch_usgs_earthquakes(self) -> List[Dict]:
        """Fetch recent earthquakes from USGS"""
        try:
            response = self.make_request(
                self.databases["usgs_earthquake_feed"]["url"], timeout=30
            )
            if response and response.status_code == 200:
                data = response.json()
                return data.get("features", [])
        except Exception as e:
            self.logger.error(f"Failed to fetch USGS earthquakes: {e}")
        return []

    def fetch_nasa_neo(self) -> List[Dict]:
        """Fetch Near Earth Objects from NASA"""
        try:
            response = self.make_request(
                self.databases["nasa_neo_feed"]["url"], timeout=30
            )
            if response and response.status_code == 200:
                data = response.json()
                # Extract NEOs from all dates
                neos = []
                for date_data in data.get("near_earth_objects", {}).values():
                    neos.extend(date_data)
                return neos
        except Exception as e:
            self.logger.error(f"Failed to fetch NASA NEOs: {e}")
        return []

    def fetch_cdc_alerts(self) -> List[Dict]:
        """Fetch CDC health alerts"""
        try:
            response = self.make_request(
                self.databases["cdc_health_alerts"]["url"], timeout=30
            )
            if response and response.status_code == 200:
                data = response.json()
                return data.get("results", [])
        except Exception as e:
            self.logger.error(f"Failed to fetch CDC alerts: {e}")
        return []

    def comprehensive_search(
        self, query: str, categories: Optional[List[str]] = None
    ) -> Dict[str, Any]:
        """
        Perform comprehensive search across multiple government databases
        """
        if categories is None:
            categories = ["vulnerabilities", "law_enforcement", "sanctions"]

        results: Dict[str, Any] = {
            "query": query,
            "timestamp": datetime.now().isoformat(),
            "results": {},
        }

        if "vulnerabilities" in categories:
            vuln_results = self.search_cisa_vulnerabilities(query)
            results["results"]["cisa_vulnerabilities"] = vuln_results

        if "law_enforcement" in categories:
            fbi_results = self.search_fbi_most_wanted(query)
            results["results"]["fbi_most_wanted"] = fbi_results

        if "sanctions" in categories:
            ofac_results = self.search_ofac_sanctions(query)
            results["results"]["ofac_sanctions"] = ofac_results

        # Count total results
        total_results = sum(len(res_list) for res_list in results["results"].values())
        results["total_results"] = total_results

        return results

    def get_database_statistics(self) -> Dict[str, Any]:
        """Get statistics about available databases"""
        stats: Dict[str, Any] = {
            "total_databases": len(self.databases),
            "categories": {},
            "last_updated": datetime.now().isoformat(),
        }

        for db_info in self.databases.values():
            category = db_info["category"]
            if category not in stats["categories"]:
                stats["categories"][category] = 0
            stats["categories"][category] += 1

        return stats
