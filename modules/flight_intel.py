"""
Flight Tracking and Aviation Intelligence Module
Aircraft movement analysis for high-value target investigations
"""

from datetime import datetime

from bs4 import BeautifulSoup

from utils.osint_utils import OSINTUtils


class FlightIntelligence(OSINTUtils):
    def __init__(self):
        super().__init__()
        self.results = {}

    def analyze_aircraft(self, identifier, identifier_type="registration"):
        """Comprehensive aircraft analysis"""
        self.logger.info(f"Starting aircraft analysis for: {identifier}")

        self.results = {
            "identifier": identifier,
            "identifier_type": identifier_type,
            "timestamp": datetime.now().isoformat(),
            "aircraft_info": self.get_aircraft_info(identifier, identifier_type),
            "flight_history": self.get_flight_history(identifier, identifier_type),
            "ownership_info": self.get_ownership_info(identifier),
            "route_analysis": self.analyze_routes(identifier),
        }

        return self.results

    def get_aircraft_info(self, identifier, identifier_type):
        """Get basic aircraft information from public sources"""
        aircraft_data = {}

        # FlightAware public search
        try:
            if identifier_type == "registration":
                url = f"https://flightaware.com/resources/registration/{identifier}"
            else:
                url = f"https://flightaware.com/live/flight/{identifier}"

            response = self.make_request(url)
            if response:
                aircraft_data["flightaware"] = self.parse_flightaware_data(
                    response.text
                )
        except Exception as e:
            self.logger.error(f"FlightAware lookup failed: {e}")

        # Add other sources
        aircraft_data["source"] = "Multiple Public Sources"
        return aircraft_data

    def parse_flightaware_data(self, html_content):
        """Parse FlightAware HTML content"""
        try:
            soup = BeautifulSoup(html_content, "html.parser")

            # Extract basic info
            info = {}

            # Look for aircraft type
            type_element = soup.find(text=lambda text: text and "Aircraft Type" in text)
            if type_element:
                info["aircraft_type"] = type_element.parent.get_text(strip=True)

            # Look for owner info
            owner_element = soup.find(text=lambda text: text and "Owner" in text)
            if owner_element:
                info["owner"] = owner_element.parent.get_text(strip=True)

            return info

        except Exception as e:
            self.logger.error(f"FlightAware parsing failed: {e}")
            return {}

    def get_flight_history(self, identifier, identifier_type):
        """Get flight history from public sources"""
        try:
            history_data = {"flights": [], "total_tracked": 0}

            # Try FlightAware history
            url = f"https://flightaware.com/live/flight/{identifier}/history"
            response = self.make_request(url)

            if response:
                soup = BeautifulSoup(response.text, "html.parser")

                # Parse flight table
                table = soup.find("table", class_="prettyTable")
                if table:
                    rows = table.find_all("tr")[1:]  # Skip header
                    for row in rows[:20]:  # Limit to 20 recent flights
                        cells = row.find_all("td")
                        if len(cells) >= 4:
                            flight = {
                                "date": cells[0].get_text(strip=True),
                                "route": cells[1].get_text(strip=True),
                                "aircraft": cells[2].get_text(strip=True),
                                "duration": cells[3].get_text(strip=True)
                                if len(cells) > 3
                                else "",
                            }
                            history_data["flights"].append(flight)

                history_data["total_tracked"] = len(history_data["flights"])

            return history_data

        except Exception as e:
            self.logger.error(f"Flight history lookup failed: {e}")
            return {"error": str(e)}

    def get_ownership_info(self, identifier):
        """Get aircraft ownership information"""
        ownership_data = {}

        try:
            # For US aircraft (N-numbers)
            if identifier.startswith("N"):
                ownership_data["registry"] = "FAA (United States)"
                ownership_data["registration_country"] = "United States"

            # For other registrations
            elif identifier.startswith("G-"):
                ownership_data["registry"] = "CAA (United Kingdom)"
                ownership_data["registration_country"] = "United Kingdom"
            elif identifier.startswith("D-"):
                ownership_data["registry"] = "LBA (Germany)"
                ownership_data["registration_country"] = "Germany"
            else:
                ownership_data["registry"] = "Unknown"
                ownership_data["registration_country"] = "Unknown"

            return ownership_data

        except Exception as e:
            self.logger.error(f"Ownership lookup failed: {e}")
            return {"error": str(e)}

    def analyze_routes(self, identifier):
        """Analyze flight route patterns"""
        try:
            # Get flight history
            history = self.get_flight_history(identifier, "registration")

            if "flights" not in history:
                return {"error": "No flight data available"}

            flights = history["flights"]

            # Analyze patterns
            routes = {}
            for flight in flights:
                route = flight.get("route", "")
                if route:
                    routes[route] = routes.get(route, 0) + 1

            # Sort by frequency
            frequent_routes = sorted(routes.items(), key=lambda x: x[1], reverse=True)

            return {
                "total_unique_routes": len(routes),
                "frequent_routes": frequent_routes[:10],
                "analysis_summary": f"Aircraft has {len(routes)} unique routes from {len(flights)} tracked flights",
            }

        except Exception as e:
            self.logger.error(f"Route analysis failed: {e}")
            return {"error": str(e)}

    def generate_report(self):
        """Generate flight intelligence report"""
        if not self.results:
            return "No analysis results available"

        report = f"""
# Flight Intelligence Report: {self.results['identifier']}
Generated: {self.results['timestamp']}

## Aircraft Information
"""

        aircraft_info = self.results.get("aircraft_info", {})
        fa_data = aircraft_info.get("flightaware", {})

        for key, value in fa_data.items():
            report += f"{key}: {value}\n"

        # Flight history summary
        history = self.results.get("flight_history", {})
        total = history.get("total_tracked", 0)

        report += "\n## Flight Activity Summary\n"
        report += f"Total Flights Tracked: {total}\n"

        # Route analysis
        route_analysis = self.results.get("route_analysis", {})
        if "frequent_routes" in route_analysis:
            report += "\n## Most Frequent Routes\n"
            for route, count in route_analysis["frequent_routes"][:5]:
                report += f"- {route}: {count} times\n"

        return report
