"""
Geospatial Intelligence Module
Location tracking, mapping, and geographic analysis
"""

import re
from datetime import datetime
from typing import Dict, Optional, Tuple, List, Any
import requests

from utils.osint_utils import OSINTUtils
from utils.result_normalizer import normalize_result


class GeospatialIntelligence(OSINTUtils):
    """Comprehensive geospatial intelligence and location analysis"""

    def __init__(self):
        super().__init__()
        self.results = {}

    def check_rate_limit(self, service: str) -> bool:
        """Check if we're within rate limits for a service"""
        # Simple rate limiting - could be enhanced with actual rate limiting
        return True

    def analyze_location(self, location_query: str) -> Dict:
        """
        Comprehensive location analysis from various sources

        Args:
            location_query: Address, coordinates, or location name

        Returns:
            Standardized result dict
        """
        self.logger.info(f"Starting geospatial analysis for: {location_query}")

        try:
            self.results = {
                'query': location_query,
                'timestamp': datetime.now().isoformat(),
                'geocoding': self.geocode_location(location_query),
                'reverse_geocoding': self.reverse_geocode(location_query),
                'ip_geolocation': self.extract_ip_from_location(location_query),
                'coordinates': self.parse_coordinates(location_query),
                'location_intelligence': self.analyze_location_intelligence(location_query),
                'nearby_services': self.find_nearby_services(location_query)
            }

            return normalize_result({
                "status": "success",
                "data": self.results
            })

        except Exception as e:
            self.logger.error(f"Geospatial analysis failed: {e}")
            return normalize_result({
                "status": "error",
                "error": str(e)
            })

    def geocode_location(self, location: str) -> Dict:
        """Geocode location to coordinates using multiple services"""
        results = {}

        # OpenCage geocoding (requires API key)
        opencage_result = self.geocode_opencage(location)
        if opencage_result:
            results['opencage'] = opencage_result

        # Mapbox geocoding (requires API key)
        mapbox_result = self.geocode_mapbox(location)
        if mapbox_result:
            results['mapbox'] = mapbox_result

        # Free geocoding services (no API required)
        nominatim_result = self.geocode_nominatim(location)
        if nominatim_result:
            results['nominatim'] = nominatim_result

        return results

    def geocode_opencage(self, location: str) -> Optional[Dict]:
        """Geocode using OpenCage API"""
        api_key = self.get_api_key('opencage')
        if not api_key:
            return None

        if not self.check_rate_limit('opencage'):
            return None

        try:
            url = "https://api.opencagedata.com/geocode/v1/json"
            params = {
                'q': location,
                'key': api_key,
                'limit': 1
            }

            response = self.make_request(url, params=params)
            if response and response.status_code == 200:
                data = response.json()
                if data.get('results'):
                    result = data['results'][0]
                    return {
                        'coordinates': [
                            result['geometry']['lat'],
                            result['geometry']['lng']
                        ],
                        'formatted_address': result.get('formatted', ''),
                        'country': result.get('components', {}).get('country', ''),
                        'state': result.get('components', {}).get('state', ''),
                        'city': result.get('components', {}).get('city', ''),
                        'confidence': result.get('confidence', 0)
                    }

        except Exception as e:
            self.logger.error(f"OpenCage geocoding failed: {e}")

        return None

    def geocode_mapbox(self, location: str) -> Optional[Dict]:
        """Geocode using Mapbox API"""
        api_key = self.get_api_key('mapbox')
        if not api_key:
            return None

        if not self.check_rate_limit('mapbox'):
            return None

        try:
            url = f"https://api.mapbox.com/geocoding/v5/mapbox.places/{location}.json"
            params = {
                'access_token': api_key,
                'limit': 1
            }

            response = self.make_request(url, params=params)
            if response and response.status_code == 200:
                data = response.json()
                if data.get('features'):
                    feature = data['features'][0]
                    return {
                        'coordinates': feature['center'][::-1],  # Mapbox returns [lng, lat]
                        'formatted_address': feature.get('place_name', ''),
                        'type': feature.get('type', ''),
                        'relevance': feature.get('relevance', 0)
                    }

        except Exception as e:
            self.logger.error(f"Mapbox geocoding failed: {e}")

        return None

    def geocode_nominatim(self, location: str) -> Optional[Dict]:
        """Geocode using Nominatim (OpenStreetMap) - no API key required"""
        try:
            url = "https://nominatim.openstreetmap.org/search"
            params = {
                'q': location,
                'format': 'json',
                'limit': 1,
                'addressdetails': 1
            }
            headers = {'User-Agent': 'OSINT-Suite/1.0'}

            response = self.make_request(url, params=params, headers=headers)
            if response and response.status_code == 200:
                data = response.json()
                if data:
                    result = data[0]
                    return {
                        'coordinates': [
                            float(result['lat']),
                            float(result['lon'])
                        ],
                        'formatted_address': result.get('display_name', ''),
                        'type': result.get('type', ''),
                        'importance': result.get('importance', 0),
                        'address': result.get('address', {})
                    }

        except Exception as e:
            self.logger.error(f"Nominatim geocoding failed: {e}")

        return None

    def reverse_geocode(self, location: str) -> Dict:
        """Reverse geocode coordinates to addresses"""
        coords = self.parse_coordinates(location)
        if not coords:
            return {}

        results = {}

        # Try reverse geocoding with available services
        nominatim_result = self.reverse_geocode_nominatim(coords)
        if nominatim_result:
            results['nominatim'] = nominatim_result

        return results

    def reverse_geocode_nominatim(self, coords: Tuple[float, float]) -> Optional[Dict]:
        """Reverse geocode using Nominatim"""
        try:
            url = "https://nominatim.openstreetmap.org/reverse"
            params = {
                'lat': coords[0],
                'lon': coords[1],
                'format': 'json',
                'addressdetails': 1
            }
            headers = {'User-Agent': 'OSINT-Suite/1.0'}

            response = self.make_request(url, params=params, headers=headers)
            if response and response.status_code == 200:
                data = response.json()
                return {
                    'formatted_address': data.get('display_name', ''),
                    'address': data.get('address', {}),
                    'type': data.get('type', ''),
                    'importance': data.get('importance', 0)
                }

        except Exception as e:
            self.logger.error(f"Nominatim reverse geocoding failed: {e}")

        return None

    def parse_coordinates(self, location: str) -> Optional[Tuple[float, float]]:
        """Parse coordinates from various formats"""
        # Regex patterns for different coordinate formats
        patterns = [
            # Decimal degrees: 40.7128, -74.0060
            r'(-?\d+\.\d+),\s*(-?\d+\.\d+)',
            # Degrees minutes seconds: 40°42'51"N 74°00'23"W
            r'(\d+)°(\d+)\'(\d+)"([NS])\s+(\d+)°(\d+)\'(\d+)"([EW])',
            # Simple lat/lng with N/S E/W
            r'(\d+\.\d+)([NS])\s*(\d+\.\d+)([EW])'
        ]

        lat: Optional[float] = None
        lng: Optional[float] = None

        for pattern in patterns:
            match = re.search(pattern, location, re.IGNORECASE)
            if match:
                groups = match.groups()
                if len(groups) == 2:
                    # Decimal format
                    lat, lng = float(groups[0]), float(groups[1])
                elif len(groups) == 8:
                    # DMS format
                    lat_deg, lat_min, lat_sec, lat_dir = int(groups[0]), int(groups[1]), int(groups[2]), groups[3].upper()
                    lng_deg, lng_min, lng_sec, lng_dir = int(groups[4]), int(groups[5]), int(groups[6]), groups[7].upper()

                    lat = lat_deg + lat_min/60 + lat_sec/3600
                    lng = lng_deg + lng_min/60 + lng_sec/3600

                    if lat_dir == 'S':
                        lat = -lat
                    if lng_dir == 'W':
                        lng = -lng
                elif len(groups) == 4:
                    # N/S E/W format
                    lat, lat_dir, lng, lng_dir = float(groups[0]), groups[1].upper(), float(groups[2]), groups[3].upper()
                    if lat_dir == 'S':
                        lat = -lat
                    if lng_dir == 'W':
                        lng = -lng

                # Validate coordinates
                if lat is not None and lng is not None and -90 <= lat <= 90 and -180 <= lng <= 180:
                    return (lat, lng)

        return None

    def extract_ip_from_location(self, location: str) -> Optional[Dict]:
        """Extract and geolocate IP addresses from location queries"""
        # Look for IP addresses in the query
        ip_pattern = r'\b\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}\b'
        ips = re.findall(ip_pattern, location)

        if not ips:
            return None

        # Use IP intelligence for geolocation
        try:
            from .ip_intel import IPIntelligence
            ip_intel = IPIntelligence()

            results = {}
            for ip in ips[:3]:  # Limit to first 3 IPs
                ip_info = ip_intel.analyze_ip(ip)
                if ip_info and ip_info.get('status') == 'success':
                    results[ip] = ip_info.get('data', {})

            return results

        except Exception as e:
            self.logger.error(f"IP geolocation failed: {e}")
            return None

    def analyze_location_intelligence(self, location: str) -> Dict:
        """Analyze location for intelligence value"""
        analysis = {
            'risk_assessment': self.assess_location_risk(location),
            'infrastructure': self.analyze_location_infrastructure(location),
            'demographics': self.get_location_demographics(location),
            'business_intelligence': self.get_business_intelligence(location)
        }

        return analysis

    def assess_location_risk(self, location: str) -> Dict:
        """Assess security and risk factors for a location"""
        # This would integrate with threat intelligence feeds
        # For now, return basic analysis
        return {
            'high_risk_indicators': [],
            'medium_risk_indicators': [],
            'low_risk_indicators': ['Standard location analysis'],
            'overall_risk': 'low'
        }

    def analyze_location_infrastructure(self, location: str) -> Dict:
        """Analyze infrastructure around a location"""
        coords = self.parse_coordinates(location)
        if not coords:
            return {}

        # This would integrate with infrastructure databases
        return {
            'internet_connectivity': 'unknown',
            'power_grid': 'unknown',
            'transportation': 'unknown',
            'emergency_services': 'unknown'
        }

    def get_location_demographics(self, location: str) -> Dict:
        """Get demographic information for a location"""
        # This would integrate with demographic databases
        return {
            'population': 'unknown',
            'median_income': 'unknown',
            'education_level': 'unknown',
            'age_distribution': 'unknown'
        }

    def get_business_intelligence(self, location: str) -> Dict:
        """Get business intelligence for a location"""
        # This would integrate with business databases
        return {
            'major_companies': [],
            'industry_focus': 'unknown',
            'economic_indicators': {},
            'business_density': 'unknown'
        }

    def find_nearby_services(self, location: str) -> Dict:
        """Find nearby services and points of interest"""
        coords = self.parse_coordinates(location)
        if not coords:
            return {}

        # Use Overpass API for OpenStreetMap data (no API key required)
        return self.query_overpass_api(coords)

    def query_overpass_api(self, coords: Tuple[float, float]) -> Dict:
        """Query Overpass API for nearby amenities"""
        try:
            # Overpass API query for amenities within 1km
            query = f"""
            [out:json][timeout:25];
            (
              node(around:1000,{coords[0]},{coords[1]})[amenity];
              way(around:1000,{coords[0]},{coords[1]})[amenity];
              relation(around:1000,{coords[0]},{coords[1]})[amenity];
            );
            out center;
            """

            url = "https://overpass-api.de/api/interpreter"
            data = {'data': query}

            response = requests.post(url, data=data)
            if response and response.status_code == 200:
                data = response.json()
                amenities: Dict[str, List[Dict[str, Any]]] = {}

                for element in data.get('elements', []):
                    amenity_type = element.get('tags', {}).get('amenity', 'unknown')
                    if amenity_type not in amenities:
                        amenities[amenity_type] = []
                    amenities[amenity_type].append({
                        'name': element.get('tags', {}).get('name', 'Unnamed'),
                        'lat': element.get('lat', element.get('center', {}).get('lat')),
                        'lon': element.get('lon', element.get('center', {}).get('lon'))
                    })

                return amenities

        except Exception as e:
            self.logger.error(f"Overpass API query failed: {e}")

        return {}