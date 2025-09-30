#!/usr/bin/env python3
"""
Bellingcat Toolkit Module
Integration with Bellingcat's open-source investigation tools and methodologies.
"""

import logging
import re
import requests
from typing import Any, Dict, List, Optional
from datetime import datetime
import hashlib
import importlib.util

logger = logging.getLogger(__name__)

try:
    HAS_PIL = importlib.util.find_spec("PIL") is not None
except Exception:
    HAS_PIL = False


class BellingcatToolkit:
    """Bellingcat-style open source investigation toolkit"""

    def __init__(self):
        self.enabled = True
        self.user_agent = "OSINT-Suite-Bellingcat-Toolkit/1.0"
        self.timeout = 30

        # Known image databases for reverse image search
        self.reverse_image_services = [
            "https://www.google.com/searchbyimage",
            "https://yandex.com/images/search",
            "https://tineye.com/search",
        ]

        # Social media platforms for investigation
        self.social_platforms = {
            "twitter": "https://twitter.com/",
            "facebook": "https://facebook.com/",
            "instagram": "https://instagram.com/",
            "tiktok": "https://tiktok.com/@",
            "youtube": "https://youtube.com/user/",
            "telegram": "https://t.me/",
        }

        logger.info("BellingcatToolkit initialized with OSINT investigation tools")

    def analyze_media(self, media_url: str) -> Dict[str, Any]:
        """Analyze media using Bellingcat-style techniques"""
        try:
            analysis = {
                "media_url": media_url,
                "analysis_type": "bellingcat_osint",
                "metadata": {},
                "reverse_search": {},
                "forensic_analysis": {},
                "timestamp": datetime.now().isoformat(),
            }

            # Download and analyze media
            media_data = self._download_media(media_url)
            if not media_data:
                analysis["error"] = "Could not download media"
                return analysis

            # Extract metadata
            metadata = self._extract_media_metadata(media_data, media_url)
            analysis["metadata"] = metadata

            # Reverse image search
            if self._is_image_url(media_url):
                reverse_results = self._perform_reverse_image_search(media_url)
                analysis["reverse_search"] = reverse_results

            # Forensic analysis
            forensic = self._perform_forensic_analysis(media_data, metadata)
            analysis["forensic_analysis"] = forensic

            # Cross-reference with known sources
            cross_ref = self._cross_reference_media(media_data, metadata)
            analysis["cross_references"] = cross_ref

            return analysis

        except Exception as e:
            logger.error(f"Failed to analyze media {media_url}: {e}")
            return {"media_url": media_url, "error": str(e), "analysis": {}}

    def _download_media(self, url: str) -> Optional[bytes]:
        """Download media from URL"""
        try:
            headers = {"User-Agent": self.user_agent}
            response = requests.get(url, headers=headers, timeout=self.timeout)
            response.raise_for_status()
            return response.content
        except Exception as e:
            logger.warning(f"Could not download media from {url}: {e}")
            return None

    def _is_image_url(self, url: str) -> bool:
        """Check if URL points to an image"""
        image_extensions = [".jpg", ".jpeg", ".png", ".gif", ".bmp", ".tiff", ".webp"]
        return any(url.lower().endswith(ext) for ext in image_extensions)

    def _extract_media_metadata(self, media_data: bytes, url: str) -> Dict[str, Any]:
        """Extract metadata from media"""
        metadata = {
            "file_size": len(media_data),
            "file_hash": hashlib.sha256(media_data).hexdigest(),
            "url": url,
        }

        try:
            # Try to identify file type
            if HAS_PIL and self._is_image_url(url):
                from io import BytesIO
                from PIL import (
                    Image,
                    ExifTags,
                )  # Import here to avoid issues if PIL not available

                image = Image.open(BytesIO(media_data))

                metadata.update(
                    {
                        "format": image.format,
                        "width": image.width,
                        "height": image.height,
                        "mode": image.mode,
                        "is_animated": getattr(image, "is_animated", False),
                    }
                )

                # Extract EXIF data
                if hasattr(image, "_getexif") and image._getexif():  # type: ignore
                    exif_data = {}
                    exif_dict = image._getexif()  # type: ignore
                    for tag, value in exif_dict.items():
                        tag_name = ExifTags.TAGS.get(tag, str(tag))  # type: ignore
                        exif_data[tag_name] = str(value)
                    metadata["exif"] = exif_data

                    # Extract GPS if available
                    gps = self._extract_gps_from_exif(exif_data)
                    if gps:
                        metadata["gps_coordinates"] = gps

        except Exception as e:
            logger.warning(f"Could not extract detailed metadata: {e}")

        return metadata

    def _extract_gps_from_exif(
        self, exif_data: Dict[str, Any]
    ) -> Optional[Dict[str, float]]:
        """Extract GPS coordinates from EXIF data"""
        try:
            gps_tags = [
                "GPSLatitude",
                "GPSLongitude",
                "GPSLatitudeRef",
                "GPSLongitudeRef",
            ]

            if not all(tag in exif_data for tag in gps_tags):
                return None

            def convert_to_degrees(value_str: str) -> float:
                # Parse GPS coordinate string like "(41, 53, 34.12)"
                parts = re.findall(r"[\d.]+", value_str)
                if len(parts) >= 3:
                    degrees = float(parts[0])
                    minutes = float(parts[1])
                    seconds = float(parts[2])
                    return degrees + (minutes / 60.0) + (seconds / 3600.0)
                return 0.0

            lat = convert_to_degrees(exif_data["GPSLatitude"])
            lon = convert_to_degrees(exif_data["GPSLongitude"])

            if exif_data.get("GPSLatitudeRef") == "S":
                lat = -lat
            if exif_data.get("GPSLongitudeRef") == "W":
                lon = -lon

            return {"latitude": lat, "longitude": lon}

        except Exception as e:
            logger.debug(f"Could not extract GPS data: {e}")
            return None

    def _perform_reverse_image_search(self, image_url: str) -> Dict[str, Any]:
        """Perform reverse image search"""
        results = {
            "google_search_url": f"https://www.google.com/searchbyimage?image_url={image_url}",
            "yandex_search_url": f"https://yandex.com/images/search?url={image_url}&rpt=imageview",
            "tineye_search_url": f"https://tineye.com/search?url={image_url}",
        }

        # Note: Actual API calls would require API keys and are not implemented here
        # to avoid rate limiting and API key requirements
        results["note"] = (
            "Reverse image search URLs generated - manual checking required"
        )

        return results

    def _perform_forensic_analysis(
        self, media_data: bytes, metadata: Dict[str, Any]
    ) -> Dict[str, Any]:
        """Perform forensic analysis on media"""
        forensic: Dict[str, Any] = {
            "file_integrity": "unknown",
            "manipulation_indicators": [],
            "compression_artifacts": False,
            "metadata_consistency": True,
        }

        try:
            # Check file size vs expected
            file_size = metadata.get("file_size", 0)
            if file_size > 0:
                # Very small files might be suspicious
                if file_size < 100:
                    forensic["manipulation_indicators"].append(
                        "Unusually small file size"
                    )

                # Very large files might indicate steganography
                if file_size > 50 * 1024 * 1024:  # 50MB
                    forensic["manipulation_indicators"].append(
                        "Unusually large file size"
                    )

            # Check for metadata inconsistencies
            if metadata.get("width") and metadata.get("height"):
                width, height = metadata["width"], metadata["height"]
                # Suspicious aspect ratios
                if width > height * 10 or height > width * 10:
                    forensic["manipulation_indicators"].append("Extreme aspect ratio")
                    forensic["metadata_consistency"] = False

            # Check EXIF consistency
            exif = metadata.get("exif", {})
            if exif:
                # Check if software field indicates editing
                software = exif.get("Software", "").lower()
                if any(
                    edit_tool in software
                    for edit_tool in ["photoshop", "gimp", "paint", "editor"]
                ):
                    forensic["manipulation_indicators"].append(
                        "Image edited with software"
                    )

        except Exception as e:
            logger.warning(f"Forensic analysis failed: {e}")

        return forensic

    def _cross_reference_media(
        self, media_data: bytes, metadata: Dict[str, Any]
    ) -> Dict[str, Any]:
        """Cross-reference media with known sources"""
        cross_ref: Dict[str, Any] = {
            "known_sources": [],
            "similar_images": [],
            "social_media_presence": [],
            "hash_checked": False,
            "location_analysis": {},
        }

        try:
            # Check hash against known databases (placeholder)
            file_hash = metadata.get("file_hash", "")
            if file_hash:
                # This would typically query hash databases
                cross_ref["hash_checked"] = True
                cross_ref["hash_databases"] = [
                    "Placeholder - would check against known image databases"
                ]

            # Check GPS coordinates against known locations
            gps = metadata.get("gps_coordinates")
            if gps:
                location_info = self._analyze_location(gps)
                cross_ref["location_analysis"] = location_info

        except Exception as e:
            logger.warning(f"Cross-reference failed: {e}")

        return cross_ref

    def geolocate_image(self, image_url: str) -> Dict[str, Any]:
        """Geolocate image using various techniques"""
        try:
            # First analyze the media
            analysis = self.analyze_media(image_url)
            metadata = analysis.get("metadata", {})

            geolocation: Dict[str, Any] = {
                "image_url": image_url,
                "geolocation_methods": [],
                "possible_locations": [],
                "confidence": 0.0,
            }

            # Method 1: EXIF GPS data
            gps = metadata.get("gps_coordinates")
            if gps:
                geolocation["geolocation_methods"].append("exif_gps")
                geolocation["possible_locations"].append(
                    {
                        "coordinates": gps,
                        "method": "exif_gps",
                        "confidence": 0.9,
                        "source": "Image EXIF data",
                    }
                )
                geolocation["confidence"] = max(geolocation["confidence"], 0.9)

            # Method 2: Reverse image search locations
            reverse_search = analysis.get("reverse_search", {})
            if reverse_search:
                geolocation["geolocation_methods"].append("reverse_image_search")
                # This would parse search results for location data
                geolocation["reverse_search_urls"] = [
                    reverse_search.get("google_search_url"),
                    reverse_search.get("yandex_search_url"),
                ]

            # Method 3: Visual landmarks recognition (placeholder)
            visual_landmarks = self._identify_visual_landmarks(metadata)
            if visual_landmarks:
                geolocation["geolocation_methods"].append("visual_landmarks")
                geolocation["possible_locations"].extend(visual_landmarks)

            # Method 4: Shadow analysis for time/season
            shadow_analysis = self._analyze_shadows(metadata)
            if shadow_analysis:
                geolocation["shadow_analysis"] = shadow_analysis

            return geolocation

        except Exception as e:
            logger.error(f"Failed to geolocate image {image_url}: {e}")
            return {"image_url": image_url, "error": str(e), "possible_locations": []}

    def _analyze_location(self, gps: Dict[str, float]) -> Dict[str, Any]:
        """Analyze GPS coordinates for location information"""
        try:
            lat, lon = gps["latitude"], gps["longitude"]

            # Basic location analysis (could be enhanced with geocoding APIs)
            location_info = {
                "coordinates": gps,
                "hemisphere": "Northern" if lat >= 0 else "Southern",
                "latitude_band": self._get_latitude_band(lat),
                "estimated_country": self._estimate_country(lat, lon),
            }

            return location_info

        except Exception as e:
            return {"error": str(e)}

    def _get_latitude_band(self, latitude: float) -> str:
        """Get latitude band description"""
        abs_lat = abs(latitude)
        if abs_lat < 23.5:
            return "Tropical"
        elif abs_lat < 35:
            return "Subtropical"
        elif abs_lat < 50:
            return "Temperate"
        elif abs_lat < 66.5:
            return "Subarctic"
        else:
            return "Arctic"

    def _estimate_country(self, lat: float, lon: float) -> str:
        """Basic country estimation from coordinates (simplified)"""
        # This is a very basic implementation - real geocoding would use APIs
        if 25 <= lat <= 50 and -125 <= lon <= -65:
            return "United States (approximate)"
        elif 35 <= lat <= 72 and -10 <= lon <= 40:
            return "Europe (approximate)"
        elif -35 <= lat <= 35 and -20 <= lon <= 55:
            return "Africa/Middle East (approximate)"
        else:
            return "Unknown/Other region"

    def _identify_visual_landmarks(
        self, metadata: Dict[str, Any]
    ) -> List[Dict[str, Any]]:
        """Identify visual landmarks (placeholder for computer vision)"""
        # This would require computer vision libraries like OpenCV
        # For now, return empty list
        return []

    def _analyze_shadows(self, metadata: Dict[str, Any]) -> Optional[Dict[str, Any]]:
        """Analyze shadows for time/season information"""
        # This would require image processing to detect shadows
        # For now, return None
        return None

    def investigate_social_media(
        self, username: str, platforms: Optional[List[str]] = None
    ) -> Dict[str, Any]:
        """Investigate social media presence using Bellingcat techniques"""
        try:
            if platforms is None:
                platforms = list(self.social_platforms.keys())

            investigation: Dict[str, Any] = {
                "username": username,
                "platforms_checked": platforms,
                "profiles_found": [],
                "cross_platform_analysis": {},
                "timestamp": datetime.now().isoformat(),
            }

            for platform in platforms:
                if platform in self.social_platforms:
                    profile_url = f"{self.social_platforms[platform]}{username}"
                    profile_info = self._check_social_profile(profile_url, platform)

                    if profile_info.get("exists"):
                        investigation["profiles_found"].append(profile_info)

            # Cross-platform analysis
            if len(investigation["profiles_found"]) > 1:
                cross_analysis = self._analyze_cross_platform_presence(
                    investigation["profiles_found"]
                )
                investigation["cross_platform_analysis"] = cross_analysis

            return investigation

        except Exception as e:
            logger.error(f"Failed to investigate social media for {username}: {e}")
            return {"username": username, "error": str(e), "profiles_found": []}

    def _check_social_profile(self, profile_url: str, platform: str) -> Dict[str, Any]:
        """Check if a social media profile exists"""
        try:
            headers = {"User-Agent": self.user_agent}
            response = requests.head(
                profile_url, headers=headers, timeout=self.timeout, allow_redirects=True
            )

            profile_info = {
                "platform": platform,
                "url": profile_url,
                "exists": response.status_code == 200,
                "status_code": response.status_code,
                "last_checked": datetime.now().isoformat(),
            }

            # Try to get additional info from the page
            if response.status_code == 200:
                try:
                    response = requests.get(
                        profile_url, headers=headers, timeout=self.timeout
                    )
                    # Basic content analysis (could be enhanced)
                    profile_info["content_length"] = len(response.content)
                    profile_info["has_content"] = len(response.content) > 1000
                except Exception:
                    # Ignore content fetch errors; HEAD already provided existence/status
                    pass

            return profile_info

        except Exception as e:
            return {
                "platform": platform,
                "url": profile_url,
                "exists": False,
                "error": str(e),
            }

    def _analyze_cross_platform_presence(
        self, profiles: List[Dict[str, Any]]
    ) -> Dict[str, Any]:
        """Analyze cross-platform social media presence"""
        analysis: Dict[str, Any] = {
            "total_platforms": len(profiles),
            "consistency_score": 0.0,
            "activity_patterns": [],
            "risk_indicators": [],
        }

        try:
            # Check for consistent usernames across platforms
            usernames = [p.get("url", "").split("/")[-1] for p in profiles]
            consistent_username = len(set(usernames)) == 1
            analysis["consistent_username"] = consistent_username

            if consistent_username:
                analysis["consistency_score"] += 0.5

            # Check for activity patterns
            active_profiles = [p for p in profiles if p.get("has_content")]
            analysis["active_profiles"] = len(active_profiles)

            if len(active_profiles) > len(profiles) * 0.5:
                analysis["activity_patterns"].append("Active across multiple platforms")

            # Risk indicators
            if len(profiles) >= 5:
                analysis["risk_indicators"].append("Heavy multi-platform presence")

            if not consistent_username:
                analysis["risk_indicators"].append(
                    "Inconsistent usernames across platforms"
                )

        except Exception as e:
            logger.warning(f"Cross-platform analysis failed: {e}")

        return analysis
