#!/usr/bin/env python3
"""
Metadata Extractor Module
Extract and analyze metadata from files and documents.
"""

import os
import hashlib
import logging
from datetime import datetime
from typing import Any, Dict, Optional

logger = logging.getLogger(__name__)

try:
    from PIL import Image, ExifTags

    HAS_PIL = True
except ImportError:
    HAS_PIL = False
    logger.warning("PIL not available - image metadata extraction disabled")

try:
    import magic

    HAS_MAGIC = True
except ImportError:
    HAS_MAGIC = False
    logger.warning("python-magic not available - file type detection limited")


class MetadataExtractor:
    """Advanced metadata extractor for various file types"""

    def __init__(self):
        self.enabled = True
        self.supported_formats = {
            "image": [".jpg", ".jpeg", ".png", ".gif", ".bmp", ".tiff", ".webp"],
            "document": [".pdf", ".doc", ".docx", ".txt", ".rtf"],
            "audio": [".mp3", ".wav", ".flac", ".aac", ".ogg"],
            "video": [".mp4", ".avi", ".mkv", ".mov", ".wmv"],
        }
        logger.info("MetadataExtractor initialized with full functionality")

    def extract_metadata(self, file_path: str) -> Dict[str, Any]:
        """Extract metadata from file"""
        if not os.path.exists(file_path):
            return {"error": f"File not found: {file_path}", "extracted": False}

        try:
            # Basic file information
            stat_info = os.stat(file_path)
            file_info = {
                "file_path": file_path,
                "file_name": os.path.basename(file_path),
                "file_size": stat_info.st_size,
                "modified_time": datetime.fromtimestamp(stat_info.st_mtime).isoformat(),
                "created_time": datetime.fromtimestamp(stat_info.st_ctime).isoformat(),
                "file_extension": os.path.splitext(file_path)[1].lower(),
                "extracted": True,
            }

            # Calculate file hash
            file_info["sha256_hash"] = self._calculate_file_hash(file_path)

            # Detect MIME type
            if HAS_MAGIC:
                file_info["mime_type"] = magic.from_file(file_path, mime=True)  # type: ignore
                file_info["file_description"] = magic.from_file(file_path)  # type: ignore

            # Extract format-specific metadata
            ext = file_info["file_extension"]
            if ext in self.supported_formats["image"]:
                file_info["metadata"] = self._extract_image_metadata(file_path)
                file_info["file_type"] = "image"
            elif ext in self.supported_formats["document"]:
                file_info["metadata"] = self._extract_document_metadata(file_path)
                file_info["file_type"] = "document"
            elif ext in self.supported_formats["audio"]:
                file_info["metadata"] = self._extract_audio_metadata(file_path)
                file_info["file_type"] = "audio"
            elif ext in self.supported_formats["video"]:
                file_info["metadata"] = self._extract_video_metadata(file_path)
                file_info["file_type"] = "video"
            else:
                file_info["metadata"] = {}
                file_info["file_type"] = "unknown"

            return file_info

        except Exception as e:
            logger.error(f"Failed to extract metadata from {file_path}: {e}")
            return {"error": str(e), "file_path": file_path, "extracted": False}

    def _calculate_file_hash(self, file_path: str) -> str:
        """Calculate SHA256 hash of file"""
        try:
            hash_sha256 = hashlib.sha256()
            with open(file_path, "rb") as f:
                for chunk in iter(lambda: f.read(4096), b""):
                    hash_sha256.update(chunk)
            return hash_sha256.hexdigest()
        except Exception as e:
            logger.warning(f"Could not calculate hash for {file_path}: {e}")
            return ""

    def _extract_image_metadata(self, file_path: str) -> Dict[str, Any]:
        """Extract EXIF and other metadata from images"""
        if not HAS_PIL:
            return {"error": "PIL not available for image metadata extraction"}

        try:
            metadata = {}
            with Image.open(file_path) as img:  # type: ignore
                # Basic image properties
                metadata["width"] = img.width
                metadata["height"] = img.height
                metadata["format"] = img.format
                metadata["mode"] = img.mode

                # Extract EXIF data
                if hasattr(img, "_getexif") and img._getexif() is not None:  # type: ignore
                    exif_data = {}
                    exif_dict = img._getexif()  # type: ignore
                    for tag, value in exif_dict.items():
                        tag_name = ExifTags.TAGS.get(tag, tag)  # type: ignore
                        exif_data[tag_name] = str(value)
                    metadata["exif"] = exif_data

                # GPS data extraction
                if "exif" in metadata and metadata["exif"]:
                    gps_info = self._extract_gps_data(metadata["exif"])
                    if gps_info:
                        metadata["gps"] = gps_info

            return metadata

        except Exception as e:
            return {"error": f"Failed to extract image metadata: {str(e)}"}

    def _extract_gps_data(
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

            def convert_to_degrees(value):
                """Convert GPS coordinate to decimal degrees"""
                d, m, s = value
                return d + (m / 60.0) + (s / 3600.0)

            lat = convert_to_degrees(eval(exif_data["GPSLatitude"]))
            lon = convert_to_degrees(eval(exif_data["GPSLongitude"]))

            if exif_data["GPSLatitudeRef"] == "S":
                lat = -lat
            if exif_data["GPSLongitudeRef"] == "W":
                lon = -lon

            return {"latitude": lat, "longitude": lon}

        except Exception as e:
            logger.warning(f"Could not extract GPS data: {e}")
            return None

    def _extract_document_metadata(self, file_path: str) -> Dict[str, Any]:
        """Extract metadata from documents"""
        try:
            metadata: Dict[str, Any] = {}

            # For text files, extract basic statistics
            if file_path.lower().endswith(".txt"):
                with open(file_path, "r", encoding="utf-8", errors="ignore") as f:
                    content = f.read()
                    metadata["character_count"] = len(content)
                    metadata["line_count"] = len(content.split("\n"))
                    metadata["word_count"] = len(content.split())

                    # Extract potential entities (basic)
                    lines = content.split("\n")[:10]  # First 10 lines
                    metadata["sample_content"] = lines

            # For other document types, return basic info
            metadata["document_type"] = "text/plain"

            return metadata

        except Exception as e:
            return {"error": f"Failed to extract document metadata: {str(e)}"}

    def _extract_audio_metadata(self, file_path: str) -> Dict[str, Any]:
        """Extract metadata from audio files"""
        # Basic implementation - could be extended with mutagen library
        try:
            metadata = {"audio_type": "unknown"}
            # Could add more sophisticated audio metadata extraction here
            return metadata
        except Exception as e:
            return {"error": f"Failed to extract audio metadata: {str(e)}"}

    def _extract_video_metadata(self, file_path: str) -> Dict[str, Any]:
        """Extract metadata from video files"""
        # Basic implementation - could be extended with ffprobe or similar
        try:
            metadata = {"video_type": "unknown"}
            # Could add more sophisticated video metadata extraction here
            return metadata
        except Exception as e:
            return {"error": f"Failed to extract video metadata: {str(e)}"}

    def analyze_document(self, content: str) -> Dict[str, Any]:
        """Analyze document content for entities and patterns"""
        try:
            analysis: Dict[str, Any] = {
                "character_count": len(content),
                "word_count": len(content.split()),
                "line_count": len(content.split("\n")),
                "entities": [],
                "patterns": [],
            }

            # Basic entity extraction (could be enhanced with NLP)

            # Look for email patterns
            import re

            emails = re.findall(
                r"\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Z|a-z]{2,}\b", content
            )
            if emails:
                analysis["entities"].extend(
                    [{"type": "email", "value": email} for email in emails]
                )

            # Look for phone numbers (basic pattern)
            phones = re.findall(r"\b\d{3}[-.]?\d{3}[-.]?\d{4}\b", content)
            if phones:
                analysis["entities"].extend(
                    [{"type": "phone", "value": phone} for phone in phones]
                )

            # Look for URLs
            urls = re.findall(
                r"http[s]?://(?:[a-zA-Z]|[0-9]|[$-_@.&+]|[!*\\(\\),]|(?:%[0-9a-fA-F][0-9a-fA-F]))+",
                content,
            )
            if urls:
                analysis["entities"].extend(
                    [{"type": "url", "value": url} for url in urls]
                )

            return analysis

        except Exception as e:
            logger.error(f"Failed to analyze document content: {e}")
            return {"error": str(e), "entities": [], "patterns": []}
