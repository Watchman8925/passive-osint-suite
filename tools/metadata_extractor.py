"""
Metadata Extraction and File Analysis Module

This module provides local file analysis capabilities including:
- EXIF data extraction from images
- File type detection
- Basic file hashing
- Content analysis
- Local file intelligence gathering
"""

import os
import hashlib
import mimetypes
from typing import Dict, List, Optional, Any
from pathlib import Path
from PIL import Image, ExifTags
import pandas as pd
from datetime import datetime

from osint_utils import OSINTUtils


class MetadataExtractor(OSINTUtils):
    """Extract metadata from various file types locally"""

    def __init__(self):
        super().__init__()
        self.supported_formats = {
            'image': ['.jpg', '.jpeg', '.png', '.gif', '.bmp', '.tiff', '.webp'],
            'document': ['.pdf', '.doc', '.docx', '.txt', '.rtf'],
            'audio': ['.mp3', '.wav', '.flac', '.aac'],
            'video': ['.mp4', '.avi', '.mov', '.mkv']
        }

    def analyze_file(self, file_path: str) -> Dict[str, Any]:
        """Analyze a single file and extract metadata"""
        if not os.path.exists(file_path):
            return {"error": f"File not found: {file_path}"}

        file_info = {
            "file_path": file_path,
            "file_name": os.path.basename(file_path),
            "file_size": os.path.getsize(file_path),
            "modified_time": datetime.fromtimestamp(os.path.getmtime(file_path)).isoformat(),
            "created_time": datetime.fromtimestamp(os.path.getctime(file_path)).isoformat(),
        }

        # Get file type
        mime_type, encoding = mimetypes.guess_type(file_path)
        file_info["mime_type"] = mime_type
        file_info["encoding"] = encoding

        # Calculate hashes
        file_info.update(self._calculate_hashes(file_path))

        # Extract format-specific metadata
        file_ext = Path(file_path).suffix.lower()
        if file_ext in self.supported_formats['image']:
            file_info["metadata"] = self._extract_image_metadata(file_path)
        elif file_ext in self.supported_formats['document']:
            file_info["metadata"] = self._extract_document_metadata(file_path)
        else:
            file_info["metadata"] = {"type": "unsupported"}

        return file_info

    def _calculate_hashes(self, file_path: str) -> Dict[str, str]:
        """Calculate various hashes for the file"""
        hashes = {}
        hash_algorithms = ['md5', 'sha1', 'sha256']

        for algo in hash_algorithms:
            try:
                hash_obj = hashlib.new(algo)
                with open(file_path, 'rb') as f:
                    for chunk in iter(lambda: f.read(4096), b""):
                        hash_obj.update(chunk)
                hashes[algo] = hash_obj.hexdigest()
            except Exception as e:
                hashes[algo] = f"Error: {str(e)}"

        return hashes

    def _extract_image_metadata(self, file_path: str) -> Dict[str, Any]:
        """Extract EXIF and other metadata from images"""
        try:
            with Image.open(file_path) as img:
                metadata = {
                    "format": img.format,
                    "size": img.size,
                    "mode": img.mode,
                    "exif": {}
                }

                # Extract EXIF data
                if hasattr(img, '_getexif') and img._getexif():
                    exif_data = img._getexif()
                    for tag, value in exif_data.items():
                        tag_name = ExifTags.TAGS.get(tag, tag)
                        if isinstance(value, bytes):
                            try:
                                value = value.decode('utf-8', errors='ignore')
                            except:
                                value = str(value)
                        metadata["exif"][tag_name] = str(value)

                return metadata
        except Exception as e:
            return {"error": f"Failed to extract image metadata: {str(e)}"}

    def _extract_document_metadata(self, file_path: str) -> Dict[str, Any]:
        """Extract metadata from documents"""
        metadata = {"type": "document"}

        try:
            # Basic text file analysis
            with open(file_path, 'r', encoding='utf-8', errors='ignore') as f:
                content = f.read()
                metadata.update({
                    "line_count": len(content.split('\n')),
                    "word_count": len(content.split()),
                    "char_count": len(content),
                    "encoding": "utf-8"
                })

                # Check for potential sensitive information
                sensitive_patterns = {
                    "emails": len(self._find_emails(content)),
                    "phones": len(self._find_phone_numbers(content)),
                    "urls": len(self._find_urls(content))
                }
                metadata["sensitive_data"] = sensitive_patterns

        except UnicodeDecodeError:
            # Binary file or different encoding
            metadata["encoding"] = "binary/unknown"
        except Exception as e:
            metadata["error"] = str(e)

        return metadata

    def _find_emails(self, text: str) -> List[str]:
        """Find email addresses in text"""
        import re
        email_pattern = r'\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Z|a-z]{2,}\b'
        return re.findall(email_pattern, text)

    def _find_phone_numbers(self, text: str) -> List[str]:
        """Find phone numbers in text"""
        import re
        phone_pattern = r'\b\d{3}[-.]?\d{3}[-.]?\d{4}\b'
        return re.findall(phone_pattern, text)

    def _find_urls(self, text: str) -> List[str]:
        """Find URLs in text"""
        import re
        url_pattern = r'http[s]?://(?:[a-zA-Z]|[0-9]|[$-_@.&+]|[!*\\(\\),]|(?:%[0-9a-fA-F][0-9a-fA-F]))+'
        return re.findall(url_pattern, text)

    def analyze_directory(self, directory_path: str, recursive: bool = False) -> List[Dict[str, Any]]:
        """Analyze all files in a directory"""
        results = []
        path_obj = Path(directory_path)

        if not path_obj.exists():
            return [{"error": f"Directory not found: {directory_path}"}]

        pattern = "**/*" if recursive else "*"

        for file_path in path_obj.glob(pattern):
            if file_path.is_file():
                results.append(self.analyze_file(str(file_path)))

        return results

    def generate_report(self, analysis_results: List[Dict[str, Any]]) -> str:
        """Generate a summary report of file analysis"""
        if not analysis_results:
            return "No files analyzed"

        total_files = len(analysis_results)
        total_size = sum(result.get('file_size', 0) for result in analysis_results if 'file_size' in result)

        # Count file types
        file_types = {}
        for result in analysis_results:
            mime_type = result.get('mime_type', 'unknown')
            file_types[mime_type] = file_types.get(mime_type, 0) + 1

        report = f"""
File Analysis Report
===================

Total Files Analyzed: {total_files}
Total Size: {self._format_size(total_size)}

File Types:
{chr(10).join(f"- {ftype}: {count}" for ftype, count in file_types.items())}

Detailed Results:
"""

        for result in analysis_results[:10]:  # Show first 10 files
            report += f"\n- {result.get('file_name', 'Unknown')}: {result.get('mime_type', 'unknown')}"

        if total_files > 10:
            report += f"\n... and {total_files - 10} more files"

        return report

    def _format_size(self, size_bytes: int) -> str:
        """Format file size in human readable format"""
        for unit in ['B', 'KB', 'MB', 'GB']:
            if size_bytes < 1024.0:
                return f"{size_bytes:.1f} {unit}"
            size_bytes /= 1024.0
        return f"{size_bytes:.1f} TB"