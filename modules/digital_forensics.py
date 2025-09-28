"""
Digital Forensics and Metadata Analysis Module
Provides comprehensive digital forensics capabilities using open source tools
"""

import os
import json
import subprocess
import logging
from typing import Dict, List, Optional, Any

logger = logging.getLogger(__name__)

class DigitalForensicsAnalyzer:
    """Digital forensics analyzer using open source tools"""

    def __init__(self):
        self.tools = {
            'exiftool': self._check_tool('exiftool'),
            'tesseract': self._check_tool('tesseract'),
            'zbarimg': self._check_tool('zbarimg'),
            'pdfid': self._check_tool('pdfid.py'),
            'oledump': self._check_tool('oledump.py')
        }

    def _check_tool(self, tool_name: str) -> bool:
        """Check if a tool is available"""
        try:
            subprocess.run([tool_name, '--help' if tool_name != 'pdfid.py' else '-h'],
                         capture_output=True, timeout=5)
            return True
        except (subprocess.TimeoutExpired, FileNotFoundError, subprocess.CalledProcessError):
            return False

    def extract_metadata(self, file_path: str) -> Dict[str, Any]:
        """
        Extract comprehensive metadata from files using ExifTool

        Args:
            file_path: Path to the file to analyze

        Returns:
            Dictionary containing extracted metadata
        """
        if not self.tools['exiftool']:
            return {"error": "ExifTool not available"}

        if not os.path.exists(file_path):
            return {"error": f"File not found: {file_path}"}

        try:
            result = subprocess.run(
                ['exiftool', '-j', '-a', '-u', file_path],
                capture_output=True,
                text=True,
                timeout=30
            )

            if result.returncode == 0:
                metadata = json.loads(result.stdout)
                return {
                    "success": True,
                    "metadata": metadata[0] if metadata else {},
                    "file_path": file_path
                }
            else:
                return {"error": f"ExifTool error: {result.stderr}"}

        except (subprocess.TimeoutExpired, json.JSONDecodeError) as e:
            return {"error": f"Metadata extraction failed: {str(e)}"}

    def extract_text_from_image(self, image_path: str, lang: str = 'eng') -> Dict[str, Any]:
        """
        Extract text from images using Tesseract OCR

        Args:
            image_path: Path to the image file
            lang: Language code for OCR (default: eng)

        Returns:
            Dictionary containing extracted text
        """
        if not self.tools['tesseract']:
            return {"error": "Tesseract not available"}

        if not os.path.exists(image_path):
            return {"error": f"Image not found: {image_path}"}

        try:
            result = subprocess.run(
                ['tesseract', image_path, 'stdout', '-l', lang],
                capture_output=True,
                text=True,
                timeout=60
            )

            if result.returncode == 0:
                return {
                    "success": True,
                    "text": result.stdout.strip(),
                    "image_path": image_path,
                    "language": lang
                }
            else:
                return {"error": f"Tesseract error: {result.stderr}"}

        except subprocess.TimeoutExpired:
            return {"error": "OCR timeout"}

    def scan_qr_barcodes(self, image_path: str) -> Dict[str, Any]:
        """
        Scan QR codes and barcodes from images using Zbar

        Args:
            image_path: Path to the image file

        Returns:
            Dictionary containing detected codes
        """
        if not self.tools['zbarimg']:
            return {"error": "Zbar not available"}

        if not os.path.exists(image_path):
            return {"error": f"Image not found: {image_path}"}

        try:
            result = subprocess.run(
                ['zbarimg', '--quiet', '--xml', image_path],
                capture_output=True,
                text=True,
                timeout=30
            )

            codes = []
            if result.returncode == 0 and result.stdout:
                # Parse XML output for codes
                lines = result.stdout.split('\n')
                for line in lines:
                    if '<symbol' in line and 'data=' in line:
                        # Extract data from XML
                        start = line.find('data="') + 6
                        end = line.find('"', start)
                        if start > 5 and end > start:
                            codes.append(line[start:end])

            return {
                "success": True,
                "codes": codes,
                "count": len(codes),
                "image_path": image_path
            }

        except subprocess.TimeoutExpired:
            return {"error": "Barcode scanning timeout"}

    def analyze_pdf(self, pdf_path: str) -> Dict[str, Any]:
        """
        Analyze PDF files for suspicious content using pdfid

        Args:
            pdf_path: Path to the PDF file

        Returns:
            Dictionary containing PDF analysis results
        """
        if not self.tools['pdfid']:
            return {"error": "pdfid not available"}

        if not os.path.exists(pdf_path):
            return {"error": f"PDF not found: {pdf_path}"}

        try:
            result = subprocess.run(
                ['pdfid.py', pdf_path],
                capture_output=True,
                text=True,
                timeout=30
            )

            if result.returncode == 0:
                # Parse pdfid output
                analysis = {}
                lines = result.stdout.split('\n')
                for line in lines:
                    if ':' in line and len(line.split(':')) == 2:
                        key, value = line.split(':', 1)
                        analysis[key.strip()] = value.strip()

                return {
                    "success": True,
                    "analysis": analysis,
                    "pdf_path": pdf_path
                }
            else:
                return {"error": f"pdfid error: {result.stderr}"}

        except subprocess.TimeoutExpired:
            return {"error": "PDF analysis timeout"}

    def analyze_office_document(self, doc_path: str) -> Dict[str, Any]:
        """
        Analyze Office documents using oletools

        Args:
            doc_path: Path to the Office document

        Returns:
            Dictionary containing document analysis
        """
        if not self.tools['oledump']:
            return {"error": "oledump not available"}

        if not os.path.exists(doc_path):
            return {"error": f"Document not found: {doc_path}"}

        try:
            result = subprocess.run(
                ['oledump.py', doc_path],
                capture_output=True,
                text=True,
                timeout=30
            )

            streams = []
            if result.returncode == 0:
                lines = result.stdout.split('\n')
                for line in lines:
                    if line.strip() and not line.startswith('ole'):
                        streams.append(line.strip())

            return {
                "success": True,
                "streams": streams,
                "stream_count": len(streams),
                "document_path": doc_path
            }

        except subprocess.TimeoutExpired:
            return {"error": "Document analysis timeout"}

    def comprehensive_file_analysis(self, file_path: str) -> Dict[str, Any]:
        """
        Perform comprehensive analysis on a file using all available tools

        Args:
            file_path: Path to the file to analyze

        Returns:
            Dictionary containing all analysis results
        """
        results: Dict[str, Any] = {
            "file_path": file_path,
            "file_exists": os.path.exists(file_path),
            "analyses": {}
        }

        if not results["file_exists"]:
            return results

        # Get file extension for tool selection
        _, ext = os.path.splitext(file_path.lower())

        # Always try metadata extraction
        results["analyses"]["metadata"] = self.extract_metadata(file_path)

        # Image-specific analysis
        if ext in ['.jpg', '.jpeg', '.png', '.bmp', '.tiff', '.gif']:
            results["analyses"]["ocr"] = self.extract_text_from_image(file_path)
            results["analyses"]["barcodes"] = self.scan_qr_barcodes(file_path)

        # PDF analysis
        elif ext == '.pdf':
            results["analyses"]["pdf_analysis"] = self.analyze_pdf(file_path)

        # Office document analysis
        elif ext in ['.doc', '.docx', '.xls', '.xlsx', '.ppt', '.pptx']:
            results["analyses"]["office_analysis"] = self.analyze_office_document(file_path)

        return results

    def batch_analyze_directory(self, directory_path: str,
                              file_extensions: Optional[List[str]] = None) -> Dict[str, Any]:
        """
        Analyze all files in a directory

        Args:
            directory_path: Path to the directory
            file_extensions: List of file extensions to analyze (optional)

        Returns:
            Dictionary containing batch analysis results
        """
        if not os.path.exists(directory_path):
            return {"error": f"Directory not found: {directory_path}"}

        results: Dict[str, Any] = {
            "directory": directory_path,
            "files_analyzed": 0,
            "results": []
        }

        for root, dirs, files in os.walk(directory_path):
            for file in files:
                file_path = os.path.join(root, file)

                # Check extension filter
                if file_extensions:
                    _, ext = os.path.splitext(file.lower())
                    if ext not in file_extensions:
                        continue

                analysis = self.comprehensive_file_analysis(file_path)
                if analysis["file_exists"]:
                    results["results"].append(analysis)
                    results["files_analyzed"] += 1

        return results