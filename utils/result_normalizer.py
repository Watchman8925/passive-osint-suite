"""
Result Normalizers for OSINT Suite
Standardize module outputs to consistent format
"""

import json
from datetime import datetime
from typing import Any, Dict, List


class ResultNormalizer:
    """Normalize module results to consistent format"""

    @staticmethod
    def normalize(result: Any, module_name: str = "") -> Dict[str, Any]:
        """
        Normalize any result to standard format:
        {
            "status": "success" | "error",
            "data": {...} | [...] | None,
            "error": "error message" | None,
            "metadata": {
                "module": "module_name",
                "timestamp": "ISO timestamp",
                "normalized": True
            }
        }
        """
        try:
            # Handle None results
            if result is None:
                return ResultNormalizer._create_error_response(
                    "No result returned", module_name
                )

            # Handle existing normalized results
            if isinstance(result, dict) and ResultNormalizer._is_normalized(result):
                # Add metadata if missing
                if "metadata" not in result:
                    result["metadata"] = ResultNormalizer._create_metadata(module_name)
                return result

            # Handle dict results that need normalization
            if isinstance(result, dict):
                return ResultNormalizer._normalize_dict_result(result, module_name)

            # Handle list results
            if isinstance(result, list):
                return ResultNormalizer._normalize_list_result(result, module_name)

            # Handle string results
            if isinstance(result, str):
                return ResultNormalizer._normalize_string_result(result, module_name)

            # Handle other types
            return ResultNormalizer._normalize_other_result(result, module_name)

        except Exception as e:
            return ResultNormalizer._create_error_response(
                f"Normalization failed: {str(e)}", module_name
            )

    @staticmethod
    def _is_normalized(result: Dict) -> bool:
        """Check if result is already in normalized format"""
        required_keys = {"status", "data"}
        has_required = all(key in result for key in required_keys)

        if not has_required:
            return False

        # Check status is valid
        status = result.get("status")
        if status not in ["success", "error"]:
            return False

        # Check error field is present for errors
        if status == "error" and "error" not in result:
            return False

        return True

    @staticmethod
    def _normalize_dict_result(result: Dict, module_name: str) -> Dict:
        """Normalize dictionary results"""
        # Check for error indicators
        if ResultNormalizer._has_error_indicators(result):
            error_msg = ResultNormalizer._extract_error_message(result)
            return ResultNormalizer._create_error_response(error_msg, module_name)

        # Assume success for dict results without error indicators
        return {
            "status": "success",
            "data": result,
            "error": None,
            "metadata": ResultNormalizer._create_metadata(module_name),
        }

    @staticmethod
    def _normalize_list_result(result: List, module_name: str) -> Dict:
        """Normalize list results"""
        return {
            "status": "success",
            "data": result,
            "error": None,
            "metadata": ResultNormalizer._create_metadata(module_name),
        }

    @staticmethod
    def _normalize_string_result(result: str, module_name: str) -> Dict:
        """Normalize string results"""
        # Check if it's an error message
        if ResultNormalizer._looks_like_error(result):
            return ResultNormalizer._create_error_response(result, module_name)

        # Assume success
        return {
            "status": "success",
            "data": result,
            "error": None,
            "metadata": ResultNormalizer._create_metadata(module_name),
        }

    @staticmethod
    def _normalize_other_result(result: Any, module_name: str) -> Dict:
        """Normalize other result types"""
        try:
            # Try to serialize to JSON
            json.dumps(result, default=str)
            return {
                "status": "success",
                "data": result,
                "error": None,
                "metadata": ResultNormalizer._create_metadata(module_name),
            }
        except Exception:
            # If serialization fails, convert to string
            return {
                "status": "success",
                "data": str(result),
                "error": None,
                "metadata": ResultNormalizer._create_metadata(module_name),
            }

    @staticmethod
    def _has_error_indicators(result: Dict) -> bool:
        """Check if dict result has error indicators"""
        error_indicators = [
            "error",
            "err",
            "exception",
            "failure",
            "failed",
            "status",  # Check status field
        ]

        # Check for error keys
        for key in error_indicators:
            if key in result and key != "status":
                return True

        # Check status field
        status = result.get("status")
        if status and str(status).lower() in ["error", "fail", "failed", "false"]:
            return True

        return False

    @staticmethod
    def _extract_error_message(result: Dict) -> str:
        """Extract error message from result dict"""
        # Try common error fields
        error_fields = ["error", "err", "message", "msg", "exception"]

        for field in error_fields:
            if field in result and result[field]:
                return str(result[field])

        # Check status field
        status = result.get("status")
        if status and str(status).lower() in ["error", "fail", "failed"]:
            return f"Status: {status}"

        return "Unknown error"

    @staticmethod
    def _looks_like_error(text: str) -> bool:
        """Check if string looks like an error message"""
        error_keywords = [
            "error",
            "err",
            "exception",
            "failure",
            "failed",
            "not found",
            "unauthorized",
            "forbidden",
            "timeout",
        ]

        text_lower = text.lower()
        return any(keyword in text_lower for keyword in error_keywords)

    @staticmethod
    def _create_error_response(error_msg: str, module_name: str) -> Dict:
        """Create standardized error response"""
        return {
            "status": "error",
            "data": None,
            "error": error_msg,
            "metadata": ResultNormalizer._create_metadata(module_name),
        }

    @staticmethod
    def _create_metadata(module_name: str) -> Dict:
        """Create metadata for normalized result"""
        return {
            "module": module_name,
            "timestamp": datetime.now().isoformat(),
            "normalized": True,
        }

    @staticmethod
    def validate_normalized_result(result: Dict) -> bool:
        """Validate that a result is properly normalized"""
        if not isinstance(result, dict):
            return False

        # Check required fields
        required_fields = ["status", "data", "error", "metadata"]
        for field in required_fields:
            if field not in result:
                return False

        # Check status
        status = result.get("status")
        if status not in ["success", "error"]:
            return False

        # Check error field for error status
        if status == "error" and not result.get("error"):
            return False

        # Check metadata
        metadata = result.get("metadata", {})
        if not isinstance(metadata, dict):
            return False

        required_meta = ["module", "timestamp", "normalized"]
        for field in required_meta:
            if field not in metadata:
                return False

        return True


# Convenience functions
def normalize_result(result: Any, module_name: str = "") -> Dict[str, Any]:
    """Convenience function to normalize a result"""
    return ResultNormalizer.normalize(result, module_name)


def is_normalized(result: Dict) -> bool:
    """Check if result is already normalized"""
    return ResultNormalizer._is_normalized(result)


def validate_result(result: Dict) -> bool:
    """Validate normalized result format"""
    return ResultNormalizer.validate_normalized_result(result)
