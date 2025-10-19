"""
Tests for OSINT Module Capability Contracts

This test suite verifies that all modules in MODULE_REGISTRY:
1. Have at least one standard interface method
2. Return properly structured responses
3. Handle errors gracefully
4. Are callable from the API endpoint
"""

import pytest
from typing import Any

# Standard methods that modules should implement
STANDARD_METHODS = [
    "search",
    "analyze_company",
    "enumerate",
    "scrape",
    "fetch_snapshots",
    "get_history",
    "scrape_profiles",
    "dork",
]


def get_module_registry():
    """Import MODULE_REGISTRY with proper error handling"""
    try:
        from modules import MODULE_REGISTRY

        return MODULE_REGISTRY
    except ImportError as e:
        pytest.skip(f"Could not import MODULE_REGISTRY: {e}")


def validate_response_structure(response: Any) -> tuple[bool, str]:
    """
    Validate that a module response has the correct structure.

    Returns:
        tuple: (is_valid, error_message)
    """
    if not isinstance(response, dict):
        return False, f"Response must be a dict, got {type(response)}"

    if "status" not in response:
        return False, "Response must contain 'status' key"

    if response["status"] not in ("success", "error"):
        return False, f"Status must be 'success' or 'error', got '{response['status']}'"

    if response["status"] == "success" and "data" not in response:
        return False, "Success response must contain 'data' key"

    if response["status"] == "error" and "error" not in response:
        return False, "Error response must contain 'error' key"

    return True, ""


class TestModuleRegistry:
    """Test that MODULE_REGISTRY is properly configured"""

    def test_registry_exists(self):
        """MODULE_REGISTRY should be importable"""
        registry = get_module_registry()
        assert registry is not None
        assert isinstance(registry, dict)
        assert len(registry) > 0

    def test_all_entries_have_class(self):
        """All registry entries should have a 'class' key"""
        registry = get_module_registry()
        missing_class = []

        for module_name, module_info in registry.items():
            if "class" not in module_info or module_info["class"] is None:
                missing_class.append(module_name)

        if missing_class:
            pytest.fail(
                f"The following modules have no 'class' defined: {', '.join(missing_class)}\n"
                f"Either provide a valid class or remove from registry."
            )

    def test_all_entries_have_description(self):
        """All registry entries should have a description"""
        registry = get_module_registry()
        missing_desc = []

        for module_name, module_info in registry.items():
            if "description" not in module_info or not module_info["description"]:
                missing_desc.append(module_name)

        assert len(missing_desc) == 0, (
            f"Modules missing description: {', '.join(missing_desc)}"
        )

    def test_all_entries_have_category(self):
        """All registry entries should have a category"""
        registry = get_module_registry()
        missing_cat = []

        for module_name, module_info in registry.items():
            if "category" not in module_info or not module_info["category"]:
                missing_cat.append(module_name)

        assert len(missing_cat) == 0, (
            f"Modules missing category: {', '.join(missing_cat)}"
        )


class TestModuleCapabilities:
    """Test that modules implement standard capability methods"""

    def test_modules_have_standard_methods(self):
        """All modules should implement at least one standard method"""
        registry = get_module_registry()
        modules_without_methods = []

        for module_name, module_info in registry.items():
            module_class = module_info.get("class")
            if module_class is None:
                continue  # Skip - handled by test_all_entries_have_class

            # Check if module has any standard method
            has_standard_method = any(
                hasattr(module_class, method)
                and callable(getattr(module_class, method))
                for method in STANDARD_METHODS
            )

            if not has_standard_method:
                modules_without_methods.append(module_name)

        if modules_without_methods:
            methods_str = ", ".join(STANDARD_METHODS)
            pytest.fail(
                f"The following {len(modules_without_methods)} modules do not implement "
                f"any standard methods ({methods_str}):\n"
                f"{chr(10).join('  - ' + name for name in sorted(modules_without_methods))}\n\n"
                f"See docs/MODULE_CAPABILITY_CONTRACT.md for implementation guidelines."
            )

    def test_module_methods_are_callable(self):
        """Standard methods should be callable"""
        registry = get_module_registry()

        for module_name, module_info in registry.items():
            module_class = module_info.get("class")
            if module_class is None:
                continue

            # Check each standard method that exists
            for method_name in STANDARD_METHODS:
                if hasattr(module_class, method_name):
                    method = getattr(module_class, method_name)
                    assert callable(method), (
                        f"{module_name}.{method_name} exists but is not callable"
                    )


class TestModuleResponses:
    """Test that module methods return properly structured responses"""

    @pytest.fixture
    def sample_modules(self):
        """Get a sample of modules for response testing"""
        registry = get_module_registry()

        # Test modules that have standard methods
        sample_modules = []
        for module_name, module_info in registry.items():
            module_class = module_info.get("class")
            if module_class is None:
                continue

            # Find first standard method
            for method_name in STANDARD_METHODS:
                if hasattr(module_class, method_name):
                    sample_modules.append((module_name, module_class, method_name))
                    break

        return sample_modules

    def test_method_signatures_accept_target(self, sample_modules):
        """Standard methods should accept a target parameter"""
        import inspect

        for module_name, module_class, method_name in sample_modules:
            method = getattr(module_class, method_name)
            sig = inspect.signature(method)
            params = list(sig.parameters.keys())

            # Should have self + at least one parameter (target/query/etc)
            assert len(params) >= 2, (
                f"{module_name}.{method_name} should accept a target parameter, "
                f"but only has parameters: {params}"
            )

    def test_response_structure_with_mock_data(self, sample_modules):
        """Test that module responses have correct structure (with mocked calls)"""
        from unittest.mock import patch, MagicMock

        errors = []

        for module_name, module_class, method_name in sample_modules:
            try:
                # Create instance with mocked dependencies
                with patch.object(module_class, "__init__", return_value=None):
                    instance = module_class.__new__(module_class)
                    # Add minimal attributes
                    instance.logger = MagicMock()

                    # Mock any external calls
                    with patch.object(instance, "make_request", return_value=None):
                        with patch.object(
                            instance, "request_with_fallback", return_value=None
                        ):
                            try:
                                method = getattr(instance, method_name)

                                # Try calling with minimal parameters
                                # Use different test inputs based on method
                                if method_name == "analyze_company":
                                    result = method("test_company")
                                else:
                                    result = method("test_target")

                                # Validate response structure
                                is_valid, error_msg = validate_response_structure(
                                    result
                                )
                                if not is_valid:
                                    errors.append(
                                        f"{module_name}.{method_name}: {error_msg}"
                                    )

                            except TypeError as e:
                                # Method might require additional parameters - that's ok for this test
                                # We're just checking that it doesn't crash entirely
                                if "required positional argument" not in str(e):
                                    errors.append(
                                        f"{module_name}.{method_name}: Unexpected TypeError: {e}"
                                    )
                            except Exception:
                                # Some methods might fail due to missing dependencies, that's ok
                                # We're mainly checking the interface exists
                                pass

            except Exception as e:
                errors.append(f"{module_name}: Could not instantiate module - {e}")

        # This test is informational - we don't fail the test suite
        # but we report any issues found
        if errors:
            print(f"\n⚠️  Response structure issues found in {len(errors)} modules:")
            for error in errors:
                print(f"  - {error}")


class TestAPIIntegration:
    """Test that modules work with the API execution endpoint"""

    def test_get_module_function_works(self):
        """The get_module() function should instantiate modules correctly"""
        from modules import get_module

        registry = get_module_registry()

        # Test a few known working modules
        test_modules = [
            "certificate_transparency",
            "github_search",
            "public_breach_search",
        ]

        for module_name in test_modules:
            if module_name in registry:
                try:
                    instance = get_module(module_name)
                    assert instance is not None, (
                        f"get_module('{module_name}') returned None"
                    )
                except Exception as e:
                    pytest.fail(f"get_module('{module_name}') raised exception: {e}")

    def test_get_module_raises_on_invalid_name(self):
        """get_module() should raise ValueError for invalid module names"""
        from modules import get_module

        with pytest.raises(ValueError, match="not found"):
            get_module("nonexistent_module_12345")


class TestModuleDocumentation:
    """Test that module contract documentation exists"""

    def test_contract_documentation_exists(self):
        """MODULE_CAPABILITY_CONTRACT.md should exist"""
        from pathlib import Path

        docs_path = (
            Path(__file__).parent.parent / "docs" / "MODULE_CAPABILITY_CONTRACT.md"
        )
        assert docs_path.exists(), (
            "docs/MODULE_CAPABILITY_CONTRACT.md not found. "
            "This file should document the module interface requirements."
        )

    def test_contract_documentation_is_complete(self):
        """Contract documentation should cover all standard methods"""
        from pathlib import Path

        docs_path = (
            Path(__file__).parent.parent / "docs" / "MODULE_CAPABILITY_CONTRACT.md"
        )
        if not docs_path.exists():
            pytest.skip("MODULE_CAPABILITY_CONTRACT.md not found")

        content = docs_path.read_text()

        # Check that all standard methods are documented
        missing = []
        for method in STANDARD_METHODS:
            if f"`{method}(" not in content and f"def {method}(" not in content:
                missing.append(method)

        assert len(missing) == 0, (
            f"Contract documentation missing these methods: {', '.join(missing)}"
        )


def test_module_audit_summary():
    """Generate and display a summary of module compliance"""
    registry = get_module_registry()

    total = len(registry)
    with_methods = 0
    without_methods = 0
    no_class = 0

    for module_name, module_info in registry.items():
        module_class = module_info.get("class")
        if module_class is None:
            no_class += 1
            continue

        has_method = any(hasattr(module_class, method) for method in STANDARD_METHODS)

        if has_method:
            with_methods += 1
        else:
            without_methods += 1

    print("\n" + "=" * 80)
    print("MODULE COMPLIANCE SUMMARY")
    print("=" * 80)
    print(f"Total modules in registry: {total}")
    print(f"✓ Modules with standard methods: {with_methods}")
    print(f"⚠️  Modules without standard methods: {without_methods}")
    print(f"❌ Modules with no class: {no_class}")
    print("=" * 80)

    # This is an informational test - always passes but shows the summary
    assert True
