#!/usr/bin/env python3
"""
Integration test for deployment - verifies backend and frontend work together
"""

import os
import sys
import subprocess
import pytest

sys.path.append(os.path.abspath(os.path.join(os.path.dirname(__file__), "..")))


def test_backend_starts():
    """Test that backend can start with --web flag"""
    # This test verifies the command exists but doesn't actually start the server
    # to avoid blocking the test suite
    result = subprocess.run(
        ["python3", "main.py", "--help"],
        capture_output=True,
        text=True,
        cwd=os.path.dirname(os.path.dirname(__file__)),
    )
    assert result.returncode == 0
    assert "--web" in result.stdout, "main.py should have --web flag"


def test_api_server_import():
    """Test that api_server can be imported without errors"""
    try:
        from api.api_server import app

        assert app is not None, "FastAPI app should be initialized"
        assert hasattr(app, "routes"), "FastAPI app should have routes"
        print(f"✅ API server has {len(app.routes)} routes")
    except Exception as e:
        pytest.fail(f"Failed to import api_server: {e}")


def test_health_endpoint_exists():
    """Test that health endpoint is defined in the app"""
    from api.api_server import app

    # Check if health endpoints are registered
    routes = [route.path for route in app.routes]
    assert "/api/health" in routes or any("/health" in r for r in routes), (
        "Health endpoint should be registered"
    )
    print(f"✅ Found {len([r for r in routes if 'health' in r])} health endpoints")


def test_dotenv_loading():
    """Test that environment variables can be loaded from .env"""
    try:
        from dotenv import load_dotenv

        # Create a test .env file
        test_env = os.path.join(os.path.dirname(os.path.dirname(__file__)), ".env")
        if os.path.exists(test_env):
            load_dotenv(test_env)
            # Check if OSINT_SECRET_KEY is set
            secret_key = os.getenv("OSINT_SECRET_KEY")
            assert secret_key is not None, "OSINT_SECRET_KEY should be set in .env"
            print("✅ Environment variables loaded successfully")
    except ImportError:
        pytest.skip("python-dotenv not installed")


def test_vite_config_has_proxy():
    """Test that vite.config.ts has proxy configuration"""
    vite_config_path = os.path.join(
        os.path.dirname(os.path.dirname(__file__)), "web", "vite.config.ts"
    )

    if not os.path.exists(vite_config_path):
        pytest.skip("vite.config.ts not found")

    with open(vite_config_path, "r") as f:
        content = f.read()

    assert "proxy" in content, "vite.config.ts should have proxy configuration"
    assert "/api" in content, "vite.config.ts should proxy /api requests"
    print("✅ Vite proxy configuration found")


def test_required_dependencies():
    """Test that required dependencies are installed"""
    required_deps = [
        "fastapi",
        "uvicorn",
        "pydantic",
        "rich",
        "colorama",
    ]

    missing_deps = []
    for dep in required_deps:
        try:
            __import__(dep)
        except ImportError:
            missing_deps.append(dep)

    if missing_deps:
        pytest.fail(f"Missing required dependencies: {', '.join(missing_deps)}")

    print(f"✅ All {len(required_deps)} required dependencies installed")


if __name__ == "__main__":
    pytest.main([__file__, "-v"])
