#!/usr/bin/env python3
"""
Local LLM Engine
Provides local AI/LLM capabilities for the OSINT suite.
"""

import logging
from typing import Any, Dict

logger = logging.getLogger(__name__)


class LocalLLMEngine:
    """
    Local LLM Engine for AI-powered analysis and processing.
    """

    def __init__(self):
        self.active_backend = None
        self.openai_client = None
        self.logger = logging.getLogger(__name__)

    def _setup_openai(self):
        """Setup OpenAI backend"""
        try:
            # Import dynamically to avoid static import resolution errors in environments
            # where the openai package is optional or not installed.
            import importlib

            openai_mod = importlib.import_module("openai")
            # Support the new OpenAI client and fall back to the legacy openai module.
            if hasattr(openai_mod, "OpenAI"):
                self.openai_client = openai_mod.OpenAI()
            else:
                # legacy openai module exposes its functions/clients at module level
                self.openai_client = openai_mod
            self.active_backend = "openai"
            self.logger.info("OpenAI backend initialized")
        except Exception as e:
            self.logger.error(f"Failed to setup OpenAI: {e}")
            raise

    async def _query_llm(self, prompt: str) -> Any:
        """Query the active LLM backend"""
        if self.active_backend == 'openai' and self.openai_client:
            try:
                response = self.openai_client.chat.completions.create(
                    model="gpt-3.5-turbo",
                    messages=[{"role": "user", "content": prompt}],
                    max_tokens=1000
                )
                return response.choices[0].message.content
            except Exception as e:
                self.logger.error(f"OpenAI query failed: {e}")
                raise
        else:
            raise ValueError("No active LLM backend configured")

    async def analyze_text(self, text: str) -> Dict[str, Any]:
        """Analyze text for intelligence insights"""
        prompt = f"Analyze the following text for intelligence value: {text[:1000]}"
        try:
            analysis = await self._query_llm(prompt)
            return {
                "analysis": analysis,
                "confidence": 0.8,
                "entities": [],
                "sentiment": "neutral"
            }
        except Exception as e:
            return {
                "error": str(e),
                "analysis": "Analysis failed",
                "confidence": 0.0
            }

    async def generate_report_summary(self, data: Dict[str, Any]) -> str:
        """Generate a summary report from investigation data"""
        prompt = f"Generate a concise intelligence summary from this data: {str(data)[:2000]}"
        try:
            return await self._query_llm(prompt)
        except Exception as e:
            return f"Report generation failed: {e}"
