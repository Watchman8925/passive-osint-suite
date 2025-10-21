#!/usr/bin/env python3
"""Compatibility wrapper exposing the enhanced local LLM engine."""

from core.local_llm_engine import (
    LocalLLMEngine,
    create_local_llm_engine,
)

__all__ = ["LocalLLMEngine", "create_local_llm_engine"]
