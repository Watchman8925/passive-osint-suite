"""Capability framework package.

Provides:
- CapabilityDefinition: metadata contract
- CapabilityResult: standardized execute() return
- REGISTRY: global capability catalog

Later phases will add dynamic loading and validation.
"""
from .definitions import CapabilityDefinition, CapabilityResult  # noqa
from .registry import REGISTRY  # noqa
