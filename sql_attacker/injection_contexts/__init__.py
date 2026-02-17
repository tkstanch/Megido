"""
Multi-Context Injection Attack Framework

This package provides a generalized framework for detecting and exploiting
injection vulnerabilities across various interpreted query contexts.
"""

from .base import InjectionContext, InjectionResult, AttackVector, InjectionContextType

__all__ = [
    'InjectionContext',
    'InjectionResult',
    'AttackVector',
    'InjectionContextType',
]
