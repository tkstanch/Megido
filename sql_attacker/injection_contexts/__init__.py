"""
Multi-Context Injection Attack Framework

This package provides a generalized framework for detecting and exploiting
injection vulnerabilities across various interpreted query contexts.
"""

from .base import (
    InjectionAttackModule,
    InjectionContext,
    InjectionResult,
    AttackVector,
    InjectionContextType
)

__all__ = [
    'InjectionAttackModule',
    'InjectionContext',
    'InjectionResult',
    'AttackVector',
    'InjectionContextType',
]
