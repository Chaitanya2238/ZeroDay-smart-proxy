# phase2/__init__.py - Phase 2 Package
"""
Phase 2: Nervous System - AI-Driven Threat Detection
Monitors proxy.log for security threats using Tier 1 (Rules) + Tier 2 (AI/LLM)
"""

__version__ = "2.0.0"
__description__ = "AI-powered security analysis for reverse proxy logs"

from .rules import SecurityRules
from .ai_engine import AISecurityAnalyzer
from .analyzer import SecurityAnalyzerPipeline, LogTailer, StatisticsTracker

__all__ = [
    'SecurityRules',
    'AISecurityAnalyzer',
    'SecurityAnalyzerPipeline',
    'LogTailer',
    'StatisticsTracker'
]
