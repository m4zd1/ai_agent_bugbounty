"""
Bug Bounty AI Agent - Automated Cybersecurity Testing
"""

__version__ = "1.0.0"
__author__ = "BugBountyAgent"
__description__ = "AI-powered bug bounty and cybersecurity testing agent"

from .core import CyberAgent, Severity, Finding

__all__ = [
    "CyberAgent",
    "Severity",
    "Finding"
]