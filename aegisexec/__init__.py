"""
AegisExec: Defensive Linux AI-agent action broker.
Author: Built by onkar-cybersec

AegisExec intercepts structured action requests from untrusted AI clients,
evaluating them against explicit local policies and executing approved operations
under Linux Bubblewrap isolation with strict guardrails.
"""

__version__ = "0.1.0"
__author__ = "Built by onkar-cybersec"

from aegisexec.broker import AegisBroker
from aegisexec.policy import PolicyEngine
from aegisexec.paths import PathValidator
from aegisexec.manifest import ManifestManager

__all__ = [
    "AegisBroker",
    "PolicyEngine",
    "PathValidator",
    "ManifestManager",
    "__version__",
    "__author__",
]
