"""Honeypot collector.

Normalizuje, obohacuje a ukládá události o kybernetických útocích
zachycené senzory honeypotu (Cowrie, HTTP honeypot, ...).
"""

from honeypot_collector.models import AttackEvent

__all__ = ["AttackEvent", "__version__"]
__version__ = "0.1.0"
