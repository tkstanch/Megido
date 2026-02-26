"""
Base OSINT Engine

Defines the abstract base class and result structure for all OSINT engines.
"""
import logging
import time
from abc import ABC, abstractmethod
from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional

logger = logging.getLogger(__name__)


@dataclass
class EngineResult:
    """Standardised result container returned by every OSINT engine."""
    engine_name: str
    success: bool
    data: Dict[str, Any] = field(default_factory=dict)
    errors: List[str] = field(default_factory=list)
    duration_seconds: float = 0.0
    items_found: int = 0

    def to_dict(self) -> Dict[str, Any]:
        return {
            'engine': self.engine_name,
            'success': self.success,
            'data': self.data,
            'errors': self.errors,
            'duration_seconds': self.duration_seconds,
            'items_found': self.items_found,
        }


class BaseOSINTEngine(ABC):
    """
    Abstract base class for all OSINT engines.

    Subclasses must implement ``collect(target)``.  The base class handles
    timing, error isolation and result wrapping so each engine can focus on
    its data-collection logic.
    """

    # Override in subclasses to declare a human-readable name.
    name: str = 'BaseEngine'
    # Override to describe what the engine collects.
    description: str = ''
    # Seconds to wait between paginated / rate-limited requests.
    rate_limit_delay: float = 1.0
    # Whether the engine performs active probing of the target host.
    is_active: bool = False

    def __init__(self, config: Optional[Dict[str, Any]] = None):
        self.config = config or {}
        self.logger = logging.getLogger(
            f'discover.osint_engines.{self.__class__.__name__}'
        )

    @abstractmethod
    def collect(self, target: str) -> Dict[str, Any]:
        """
        Perform data collection for *target*.

        Args:
            target: Domain, IP address, or URL to investigate.

        Returns:
            A dictionary containing the collected data.  The exact schema is
            engine-specific but should be JSON-serialisable.
        """

    def run(self, target: str) -> EngineResult:
        """
        Execute the engine, wrapping ``collect`` with timing and error handling.

        Always returns an :class:`EngineResult` — never raises.
        """
        start = time.monotonic()
        try:
            self.logger.info("Starting %s for target: %s", self.name, target)
            data = self.collect(target)
            duration = time.monotonic() - start
            items = self._count_items(data)
            self.logger.info(
                "%s finished in %.2fs, found %d item(s)", self.name, duration, items
            )
            return EngineResult(
                engine_name=self.name,
                success=True,
                data=data,
                duration_seconds=round(duration, 3),
                items_found=items,
            )
        except Exception as exc:  # pylint: disable=broad-except
            duration = time.monotonic() - start
            self.logger.exception("%s failed after %.2fs: %s", self.name, duration, exc)
            return EngineResult(
                engine_name=self.name,
                success=False,
                errors=[str(exc)],
                duration_seconds=round(duration, 3),
            )

    def _count_items(self, data: Dict[str, Any]) -> int:
        """
        Heuristic: count the total number of items in list-valued keys.
        Engines can override this for more precise counting.
        """
        total = 0
        for value in data.values():
            if isinstance(value, list):
                total += len(value)
        return total

    def _get_config(self, key: str, default: Any = None) -> Any:
        return self.config.get(key, default)
