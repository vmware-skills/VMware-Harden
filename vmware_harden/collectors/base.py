"""Base collector class. Concrete collectors implement collect()."""
from vmware_harden.store.twin import Twin


class Collector:
    """Abstract base for inventory collectors."""

    def __init__(self, twin: Twin):
        self.twin = twin

    def collect(self, snapshot_id: str, target: str) -> int:
        """Fetch and write inventory for the given snapshot. Returns count written."""
        raise NotImplementedError


class CollectorError(Exception):
    """Raised when a collector encounters malformed inventory data."""
