"""
Evidence Storage Abstraction
==============================
Provides an abstract :class:`EvidenceStorage` interface and a concrete
:class:`LocalFileStorage` implementation so that evidence persistence can
target both local filesystems and future hosted back-ends.

Usage::

    from sql_attacker.engine.storage import LocalFileStorage
    from sql_attacker.engine.evidence_pack import EvidencePack

    store = LocalFileStorage("/var/megido/evidence")
    store.save(pack)

    all_packs = store.list_all()
    pack = store.load("finding_abc123")
"""

from __future__ import annotations

import json
import os
from abc import ABC, abstractmethod
from typing import List, Optional

from .evidence_pack import EvidencePack


# ---------------------------------------------------------------------------
# Abstract interface
# ---------------------------------------------------------------------------


class EvidenceStorage(ABC):
    """Abstract base class for evidence persistence back-ends."""

    @abstractmethod
    def save(self, pack: EvidencePack) -> str:
        """Persist *pack* and return a back-end-specific reference (e.g. a file
        path or remote URL)."""

    @abstractmethod
    def load(self, finding_id: str) -> EvidencePack:
        """Load the :class:`EvidencePack` for *finding_id*.

        Raises
        ------
        KeyError: If no pack for *finding_id* exists in this store.
        """

    @abstractmethod
    def list_all(self) -> List[EvidencePack]:
        """Return every stored :class:`EvidencePack`, ordered by capture time."""

    @abstractmethod
    def delete(self, finding_id: str) -> bool:
        """Delete the pack for *finding_id*.

        Returns
        -------
        bool: ``True`` if a pack was deleted, ``False`` if none was found.
        """


# ---------------------------------------------------------------------------
# Local filesystem implementation
# ---------------------------------------------------------------------------


class LocalFileStorage(EvidenceStorage):
    """Stores each :class:`EvidencePack` as a JSON file on the local filesystem.

    Files are named ``finding_<finding_id>.json`` and stored in *evidence_dir*.

    Parameters
    ----------
    evidence_dir:
        Directory where evidence files will be written.  Created automatically
        if it does not exist.
    """

    _FILE_PREFIX = "finding_"
    _FILE_SUFFIX = ".json"

    def __init__(self, evidence_dir: str) -> None:
        self._dir = os.path.abspath(evidence_dir)
        os.makedirs(self._dir, exist_ok=True)

    @property
    def evidence_dir(self) -> str:
        """Absolute path to the evidence directory."""
        return self._dir

    def _path_for(self, finding_id: str) -> str:
        safe_id = finding_id.replace("/", "_").replace("\\", "_")
        return os.path.join(
            self._dir, f"{self._FILE_PREFIX}{safe_id}{self._FILE_SUFFIX}"
        )

    def save(self, pack: EvidencePack) -> str:
        """Write *pack* to disk and return its file path."""
        path = self._path_for(pack.finding_id)
        pack.save(path)
        return path

    def load(self, finding_id: str) -> EvidencePack:
        """Load and return the :class:`EvidencePack` for *finding_id*.

        Raises
        ------
        KeyError: If no file exists for *finding_id*.
        """
        path = self._path_for(finding_id)
        if not os.path.exists(path):
            raise KeyError(
                f"No evidence pack found for finding_id='{finding_id}' "
                f"in {self._dir!r}"
            )
        return EvidencePack.load(path)

    def list_all(self) -> List[EvidencePack]:
        """Return all stored packs, sorted by *captured_at* ascending."""
        packs: List[EvidencePack] = []
        for name in os.listdir(self._dir):
            if name.startswith(self._FILE_PREFIX) and name.endswith(self._FILE_SUFFIX):
                try:
                    packs.append(EvidencePack.load(os.path.join(self._dir, name)))
                except (ValueError, json.JSONDecodeError, KeyError):
                    pass  # Skip corrupted files gracefully
        packs.sort(key=lambda p: p.captured_at)
        return packs

    def delete(self, finding_id: str) -> bool:
        """Delete the pack for *finding_id* from disk.

        Returns ``True`` if the file was deleted, ``False`` if it did not exist.
        """
        path = self._path_for(finding_id)
        if os.path.exists(path):
            os.remove(path)
            return True
        return False
