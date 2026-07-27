import json
from datetime import datetime, timezone
from pathlib import Path

from logger import get_logger

logger = get_logger("cache")

CACHE_VERSION = 1

class IncidentCache:
    """
    Disk-based cache for AI analysis.

    Each cached analysis is stored as:

        cache/<sha256>.json

    where <sha256> is the incident fingerprint.

    Entries are self-describing: they're wrapped with a cache_version,
    the model that produced them, and a created_at timestamp, so a
    stale entry (wrong version, or produced by a model you've since
    switched away from) can be detected and ignored automatically
    instead of silently served forever.
    """

    CACHE_DIR = Path("cache")

    def __init__(self):
        self.CACHE_DIR.mkdir(exist_ok=True)

    # ==========================================================
    # Internal Helpers
    # ==========================================================

    def _cache_file(self, incident_hash):
        return self.CACHE_DIR / f"{incident_hash}.json"

    # ==========================================================
    # Cache Exists
    # ==========================================================

    def exists(self, incident_hash):
        """
        Returns True if the cache file exists.

        Note: this only checks presence on disk, not whether the
        entry is still valid for the current model/version -- that
        check happens in load(). A file can exist() but still load()
        as None if it's stale.
        """

        return self._cache_file(incident_hash).exists()

    # ==========================================================
    # Load Cache
    # ==========================================================

    def load(self, incident_hash, model=None):
        """
        Load cached AI analysis.

        Args:
            incident_hash (str): the fingerprint to look up.
            model (str, optional): the model currently configured
                (OLLAMA_MODEL). If given, entries cached under a
                different model are treated as a miss.

        Returns:
            dict | None -- the analysis object itself (unwrapped),
            or None if there's no usable cached entry.
        """

        cache_file = self._cache_file(incident_hash)

        if not cache_file.exists():
            return None

        try:

            with cache_file.open("r", encoding="utf-8") as f:
                payload = json.load(f)

            # Backward compatibility: cache entries written before this
            # wrapper existed are just the bare analysis dict. Serve
            # them as-is rather than treating them as invalid.
            if not isinstance(payload, dict) or "analysis" not in payload:
                return payload

            if payload.get("cache_version") != CACHE_VERSION:
                logger.info(
                    "%s... cached under a different cache_version, treating as a miss.",
                    incident_hash[:12]
                )
                return None

            if model is not None and payload.get("model") != model:
                logger.info(
                    "%s... was cached with model \"%s\", current model is \"%s\" -- treating as a miss.",
                    incident_hash[:12], payload.get("model"), model
                )
                return None

            return payload.get("analysis")

        except Exception:

            # Corrupted cache
            logger.warning("Corrupted cache file for %s, deleting it.", incident_hash[:12])
            cache_file.unlink(missing_ok=True)

            return None

    # ==========================================================
    # Save Cache
    # ==========================================================

    def save(self, incident_hash, analysis, model=None):
        """
        Save AI analysis to disk using an atomic write, wrapped with
        cache_version/model/created_at metadata.
        """

        cache_file = self._cache_file(incident_hash)

        tmp_file = cache_file.with_suffix(".tmp")

        payload = {
            "cache_version": CACHE_VERSION,
            "model": model,
            "created_at": datetime.now(timezone.utc).strftime(
                "%Y-%m-%dT%H:%M:%SZ"
            ),
            "analysis": analysis,
        }

        with tmp_file.open(
            "w",
            encoding="utf-8"
        ) as f:

            json.dump(
                payload,
                f,
                indent=4,
                ensure_ascii=False
            )

        # Atomically replace the old cache file
        tmp_file.replace(cache_file)

    # ==========================================================
    # Delete Cache
    # ==========================================================

    def delete(self, incident_hash):
        """
        Delete a cache entry.
        """

        cache_file = self._cache_file(incident_hash)

        if cache_file.exists():
            cache_file.unlink()

    # ==========================================================
    # Clear Cache
    # ==========================================================

    def clear(self):
        """
        Delete every cached incident.
        """

        for file in self.CACHE_DIR.glob("*.json"):
            file.unlink()

    # ==========================================================
    # Cache Size
    # ==========================================================

    def count(self):
        """
        Number of cached incidents.
        """

        return len(list(self.CACHE_DIR.glob("*.json")))

    # ==========================================================
    # List Cache Files
    # ==========================================================

    def list(self):
        """
        Return all cached hashes.
        """

        return [
            file.stem
            for file in self.CACHE_DIR.glob("*.json")
        ]
