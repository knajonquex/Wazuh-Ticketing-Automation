import json
from pathlib import Path


class IncidentCache:
    """
    Disk-based cache for AI analysis.

    Each cached analysis is stored as:

        cache/<sha256>.json

    where <sha256> is the incident fingerprint.
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

    def exists(self, incident_hash): #Returns True if the cache file exists.

        return self._cache_file(incident_hash).exists()

    # ==========================================================
    # Load Cache
    # ==========================================================

    def load(self, incident_hash):
        """
        Load cached AI analysis.

        Returns:
            dict | None
        """

        cache_file = self._cache_file(incident_hash)

        if not cache_file.exists():
            return None

        try:

            with cache_file.open(
                "r",
                encoding="utf-8"
            ) as f:

                return json.load(f)

        except Exception:

            # Corrupted cache

            cache_file.unlink(missing_ok=True)

            return None

    # ==========================================================
    # Save Cache
    # ==========================================================

    def save(self, incident_hash, analysis):
        """
        Save AI analysis to disk using an atomic write.
        """

        cache_file = self._cache_file(incident_hash)

        tmp_file = cache_file.with_suffix(".tmp")

        with tmp_file.open(
            "w",
            encoding="utf-8"
        ) as f:

            json.dump(
                analysis,
                f,
                indent=4,
                ensure_ascii=False
            )

    # Atomically replace the old cache file
        tmp_file.replace(cache_file)

    # ==========================================================
    # Delete Cache
    # ==========================================================

    def delete(self, incident_hash): #Delete a cache entry.
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
