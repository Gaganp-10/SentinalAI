import time
import logging
import asyncio
from typing import List, Dict, Tuple, Set, Optional, Any
import httpx

from backend.utils.config import settings

logger = logging.getLogger(__name__)

# Valid ecosystem strings per OSV.dev specification
ALLOWED_ECOSYSTEMS = {"PyPI", "npm", "Maven"}

# In-memory cache (does not survive process restarts)
# Key: (ecosystem, name, version) -> List[str] (advisory IDs)
_QUERY_CACHE: Dict[Tuple[str, str, str], Tuple[float, List[str]]] = {}
# Key: vuln_id -> dict (advisory payload)
_ADVISORY_CACHE: Dict[str, Tuple[float, dict]] = {}

CACHE_TTL_SECONDS = 6 * 3600  # 6 hours
MAX_BATCH_SIZE = 500
MAX_CONCURRENCY = 8
PER_REQUEST_TIMEOUT = 10.0
MAX_ADVISORY_FETCH_CAP = 2000


class OSVClientError(Exception):
    """Raised when the OSV.dev API is unreachable, times out, or returns a fatal error."""
    pass


class OSVClient:
    def __init__(self, base_url: Optional[str] = None):
        self.base_url = (base_url or getattr(settings, "OSV_API_BASE_URL", "https://api.osv.dev")).rstrip("/")

    def validate_ecosystem(self, ecosystem: str) -> None:
        """Enforces strict ecosystem naming: PyPI, npm, Maven."""
        if ecosystem not in ALLOWED_ECOSYSTEMS:
            raise ValueError(f"Invalid ecosystem '{ecosystem}'. Must be one of: {sorted(list(ALLOWED_ECOSYSTEMS))}")

    def query_batch(
        self,
        queries: List[Dict[str, str]]
    ) -> Tuple[Dict[Tuple[str, str, str], List[str]], List[str]]:
        """
        Queries OSV.dev querybatch endpoint.
        Returns:
            mapping: (ecosystem, name, version) -> list of advisory IDs
            warnings: list of warning strings
        """
        for q in queries:
            self.validate_ecosystem(q["ecosystem"])

        results_map: Dict[Tuple[str, str, str], List[str]] = {}
        warnings: List[str] = []

        now = time.time()
        uncached_queries: List[Dict[str, str]] = []

        for q in queries:
            key = (q["ecosystem"], q["name"], q["version"])
            if key in _QUERY_CACHE:
                cached_time, cached_ids = _QUERY_CACHE[key]
                if now - cached_time < CACHE_TTL_SECONDS:
                    results_map[key] = cached_ids
                    continue
            uncached_queries.append(q)

        if not uncached_queries:
            return results_map, warnings

        # Deduplicate uncached queries
        unique_uncached: List[Dict[str, str]] = []
        seen = set()
        for q in uncached_queries:
            k = (q["ecosystem"], q["name"], q["version"])
            if k not in seen:
                seen.add(k)
                unique_uncached.append(q)

        # Batch into chunks of MAX_BATCH_SIZE
        for chunk_idx in range(0, len(unique_uncached), MAX_BATCH_SIZE):
            chunk = unique_uncached[chunk_idx : chunk_idx + MAX_BATCH_SIZE]
            batch_payload = {
                "queries": [
                    {
                        "package": {"name": q["name"], "ecosystem": q["ecosystem"]},
                        "version": q["version"]
                    }
                    for q in chunk
                ]
            }

            url = f"{self.base_url}/v1/querybatch"
            response_data = None
            last_err = None

            # Retry loop: 2 retries (3 attempts total) on network error or 429/5xx
            for attempt in range(3):
                try:
                    with httpx.Client(timeout=PER_REQUEST_TIMEOUT) as client:
                        resp = client.post(url, json=batch_payload)
                        if resp.status_code == 200:
                            response_data = resp.json()
                            break
                        elif resp.status_code in (429, 500, 502, 503, 504):
                            last_err = f"HTTP {resp.status_code}"
                            time.sleep(0.5 * (2 ** attempt))
                            continue
                        else:
                            raise OSVClientError(f"OSV batch query failed with HTTP {resp.status_code}")
                except (httpx.RequestError, httpx.TimeoutException) as ex:
                    last_err = str(ex)
                    time.sleep(0.5 * (2 ** attempt))

            if response_data is None:
                raise OSVClientError(f"OSV.dev querybatch unreachable: {last_err}")

            raw_results = response_data.get("results", [])
            # Positional mapping: result i belongs to query i
            for i, q in enumerate(chunk):
                k = (q["ecosystem"], q["name"], q["version"])
                advisory_ids: List[str] = []
                if i < len(raw_results):
                    res = raw_results[i]
                    vulns = res.get("vulns", [])
                    for v in vulns:
                        vid = v.get("id")
                        if vid and vid not in advisory_ids:
                            advisory_ids.append(vid)

                results_map[k] = advisory_ids
                _QUERY_CACHE[k] = (now, advisory_ids)

        return results_map, warnings

    async def fetch_advisories_async(
        self,
        advisory_ids: Set[str]
    ) -> Tuple[Dict[str, dict], List[str]]:
        """
        Fetches full advisory records by ID with concurrency control (MAX_CONCURRENCY=8).
        Caps at MAX_ADVISORY_FETCH_CAP (2000).
        """
        advisories: Dict[str, dict] = {}
        warnings: List[str] = []
        now = time.time()

        ids_to_fetch: List[str] = []
        for aid in advisory_ids:
            if aid in _ADVISORY_CACHE:
                cached_time, cached_record = _ADVISORY_CACHE[aid]
                if now - cached_time < CACHE_TTL_SECONDS:
                    advisories[aid] = cached_record
                    continue
            ids_to_fetch.append(aid)

        if len(ids_to_fetch) > MAX_ADVISORY_FETCH_CAP:
            warnings.append(f"Advisory record fetch cap reached ({MAX_ADVISORY_FETCH_CAP} advisories).")
            ids_to_fetch = ids_to_fetch[:MAX_ADVISORY_FETCH_CAP]

        semaphore = asyncio.Semaphore(MAX_CONCURRENCY)

        async def fetch_one(client: httpx.AsyncClient, aid: str) -> Optional[Tuple[str, dict]]:
            async with semaphore:
                url = f"{self.base_url}/v1/vulns/{aid}"
                for attempt in range(3):
                    try:
                        resp = await client.get(url)
                        if resp.status_code == 200:
                            data = resp.json()
                            return (aid, data)
                        elif resp.status_code in (429, 500, 502, 503, 504):
                            await asyncio.sleep(0.5 * (2 ** attempt))
                            continue
                        elif resp.status_code == 404:
                            return None
                        else:
                            logger.warning(f"Error fetching advisory {aid}: HTTP {resp.status_code}")
                            return None
                    except (httpx.RequestError, httpx.TimeoutException) as ex:
                        if attempt == 2:
                            logger.warning(f"Timeout/network error fetching advisory {aid}: {ex}")
                        await asyncio.sleep(0.5 * (2 ** attempt))
                return None

        if ids_to_fetch:
            limits = httpx.Limits(max_connections=MAX_CONCURRENCY, max_keepalive_connections=MAX_CONCURRENCY)
            async with httpx.AsyncClient(timeout=PER_REQUEST_TIMEOUT, limits=limits) as async_client:
                tasks = [fetch_one(async_client, aid) for aid in ids_to_fetch]
                fetch_results = await asyncio.gather(*tasks, return_exceptions=True)

                for r in fetch_results:
                    if isinstance(r, tuple) and r is not None:
                        aid, data = r
                        advisories[aid] = data
                        _ADVISORY_CACHE[aid] = (now, data)

        return advisories, warnings

    def fetch_advisories(self, advisory_ids: Set[str]) -> Tuple[Dict[str, dict], List[str]]:
        """Synchronous wrapper for fetch_advisories_async."""
        if not advisory_ids:
            return {}, []
        try:
            loop = asyncio.get_event_loop()
        except RuntimeError:
            loop = None

        if loop and loop.is_running():
            # If inside an existing running event loop
            import concurrent.futures
            with concurrent.futures.ThreadPoolExecutor(max_workers=1) as pool:
                return pool.submit(lambda: asyncio.run(self.fetch_advisories_async(advisory_ids))).result()
        else:
            return asyncio.run(self.fetch_advisories_async(advisory_ids))
