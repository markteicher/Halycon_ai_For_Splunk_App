# bin/halcyon_input.py
#
# Halcyon.ai for Splunk App — Modular Input (combat-ready)
# - Multi-endpoint collection (24 sourcetypes)
# - Per-sourcetype checkpointing
# - Safe polling cadences (hourly / multi-hour / daily)
# - Pagination handling (next/cursor/page/offset patterns)
# - Retries + backoff
#
# Requires: Splunk Python + splunklib (Splunk SDK)

from __future__ import annotations

import json
import os
import time
import math
import random
import traceback
from dataclasses import dataclass
from datetime import datetime, timezone
from typing import Any, Dict, Iterable, List, Optional, Tuple, Union

import requests
from splunklib.modularinput import Script, Scheme, Argument, Event, EventWriter, InputDefinition


APP_NAME = "Halcyon_ai_for_Splunk"
DEFAULT_BASE_URL = "https://api.halcyon.ai"
DEFAULT_INDEX = "security_halcyon"

DEFAULT_TIMEOUT_SECONDS = 60
DEFAULT_PAGE_SIZE = 200
MAX_PAGES_SAFETY_CAP = 2000

RETRY_MAX = 5
RETRY_BASE_SLEEP = 1.0
RETRY_JITTER = 0.25


# --------------------------------------------------------------------
# Sourcetypes (24) + endpoint group mapping
# NOTE: endpoint paths below are intentionally generic. If your OpenAPI
# uses different paths, update ENDPOINTS once and you’re done.
# --------------------------------------------------------------------

@dataclass(frozen=True)
class EndpointSpec:
    name: str
    sourcetype: str
    path: str
    cadence_seconds: int
    list_key_hints: Tuple[str, ...] = ("items", "data", "results", "value")
    time_field_hints: Tuple[str, ...] = (
        "time",
        "timestamp",
        "createdAt",
        "updatedAt",
        "occurredAt",
        "eventTime",
        "lastSeen",
        "firstSeen",
    )
    id_field_hints: Tuple[str, ...] = ("id", "uuid", "alertId", "eventId")


ENDPOINTS: List[EndpointSpec] = [
    # Core Security Objects
    EndpointSpec("alerts",               "halcyon:alert",             "/v2/alerts",               cadence_seconds=3600),
    EndpointSpec("alert_instances",      "halcyon:alert_instance",    "/v2/alert-instances",      cadence_seconds=3600),
    EndpointSpec("events",               "halcyon:event",             "/v2/events",               cadence_seconds=3600),
    EndpointSpec("threats",              "halcyon:threat",            "/v2/threats",              cadence_seconds=21600),
    EndpointSpec("alert_artifacts",      "halcyon:artifact",          "/v2/alerts/artifacts",     cadence_seconds=3600),

    # Assets & Devices
    EndpointSpec("assets",               "halcyon:asset",             "/v2/assets",               cadence_seconds=21600),
    EndpointSpec("devices",              "halcyon:device",            "/v2/devices",              cadence_seconds=3600),
    EndpointSpec("device_extracted_keys","halcyon:device_extracted_key","/v2/device-extracted-keys", cadence_seconds=21600),

    # Identity & Access
    EndpointSpec("current_user",         "halcyon:user",              "/v2/users/me",             cadence_seconds=86400),
    EndpointSpec("tenant_users",         "halcyon:tenant_user",       "/v2/tenant-users",         cadence_seconds=21600),
    EndpointSpec("identity_providers",   "halcyon:identity_provider", "/v2/identity-providers",   cadence_seconds=86400),

    # Tenancy & Structure
    EndpointSpec("tenants",              "halcyon:tenant",            "/v2/tenants",              cadence_seconds=86400),
    EndpointSpec("subtenants",           "halcyon:subtenant",         "/v2/subtenants",           cadence_seconds=86400),
    EndpointSpec("deployment_groups",    "halcyon:deployment_group",  "/v2/deployment-groups",    cadence_seconds=86400),

    # Policy & Control Plane
    EndpointSpec("policies",             "halcyon:policy",            "/v2/policies",             cadence_seconds=86400),
    EndpointSpec("policy_groups",        "halcyon:policy_group",      "/v2/policy-groups",        cadence_seconds=86400),
    EndpointSpec("overrides",            "halcyon:override",          "/v2/overrides",            cadence_seconds=21600),
    EndpointSpec("tags",                 "halcyon:tag",               "/v2/tags",                 cadence_seconds=86400),

    # Operations & Automation
    EndpointSpec("jobs",                 "halcyon:job",               "/v2/jobs",                 cadence_seconds=3600),
    EndpointSpec("webhooks",             "halcyon:webhook",           "/v2/webhooks",             cadence_seconds=21600),
    EndpointSpec("integrations",         "halcyon:integration",       "/v2/integrations",         cadence_seconds=21600),
    EndpointSpec("installers",           "halcyon:installer",         "/v2/installers",           cadence_seconds=86400),

    # Platform Health & Meta
    EndpointSpec("health",               "halcyon:health",            "/health",                  cadence_seconds=1800),
    EndpointSpec("auth",                 "halcyon:auth_event",        "/v2/auth",                 cadence_seconds=86400),
]


# --------------------------------------------------------------------
# Utilities
# --------------------------------------------------------------------

def _utc_now() -> datetime:
    return datetime.now(timezone.utc)


def _safe_json_dumps(obj: Any) -> str:
    return json.dumps(obj, ensure_ascii=False, separators=(",", ":"), default=str)


def _parse_time(value: Any) -> Optional[float]:
    """
    Returns epoch seconds (float) or None.
    Supports:
      - epoch (int/float)
      - ISO8601 strings with 'Z'
      - common datetime strings
    """
    if value is None:
        return None

    # epoch
    if isinstance(value, (int, float)) and value > 0:
        # assume seconds; if ms, convert
        if value > 10_000_000_000:  # ~2286-11-20 in seconds
            return float(value) / 1000.0
        return float(value)

    if isinstance(value, str):
        s = value.strip()
        if not s:
            return None

        # numeric string epoch
        if s.isdigit():
            n = int(s)
            if n > 10_000_000_000:
                return float(n) / 1000.0
            return float(n)

        # ISO8601
        try:
            if s.endswith("Z"):
                s = s[:-1] + "+00:00"
            dt = datetime.fromisoformat(s)
            if dt.tzinfo is None:
                dt = dt.replace(tzinfo=timezone.utc)
            return dt.timestamp()
        except Exception:
            pass

        # fallback: common formats
        for fmt in (
            "%Y-%m-%d %H:%M:%S",
            "%Y-%m-%dT%H:%M:%S",
            "%Y-%m-%dT%H:%M:%S.%f",
            "%Y-%m-%d %H:%M:%S.%f",
        ):
            try:
                dt = datetime.strptime(s, fmt).replace(tzinfo=timezone.utc)
                return dt.timestamp()
            except Exception:
                continue

    return None


def _extract_best_event_time(obj: Dict[str, Any], hints: Tuple[str, ...]) -> float:
    """
    Pick first valid timestamp from hinted fields, else now().
    """
    for k in hints:
        if k in obj:
            ts = _parse_time(obj.get(k))
            if ts is not None:
                return ts
    return _utc_now().timestamp()


def _extract_id(obj: Dict[str, Any], hints: Tuple[str, ...]) -> Optional[str]:
    for k in hints:
        v = obj.get(k)
        if v is None:
            continue
        if isinstance(v, (str, int)):
            return str(v)
    return None


def _mkdirp(path: str) -> None:
    os.makedirs(path, exist_ok=True)


def _checkpoint_path(checkpoint_dir: str, stanza_name: str, key: str) -> str:
    safe_stanza = "".join(c if c.isalnum() or c in ("-", "_") else "_" for c in stanza_name)
    safe_key = "".join(c if c.isalnum() or c in ("-", "_") else "_" for c in key)
    return os.path.join(checkpoint_dir, f"{safe_stanza}.{safe_key}.json")


def load_checkpoint(checkpoint_dir: str, stanza_name: str, key: str) -> Dict[str, Any]:
    p = _checkpoint_path(checkpoint_dir, stanza_name, key)
    if not os.path.exists(p):
        return {}
    try:
        with open(p, "r", encoding="utf-8") as f:
            return json.load(f) or {}
    except Exception:
        return {}


def save_checkpoint(checkpoint_dir: str, stanza_name: str, key: str, data: Dict[str, Any]) -> None:
    _mkdirp(checkpoint_dir)
    p = _checkpoint_path(checkpoint_dir, stanza_name, key)
    tmp = p + ".tmp"
    with open(tmp, "w", encoding="utf-8") as f:
        json.dump(data, f, ensure_ascii=False, indent=2, default=str)
    os.replace(tmp, p)


# --------------------------------------------------------------------
# Halcyon API Client
# --------------------------------------------------------------------

class HalcyonClient:
    def __init__(
        self,
        base_url: str,
        token: str,
        verify_ssl: bool = True,
        proxy_url: Optional[str] = None,
        timeout: int = DEFAULT_TIMEOUT_SECONDS,
        user_agent: str = f"{APP_NAME}/1.0",
    ) -> None:
        self.base_url = base_url.rstrip("/")
        self.token = token.strip()
        self.verify_ssl = verify_ssl
        self.timeout = timeout
        self.session = requests.Session()
        self.session.headers.update(
            {
                "Authorization": f"Bearer {self.token}",
                "Accept": "application/json",
                "User-Agent": user_agent,
            }
        )
        self.proxies = None
        if proxy_url:
            proxy_url = proxy_url.strip()
            if proxy_url:
                self.proxies = {"http": proxy_url, "https": proxy_url}

    def request(self, method: str, path_or_url: str, params: Optional[Dict[str, Any]] = None) -> requests.Response:
        if path_or_url.startswith("http://") or path_or_url.startswith("https://"):
            url = path_or_url
        else:
            url = f"{self.base_url}{path_or_url}"

        last_exc = None
        for attempt in range(1, RETRY_MAX + 1):
            try:
                resp = self.session.request(
                    method=method,
                    url=url,
                    params=params,
                    timeout=self.timeout,
                    verify=self.verify_ssl,
                    proxies=self.proxies,
                )

                # retry on 429/5xx
                if resp.status_code in (429, 500, 502, 503, 504):
                    sleep_s = RETRY_BASE_SLEEP * (2 ** (attempt - 1))
                    sleep_s = sleep_s + random.uniform(0, RETRY_JITTER)
                    # honor Retry-After if present
                    ra = resp.headers.get("Retry-After")
                    if ra and ra.isdigit():
                        sleep_s = max(sleep_s, float(ra))
                    time.sleep(min(sleep_s, 60.0))
                    continue

                return resp

            except Exception as e:
                last_exc = e
                sleep_s = RETRY_BASE_SLEEP * (2 ** (attempt - 1))
                sleep_s = sleep_s + random.uniform(0, RETRY_JITTER)
                time.sleep(min(sleep_s, 30.0))

        raise RuntimeError(f"Halcyon API request failed after retries: {method} {url}: {last_exc}")


# --------------------------------------------------------------------
# Pagination (generic)
# --------------------------------------------------------------------

def _as_list_payload(payload: Any, list_key_hints: Tuple[str, ...]) -> List[Dict[str, Any]]:
    if isinstance(payload, list):
        return [x for x in payload if isinstance(x, dict)]

    if isinstance(payload, dict):
        for k in list_key_hints:
            v = payload.get(k)
            if isinstance(v, list):
                return [x for x in v if isinstance(x, dict)]

        # fallback: single object
        return [payload]

    return []


def _next_link(payload: Any) -> Optional[str]:
    if not isinstance(payload, dict):
        return None
    # common patterns: next, links.next, paging.next
    for path in (("next",), ("links", "next"), ("paging", "next"), ("_links", "next", "href")):
        cur = payload
        ok = True
        for p in path:
            if isinstance(cur, dict) and p in cur:
                cur = cur[p]
            else:
                ok = False
                break
        if ok and isinstance(cur, str) and cur.startswith(("http://", "https://")):
            return cur
    return None


def _cursor_token(payload: Any) -> Optional[str]:
    if not isinstance(payload, dict):
        return None
    for k in ("cursor", "nextCursor", "next_cursor", "continuationToken", "continuation_token"):
        v = payload.get(k)
        if isinstance(v, str) and v.strip():
            return v.strip()
    # nested
    paging = payload.get("paging")
    if isinstance(paging, dict):
        for k in ("cursor", "nextCursor", "next_cursor"):
            v = paging.get(k)
            if isinstance(v, str) and v.strip():
                return v.strip()
    return None


def _page_meta(payload: Any) -> Optional[Tuple[int, int]]:
    """
    Returns (page, total_pages) if present.
    """
    if not isinstance(payload, dict):
        return None
    for block_key in ("page", "pagination", "paging", "meta"):
        blk = payload.get(block_key)
        if not isinstance(blk, dict):
            continue
        p = blk.get("page") or blk.get("currentPage") or blk.get("current_page")
        tp = blk.get("totalPages") or blk.get("total_pages")
        if isinstance(p, int) and isinstance(tp, int) and tp >= 1:
            return (p, tp)
    return None


def paginate_list(
    client: HalcyonClient,
    spec: EndpointSpec,
    params: Optional[Dict[str, Any]] = None,
) -> Iterable[Dict[str, Any]]:
    """
    Yields dict objects from a list endpoint using multiple pagination styles.
    """
    params = dict(params or {})
    # best-effort page size
    params.setdefault("limit", DEFAULT_PAGE_SIZE)
    params.setdefault("pageSize", DEFAULT_PAGE_SIZE)
    params.setdefault("perPage", DEFAULT_PAGE_SIZE)

    url_or_path: str = spec.path
    pages = 0
    seen_page_guard = set()

    cursor_mode = False
    cursor = None

    # offset mode
    offset_mode = False
    offset = params.get("offset")
    if isinstance(offset, int):
        offset_mode = True

    while True:
        pages += 1
        if pages > MAX_PAGES_SAFETY_CAP:
            break

        # apply cursor if we discovered it
        if cursor_mode and cursor:
            params["cursor"] = cursor
            params["nextCursor"] = cursor
            params["next_cursor"] = cursor

        # apply offset if enabled
        if offset_mode and isinstance(offset, int):
            params["offset"] = offset

        resp = client.request("GET", url_or_path, params=params)
        if resp.status_code >= 400:
            raise RuntimeError(f"HTTP {resp.status_code} calling {url_or_path}: {resp.text[:500]}")

        payload = resp.json()
        objs = _as_list_payload(payload, spec.list_key_hints)
        for obj in objs:
            yield obj

        # next link style
        nxt = _next_link(payload)
        if nxt:
            # guard against loops
            if nxt in seen_page_guard:
                break
            seen_page_guard.add(nxt)
            url_or_path = nxt
            continue

        # cursor style
        cur = _cursor_token(payload)
        if cur:
            if cursor_mode and cur == cursor:
                break
            cursor_mode = True
            cursor = cur
            continue

        # page meta style
        pm = _page_meta(payload)
        if pm:
            page, total_pages = pm
            if page >= total_pages:
                break
            # increment page if it exists
            params["page"] = page + 1
            continue

        # offset style heuristic
        if isinstance(payload, dict) and any(k in payload for k in ("total", "count")):
            if not offset_mode:
                offset_mode = True
                offset = 0
            page_size = int(params.get("limit") or params.get("pageSize") or DEFAULT_PAGE_SIZE)
            if len(objs) < page_size:
                break
            offset = int(offset or 0) + page_size
            continue

        # default stop (no pagination indicators)
        break


# --------------------------------------------------------------------
# Modular Input
# --------------------------------------------------------------------

class HalcyonModularInput(Script):
    def get_scheme(self) -> Scheme:
        scheme = Scheme("halcyon_ai")
        scheme.description = "Halcyon.ai API modular input (multi-endpoint)"
        scheme.use_external_validation = True
        scheme.use_single_instance = True

        scheme.add_argument(Argument("api_token", title="API Token", description="Halcyon Bearer token", required_on_create=True))
        scheme.add_argument(Argument("base_url", title="Base URL", description="Halcyon API base URL", required_on_create=False))
        scheme.add_argument(Argument("verify_ssl", title="Verify SSL", description="true/false", required_on_create=False))
        scheme.add_argument(Argument("proxy_url", title="Proxy URL", description="Optional proxy URL", required_on_create=False))
        scheme.add_argument(Argument("index", title="Index", description="Target Splunk index", required_on_create=False))
        scheme.add_argument(Argument("page_size", title="Page Size", description="API page size", required_on_create=False))
        scheme.add_argument(Argument("timeout", title="Timeout", description="HTTP timeout seconds", required_on_create=False))

        # optional toggles per endpoint (default enabled if missing)
        for spec in ENDPOINTS:
            scheme.add_argument(
                Argument(
                    f"enable_{spec.name}",
                    title=f"Enable {spec.name}",
                    description=f"true/false to enable collection for {spec.sourcetype}",
                    required_on_create=False,
                )
            )

        return scheme

    def validate_input(self, definition: InputDefinition) -> None:
        params = definition.parameters
        token = (params.get("api_token") or "").strip()
        if not token:
            raise ValueError("api_token is required")

        base_url = (params.get("base_url") or DEFAULT_BASE_URL).strip() or DEFAULT_BASE_URL
        if not base_url.startswith("http"):
            raise ValueError("base_url must start with http/https")

    def stream_events(self, inputs: InputDefinition, ew: EventWriter) -> None:
        stanza_items = inputs.inputs.items()
        checkpoint_dir = inputs.metadata.get("checkpoint_dir") or os.path.join(os.getcwd(), "halcyon_checkpoints")
        _mkdirp(checkpoint_dir)

        for stanza_name, stanza in stanza_items:
            params = stanza

            token = (params.get("api_token") or "").strip()
            base_url = (params.get("base_url") or DEFAULT_BASE_URL).strip() or DEFAULT_BASE_URL
            verify_ssl = str(params.get("verify_ssl") or "true").strip().lower() not in ("false", "0", "no")
            proxy_url = (params.get("proxy_url") or "").strip() or None
            index = (params.get("index") or DEFAULT_INDEX).strip() or DEFAULT_INDEX

            try:
                page_size = int(params.get("page_size") or DEFAULT_PAGE_SIZE)
            except Exception:
                page_size = DEFAULT_PAGE_SIZE

            try:
                timeout = int(params.get("timeout") or DEFAULT_TIMEOUT_SECONDS)
            except Exception:
                timeout = DEFAULT_TIMEOUT_SECONDS

            client = HalcyonClient(
                base_url=base_url,
                token=token,
                verify_ssl=verify_ssl,
                proxy_url=proxy_url,
                timeout=timeout,
            )

            now_epoch = _utc_now().timestamp()

            # master schedule checkpoint
            sched_cp = load_checkpoint(checkpoint_dir, stanza_name, "scheduler") or {}
            last_run_by_name: Dict[str, float] = sched_cp.get("last_run_by_name", {}) if isinstance(sched_cp.get("last_run_by_name"), dict) else {}

            for spec in ENDPOINTS:
                # endpoint enable flag
                enable_key = f"enable_{spec.name}"
                enabled_raw = params.get(enable_key)
                if enabled_raw is None or str(enabled_raw).strip() == "":
                    enabled = True
                else:
                    enabled = str(enabled_raw).strip().lower() not in ("false", "0", "no")

                if not enabled:
                    continue

                last_run = float(last_run_by_name.get(spec.name, 0.0) or 0.0)
                due = (now_epoch - last_run) >= float(spec.cadence_seconds)
                if not due:
                    continue

                # per-sourcetype checkpoint
                cp_key = f"cp_{spec.sourcetype}"
                cp = load_checkpoint(checkpoint_dir, stanza_name, cp_key) or {}
                # checkpoint fields:
                # - last_seen_time (epoch)
                # - seen_ids (small rolling set)
                last_seen_time = float(cp.get("last_seen_time", 0.0) or 0.0)
                seen_ids = cp.get("seen_ids", [])
                if not isinstance(seen_ids, list):
                    seen_ids = []
                seen_set = set(str(x) for x in seen_ids[-5000:])  # cap memory

                # query params best-effort
                req_params: Dict[str, Any] = {}
                # standard window param patterns (best effort; harmless if ignored)
                if last_seen_time > 0:
                    # ISO8601
                    since_iso = datetime.fromtimestamp(last_seen_time, tz=timezone.utc).isoformat()
                    req_params.update(
                        {
                            "since": since_iso,
                            "startTime": since_iso,
                            "start_time": since_iso,
                            "from": since_iso,
                            "fromTime": since_iso,
                        }
                    )

                # enforce page size across common param names
                req_params.update({"limit": page_size, "pageSize": page_size, "perPage": page_size})

                max_seen_time = last_seen_time
                wrote = 0

                try:
                    for obj in paginate_list(client, spec, params=req_params):
                        if not isinstance(obj, dict):
                            continue

                        obj_id = _extract_id(obj, spec.id_field_hints)
                        obj_ts = _extract_best_event_time(obj, spec.time_field_hints)

                        # basic de-dupe: id preferred, else time-only
                        if obj_id and obj_id in seen_set:
                            continue

                        # update checkpoint time window
                        if obj_ts and obj_ts > max_seen_time:
                            max_seen_time = obj_ts

                        # write event
                        evt = Event(
                            time=obj_ts,
                            index=index,
                            sourcetype=spec.sourcetype,
                            source=f"halcyon_api:{spec.name}",
                            data=_safe_json_dumps(obj),
                        )
                        ew.write_event(evt)
                        wrote += 1

                        if obj_id:
                            seen_set.add(obj_id)

                    # save per-sourcetype checkpoint
                    cp_out = {
                        "last_seen_time": max_seen_time if max_seen_time > 0 else last_seen_time,
                        "seen_ids": list(seen_set)[-5000:],
                        "last_run_epoch": now_epoch,
                    }
                    save_checkpoint(checkpoint_dir, stanza_name, cp_key, cp_out)

                    # update schedule checkpoint
                    last_run_by_name[spec.name] = now_epoch
                    sched_cp_out = {"last_run_by_name": last_run_by_name, "updated": now_epoch}
                    save_checkpoint(checkpoint_dir, stanza_name, "scheduler", sched_cp_out)

                    # write a lightweight internal status event
                    status_obj = {
                        "collector": spec.name,
                        "sourcetype": spec.sourcetype,
                        "wrote": wrote,
                        "last_seen_time": max_seen_time,
                        "run_time": now_epoch,
                    }
                    ew.write_event(
                        Event(
                            time=now_epoch,
                            index=index,
                            sourcetype="halcyon:collector_status",
                            source="halcyon_input",
                            data=_safe_json_dumps(status_obj),
                        )
                    )

                except Exception as e:
                    err_obj = {
                        "collector": spec.name,
                        "sourcetype": spec.sourcetype,
                        "error": str(e),
                        "trace": traceback.format_exc(limit=12),
                        "run_time": now_epoch,
                    }
                    ew.write_event(
                        Event(
                            time=now_epoch,
                            index=index,
                            sourcetype="halcyon:collector_error",
                            source="halcyon_input",
                            data=_safe_json_dumps(err_obj),
                        )
                    )
                    # do not advance last_run on error; next invocation retries

        # end stream_events


if __name__ == "__main__":
    HalcyonModularInput().run()
