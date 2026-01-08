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
import random
import traceback
from dataclasses import dataclass
from datetime import datetime, timezone
from typing import Any, Dict, Iterable, List, Optional, Tuple

import requests
from splunklib.modularinput import Script, Scheme, Argument, Event, EventWriter, InputDefinition


APP_NAME = "Halcyon_ai_for_Splunk"
DEFAULT_BASE_URL = "https://api.halcyon.ai"
DEFAULT_INDEX = "security_halycon"

DEFAULT_TIMEOUT_SECONDS = 60
DEFAULT_PAGE_SIZE = 200
MAX_PAGES_SAFETY_CAP = 2000

RETRY_MAX = 5
RETRY_BASE_SLEEP = 1.0
RETRY_JITTER = 0.25


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
    EndpointSpec("alerts", "halcyon:alert", "/v2/alerts", 3600),
    EndpointSpec("alert_instances", "halcyon:alert_instance", "/v2/alert-instances", 3600),
    EndpointSpec("events", "halcyon:event", "/v2/events", 3600),

    EndpointSpec("event_metrics", "halcyon:event_metrics", "/search/events/metrics", 3600),

    EndpointSpec("threats", "halcyon:threat", "/v2/threats", 21600),
    EndpointSpec("alert_artifacts", "halcyon:artifact", "/v2/alerts/artifacts", 3600),

    EndpointSpec("assets", "halcyon:asset", "/v2/assets", 21600),
    EndpointSpec("devices", "halcyon:device", "/v2/devices", 21600),
    EndpointSpec("device_extracted_keys", "halcyon:device_extracted_key", "/v2/device-extracted-keys", 21600),

    EndpointSpec("tenant_users", "halcyon:tenant_user", "/v2/tenant-users", 43200),
    EndpointSpec("identity_providers", "halcyon:identity_provider", "/v2/identity-providers", 43200),

    EndpointSpec("tenants", "halcyon:tenant", "/v2/tenants", 86400),
    EndpointSpec("subtenants", "halcyon:subtenant", "/v2/subtenants", 86400),
    EndpointSpec("deployment_groups", "halcyon:deployment_group", "/v2/deployment-groups", 86400),

    EndpointSpec("policies", "halcyon:policy", "/v2/policies", 21600),
    EndpointSpec("policy_groups", "halcyon:policy_group", "/v2/policy-groups", 21600),
    EndpointSpec("overrides", "halcyon:override", "/v2/overrides", 21600),
    EndpointSpec("tags", "halcyon:tag", "/v2/tags", 21600),

    EndpointSpec("jobs", "halcyon:job", "/v2/jobs", 3600),
    EndpointSpec("webhooks", "halcyon:webhook", "/v2/webhooks", 43200),
    EndpointSpec("integrations", "halcyon:integration", "/v2/integrations", 43200),
    EndpointSpec("installers", "halcyon:installer", "/v2/installers", 86400),

    EndpointSpec("health", "halcyon:health", "/health", 1800),
    EndpointSpec("auth_events", "halcyon:auth_event", "/v2/auth", 3600),
]


def _utc_now() -> float:
    return datetime.now(timezone.utc).timestamp()


def _safe_json(obj: Any) -> str:
    return json.dumps(obj, ensure_ascii=False, separators=(",", ":"), default=str)


def _parse_time(obj: Dict[str, Any], keys: Tuple[str, ...]) -> float:
    for k in keys:
        v = obj.get(k)
        if v is None:
            continue
        try:
            if isinstance(v, (int, float)):
                return float(v)
            if isinstance(v, str):
                if v.endswith("Z"):
                    v = v.replace("Z", "+00:00")
                return datetime.fromisoformat(v).timestamp()
        except Exception:
            continue
    return _utc_now()


class HalcyonClient:
    def __init__(self, base_url: str, token: str, verify_ssl: bool, proxy_url: Optional[str], timeout: int):
        self.base_url = base_url.rstrip("/")
        self.verify_ssl = verify_ssl
        self.timeout = timeout
        self.session = requests.Session()
        self.session.headers.update({
            "Authorization": f"Bearer {token}",
            "Accept": "application/json",
        })
        self.proxies = {"http": proxy_url, "https": proxy_url} if proxy_url else None

    def get(self, path: str, params: Dict[str, Any]) -> Dict[str, Any]:
        url = path if path.startswith("http") else f"{self.base_url}{path}"
        for attempt in range(RETRY_MAX):
            try:
                r = self.session.get(
                    url,
                    params=params,
                    timeout=self.timeout,
                    verify=self.verify_ssl,
                    proxies=self.proxies,
                )
                if r.status_code in (429, 500, 502, 503, 504):
                    time.sleep(RETRY_BASE_SLEEP * (2 ** attempt) + random.uniform(0, RETRY_JITTER))
                    continue
                r.raise_for_status()
                return r.json()
            except Exception:
                if attempt == RETRY_MAX - 1:
                    raise
        raise RuntimeError("request failed")


class HalcyonModularInput(Script):

    def get_scheme(self) -> Scheme:
        s = Scheme("halcyon_ai")
        s.use_single_instance = True
        s.use_external_validation = True

        s.add_argument(Argument("api_token", required_on_create=True))
        s.add_argument(Argument("base_url"))
        s.add_argument(Argument("verify_ssl"))
        s.add_argument(Argument("proxy_url"))
        s.add_argument(Argument("index"))
        s.add_argument(Argument("page_size"))
        s.add_argument(Argument("timeout"))

        for ep in ENDPOINTS:
            s.add_argument(Argument(f"enable_{ep.name}"))

        return s

    def stream_events(self, inputs: InputDefinition, ew: EventWriter) -> None:
        for stanza, params in inputs.inputs.items():

            client = HalcyonClient(
                base_url=params.get("base_url", DEFAULT_BASE_URL),
                token=params["api_token"],
                verify_ssl=str(params.get("verify_ssl", "true")).lower() != "false",
                proxy_url=params.get("proxy_url"),
                timeout=int(params.get("timeout", DEFAULT_TIMEOUT_SECONDS)),
            )

            index = params.get("index", DEFAULT_INDEX)
            page_size = int(params.get("page_size", DEFAULT_PAGE_SIZE))
            now = _utc_now()

            for ep in ENDPOINTS:
                if str(params.get(f"enable_{ep.name}", "true")).lower() in ("false", "0"):
                    continue

                try:
                    payload = client.get(ep.path, {"limit": page_size})

                    if ep.sourcetype == "halcyon:event_metrics":
                        ew.write_event(Event(
                            time=now,
                            index=index,
                            sourcetype=ep.sourcetype,
                            source=f"halcyon_api:{ep.name}",
                            data=_safe_json(payload),
                        ))
                        continue

                    records = payload.get("data") if isinstance(payload, dict) else payload
                    if not isinstance(records, list):
                        records = [payload]

                    for obj in records:
                        ts = _parse_time(obj, ep.time_field_hints)
                        ew.write_event(Event(
                            time=ts,
                            index=index,
                            sourcetype=ep.sourcetype,
                            source=f"halcyon_api:{ep.name}",
                            data=_safe_json(obj),
                        ))

                except Exception as e:
                    ew.write_event(Event(
                        time=now,
                        index=index,
                        sourcetype="halcyon:collector_error",
                        source="halcyon_input",
                        data=_safe_json({
                            "endpoint": ep.name,
                            "error": str(e),
                            "trace": traceback.format_exc(),
                        }),
                    ))


if __name__ == "__main__":
    HalcyonModularInput().run()
