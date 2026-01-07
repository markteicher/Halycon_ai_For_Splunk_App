# halcyon_input.py
#
# Halcyon.ai for Splunk App
# Modular Input for Halcyon.ai API ingestion
#
# Location:
#   $SPLUNK_HOME/etc/apps/Halcyon_For_Splunk/bin/halcyon_input.py

import sys
import json
import time
import ssl
import urllib.request
import urllib.error

from splunklib.modularinput import (
    Script,
    Scheme,
    Argument,
    Event,
    EventWriter
)


HALCYON_API_BASE = "https://api.halcyon.ai"


ENDPOINTS = {
    "alerts": "/api/v1/alerts",
    "alert_instances": "/api/v1/alert-instances",
    "events": "/api/v1/events",
    "threats": "/api/v1/threats",
    "artifacts": "/api/v1/artifacts",
    "assets": "/api/v1/assets",
    "devices": "/api/v1/devices",
    "device_extracted_keys": "/api/v1/device-extracted-keys",
    "users": "/api/v1/users",
    "tenant_users": "/api/v1/tenant-users",
    "identity_providers": "/api/v1/identity-providers",
    "tenants": "/api/v1/tenants",
    "subtenants": "/api/v1/subtenants",
    "deployment_groups": "/api/v1/deployment-groups",
    "policies": "/api/v1/policies",
    "policy_groups": "/api/v1/policy-groups",
    "overrides": "/api/v1/overrides",
    "tags": "/api/v1/tags",
    "jobs": "/api/v1/jobs",
    "webhooks": "/api/v1/webhooks",
    "integrations": "/api/v1/integrations",
    "installers": "/api/v1/installers",
    "health": "/api/v1/health"
}


class HalcyonInput(Script):

    def get_scheme(self):
        scheme = Scheme("Halcyon.ai Modular Input")
        scheme.description = "Ingests data from Halcyon.ai API"
        scheme.use_external_validation = True
        scheme.use_single_instance = False

        scheme.add_argument(Argument(
            name="api_token",
            title="Halcyon API Token",
            description="Bearer token for Halcyon.ai API",
            required_on_create=True,
            required_on_edit=False
        ))

        scheme.add_argument(Argument(
            name="endpoint",
            title="Endpoint",
            description="Halcyon API endpoint key",
            required_on_create=True,
            required_on_edit=False
        ))

        scheme.add_argument(Argument(
            name="interval",
            title="Interval",
            description="Polling interval in seconds",
            required_on_create=True,
            required_on_edit=False
        ))

        return scheme

    def validate_input(self, definition):
        endpoint = definition.parameters.get("endpoint")
        if endpoint not in ENDPOINTS:
            raise ValueError(f"Invalid endpoint: {endpoint}")

    def stream_events(self, inputs, ew: EventWriter):
        for input_name, input_item in inputs.inputs.items():
            api_token = input_item["api_token"]
            endpoint_key = input_item["endpoint"]
            interval = int(input_item["interval"])

            self.collect(endpoint_key, api_token, ew)
            time.sleep(interval)

    def collect(self, endpoint_key, api_token, ew):
        url = HALCYON_API_BASE + ENDPOINTS[endpoint_key]

        headers = {
            "Authorization": f"Bearer {api_token}",
            "Accept": "application/json"
        }

        context = ssl.create_default_context()
        req = urllib.request.Request(url, headers=headers, method="GET")

        try:
            with urllib.request.urlopen(req, context=context, timeout=60) as resp:
                if resp.status != 200:
                    return

                data = json.loads(resp.read().decode("utf-8"))

                if isinstance(data, list):
                    for record in data:
                        self.write_event(endpoint_key, record, ew)
                else:
                    self.write_event(endpoint_key, data, ew)

        except urllib.error.HTTPError:
            return
        except urllib.error.URLError:
            return

    def write_event(self, endpoint_key, record, ew):
        event = Event(
            data=json.dumps(record),
            sourcetype=f"halcyon:{endpoint_key}",
            index="security_halycon"
        )
        ew.write_event(event)


if __name__ == "__main__":
    sys.exit(HalcyonInput().run(sys.argv))
