# halcyon_validation.py
#
# Halcyon.ai for Splunk App
# Validation and connectivity checks
#
# Responsibilities:
# - Validate API token
# - Validate API reachability
# - Return structured results to setup UI
#
# Location:
#   $SPLUNK_HOME/etc/apps/Halcyon_For_Splunk/bin/halcyon_validation.py

import json
import sys
import ssl
import urllib.request
import urllib.error

from splunk.rest import BaseRestHandler
from splunk import admin


HALCYON_API_BASE = "https://api.halcyon.ai"
CURRENT_USER_ENDPOINT = "/api/v1/users/me"


class HalcyonValidationHandler(BaseRestHandler):

    def handle_POST(self):
        try:
            payload = json.loads(self.request['payload'])
            api_token = payload.get("api_token")

            if not api_token:
                self._respond_error("API token is required")
                return

            result = self._validate_token(api_token)
            self._respond_ok(result)

        except Exception as e:
            self._respond_error(str(e))

    def _validate_token(self, api_token):
        url = HALCYON_API_BASE + CURRENT_USER_ENDPOINT

        headers = {
            "Authorization": f"Bearer {api_token}",
            "Accept": "application/json"
        }

        context = ssl.create_default_context()
        req = urllib.request.Request(url, headers=headers, method="GET")

        try:
            with urllib.request.urlopen(req, context=context, timeout=30) as resp:
                if resp.status != 200:
                    raise Exception(f"Unexpected HTTP status: {resp.status}")

                data = json.loads(resp.read().decode("utf-8"))

                return {
                    "status": "success",
                    "user_id": data.get("id"),
                    "email": data.get("email"),
                    "role": data.get("role")
                }

        except urllib.error.HTTPError as e:
            body = e.read().decode("utf-8") if e.fp else ""
            raise Exception(f"HTTPError {e.code}: {body}")

        except urllib.error.URLError as e:
            raise Exception(f"Connection error: {e.reason}")

    def _respond_ok(self, data):
        self.response.setHeader('Content-Type', 'application/json')
        self.response.write(json.dumps({
            "success": True,
            "data": data
        }))

    def _respond_error(self, message):
        self.response.setHeader('Content-Type', 'application/json')
        self.response.write(json.dumps({
            "success": False,
            "error": message
        }))


admin.init(HalcyonValidationHandler)
