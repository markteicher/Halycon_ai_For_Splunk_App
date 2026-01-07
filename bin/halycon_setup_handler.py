# halcyon_setup_handler.py
#
# Halcyon.ai for Splunk App
# Setup REST handler
#
# Handles initial configuration, credential storage, and reloads

import json
import splunk.admin as admin
import splunk.entity as entity
import splunk.rest as rest


APP_NAME = "Halcyon_For_Splunk"
CONF_FILE = "halcyon"
CONF_STANZA = "api"


class HalcyonSetupHandler(admin.MConfigHandler):

    def setup(self):
        if self.requestedAction == admin.ACTION_CREATE:
            for arg in [
                "api_token",
                "api_base_url",
                "verify_ssl",
                "proxy_enabled",
                "proxy_url",
                "proxy_username",
                "proxy_password"
            ]:
                self.supportedArgs.addOptArg(arg)

    def handleCreate(self, confInfo):

        api_token = self.callerArgs.get("api_token", [None])[0]
        api_base_url = self.callerArgs.get("api_base_url", ["https://api.halcyon.ai"])[0]
        verify_ssl = self.callerArgs.get("verify_ssl", ["true"])[0]
        proxy_enabled = self.callerArgs.get("proxy_enabled", ["false"])[0]
        proxy_url = self.callerArgs.get("proxy_url", [""])[0]
        proxy_username = self.callerArgs.get("proxy_username", [""])[0]
        proxy_password = self.callerArgs.get("proxy_password", [""])[0]

        if not api_token:
            raise Exception("API token is required")

        self._write_conf(
            api_base_url,
            verify_ssl,
            proxy_enabled,
            proxy_url,
            proxy_username
        )

        self._store_credential(api_token, proxy_password)

    def _write_conf(
        self,
        api_base_url,
        verify_ssl,
        proxy_enabled,
        proxy_url,
        proxy_username
    ):
        entity.setEntity(
            "configs/conf-" + CONF_FILE,
            CONF_STANZA,
            {
                "api_base_url": api_base_url,
                "verify_ssl": verify_ssl,
                "proxy_enabled": proxy_enabled,
                "proxy_url": proxy_url,
                "proxy_username": proxy_username
            },
            sessionKey=self.getSessionKey(),
            owner="nobody",
            namespace=APP_NAME
        )

    def _store_credential(self, api_token, proxy_password):

        if api_token:
            rest.simpleRequest(
                "/servicesNS/nobody/{}/storage/passwords".format(APP_NAME),
                sessionKey=self.getSessionKey(),
                postargs={
                    "name": "halcyon_api_token",
                    "password": api_token
                }
            )

        if proxy_password:
            rest.simpleRequest(
                "/servicesNS/nobody/{}/storage/passwords".format(APP_NAME),
                sessionKey=self.getSessionKey(),
                postargs={
                    "name": "halcyon_proxy_password",
                    "password": proxy_password
                }
            )


admin.init(HalcyonSetupHandler, admin.CONTEXT_APP_ONLY)
