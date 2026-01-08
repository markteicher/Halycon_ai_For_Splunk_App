# halcyon_setup_handler.py
#
# Halcyon.ai for Splunk App
# Setup REST handler

import splunk.admin as admin
import splunk.entity as entity
import splunk.rest as rest

APP_NAME = "halcyon_for_splunk"
CONF_FILE = "halcyon"
CONF_STANZA = "api"
CRED_REALM = "halcyon"

class HalcyonSetupHandler(admin.MConfigHandler):

    def setup(self):
        for arg in [
            "halcyon_api_token",
            "halcyon_api_base_url",
            "halcyon_verify_ssl",
            "halcyon_use_proxy",
            "halcyon_proxy_url",
            "halcyon_proxy_username",
            "halcyon_proxy_password"
        ]:
            self.supportedArgs.addOptArg(arg)

    def handleCreate(self, confInfo):
        self._handle_write()

    def handleEdit(self, confInfo):
        self._handle_write()

    def _handle_write(self):

        api_token = self._get("halcyon_api_token")
        api_base_url = self._get("halcyon_api_base_url", "https://api.halcyon.ai")
        verify_ssl = self._get("halcyon_verify_ssl", "true")
        proxy_enabled = self._get("halcyon_use_proxy", "false")
        proxy_url = self._get("halcyon_proxy_url")
        proxy_username = self._get("halcyon_proxy_username")
        proxy_password = self._get("halcyon_proxy_password")

        if not api_token:
            raise admin.ArgValidationException("API token is required")

        entity.setEntity(
            f"configs/conf-{CONF_FILE}",
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

        self._store_secret("api_token", api_token)

        if proxy_password:
            self._store_secret("proxy_password", proxy_password)

        self._reload_conf()

    def _store_secret(self, name, value):
        rest.simpleRequest(
            f"/servicesNS/nobody/{APP_NAME}/storage/passwords",
            sessionKey=self.getSessionKey(),
            postargs={
                "name": name,
                "password": value,
                "realm": CRED_REALM
            }
        )

    def _reload_conf(self):
        rest.simpleRequest(
            "/services/admin/conf-deploy/_reload",
            sessionKey=self.getSessionKey(),
            method="POST"
        )

    def _get(self, key, default=""):
        return self.callerArgs.get(key, [default])[0]


admin.init(HalcyonSetupHandler, admin.CONTEXT_APP_ONLY)
