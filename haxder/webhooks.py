import logging
import aiohttp
import json
from haxder.config import Config

log = logging.getLogger("haxder")

class Notifier:
    def __init__(self, config_path: str = None):
        self.config = Config(config_path)
        self.discord_webhook = self.config.get_api_key("discord_webhook")
        self.slack_webhook = self.config.get_api_key("slack_webhook")
        self.siem_webhook = self.config.get_api_key("siem_webhook")

    async def send_notification(self, message: str):
        if not self.discord_webhook and not self.slack_webhook:
            log.debug("No webhooks configured. Skipping notifications.")
            return

        async with aiohttp.ClientSession() as session:
            if self.discord_webhook:
                await self._send_discord(session, message)
            if self.slack_webhook:
                await self._send_slack(session, message)

    async def send_siem_data(self, data: dict):
        if not self.siem_webhook:
            log.debug("No SIEM webhook configured. Skipping SIEM export.")
            return

        try:
            async with aiohttp.ClientSession() as session:
                async with session.post(self.siem_webhook, json=data, headers={"Content-Type": "application/json"}, timeout=10) as resp:
                    if resp.status in [200, 201, 202, 204]:
                        log.info("Successfully sent scan data to SIEM webhook.")
                    else:
                        log.warning(f"Failed to send data to SIEM webhook: HTTP {resp.status}")
        except Exception as e:
            log.error(f"Error sending SIEM notification: {e}")

    async def _send_discord(self, session: aiohttp.ClientSession, message: str):
        payload = {"content": message}
        try:
            async with session.post(self.discord_webhook, json=payload, timeout=5) as resp:
                if resp.status in [200, 204]:
                    log.info("Successfully sent Discord notification.")
                else:
                    log.warning(f"Failed to send Discord notification: HTTP {resp.status}")
        except Exception as e:
            log.error(f"Error sending Discord notification: {e}")

    async def _send_slack(self, session: aiohttp.ClientSession, message: str):
        payload = {"text": message}
        try:
            async with session.post(self.slack_webhook, json=payload, timeout=5) as resp:
                if resp.status == 200:
                    log.info("Successfully sent Slack notification.")
                else:
                    log.warning(f"Failed to send Slack notification: HTTP {resp.status}")
        except Exception as e:
            log.error(f"Error sending Slack notification: {e}")
