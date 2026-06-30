import yaml
import os
import logging

log = logging.getLogger("haxder")

class Config:
    def __init__(self, config_path: str = None):
        self.config_path = config_path or "config.yaml"
        self.api_keys = {}
        self.load_config()

    def load_config(self):
        if not os.path.exists(self.config_path):
            log.debug(f"Config file not found at {self.config_path}. Using default settings without premium APIs.")
            return

        try:
            with open(self.config_path, 'r') as f:
                data = yaml.safe_load(f)
                if data and 'api_keys' in data:
                    self.api_keys = data['api_keys']
            log.debug(f"Successfully loaded configuration from {self.config_path}")
        except Exception as e:
            log.error(f"Error loading configuration from {self.config_path}: {e}")

    def get_api_key(self, source_name: str) -> str:
        """
        Retrieves the API key for a given source, if available.
        Checks Environment Variables first (e.g., SHODAN_API_KEY), then the config file.
        """
        env_key = f"{source_name.upper()}_API_KEY"
        if env_key in os.environ:
            return os.environ[env_key]
            
        return self.api_keys.get(source_name, None)
