import abc
from typing import Set

class BaseSource(abc.ABC):
    """
    Abstract Base Class representing a passive OSINT source for subdomain enumeration.
    """

    def __init__(self, name: str):
        self.name = name

    @abc.abstractmethod
    async def fetch(self, session, domain: str) -> Set[str]:
        """
        Fetch subdomains for a given target domain asynchronously.

        Args:
            session (aiohttp.ClientSession): The shared async HTTP session.
            domain (str): Target base domain (e.g., example.com)

        Returns:
            Set[str]: A set of discovered subdomains.
        """
        pass
