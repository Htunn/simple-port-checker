"""Abstract base classes for all scanner and attacker modules."""

from __future__ import annotations

import logging
from abc import ABC, abstractmethod
from typing import Any

import httpx

from ..exceptions import AuthorizationRequired
from ..utils.authorization import make_authorization_banner
from ..utils.constants import USER_AGENT

logger = logging.getLogger(__name__)


class BaseScanner(ABC):
    """Common initialisation and HTTP client factory for all security scanners."""

    def __init__(
        self,
        target: str,
        headers: dict[str, str] | None = None,
        timeout: float = 15.0,
        verify_tls: bool = True,
        judge: Any | None = None,
    ) -> None:
        self.target = target
        self.headers = headers or {}
        self.timeout = timeout
        self.verify_tls = verify_tls
        self._judge = judge

    def _http_client(
        self,
        extra_headers: dict[str, str] | None = None,
    ) -> httpx.AsyncClient:
        """Return a pre-configured AsyncClient; use as an async context manager."""
        return httpx.AsyncClient(
            headers={
                "User-Agent": USER_AGENT,
                **self.headers,
                **(extra_headers or {}),
            },
            timeout=self.timeout,
            trust_env=False,
            verify=self.verify_tls,  # noqa: S501 — intentional for security scanning
        )

    @abstractmethod
    async def scan(self) -> Any:  # pragma: no cover
        ...


class BaseAttacker(ABC):
    """Common initialisation and authorization guard for all attacker modules.

    Subclasses must set ``_MODULE_NAME`` (e.g. ``"MCP"``) so the banner is
    labelled correctly.
    """

    _MODULE_NAME: str = "UNKNOWN"

    def __init__(self, authorized: bool = False, judge: Any | None = None) -> None:
        if not authorized:
            raise AuthorizationRequired(
                f"{self.__class__.__name__} requires authorized=True. "
                "Only use this against systems you have explicit written authorization to test."
            )
        self.authorized = True
        self._judge = judge
        logger.warning(make_authorization_banner(self._MODULE_NAME))
