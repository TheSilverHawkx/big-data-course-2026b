"""Shared HTTP client factory with retry logic via tenacity."""
from __future__ import annotations

import logging
import time
from collections.abc import Generator
from contextlib import contextmanager
from typing import Any

import httpx
from tenacity import (
    retry,
    retry_if_exception_type,
    stop_after_attempt,
    wait_exponential,
)

logger = logging.getLogger(__name__)

DEFAULT_TIMEOUT = httpx.Timeout(30.0, connect=10.0)
DEFAULT_HEADERS = {"Accept": "application/json", "User-Agent": "riskrank/0.1.0"}


@contextmanager
def build_client(
    headers: dict[str, str] | None = None,
    timeout: httpx.Timeout = DEFAULT_TIMEOUT,
) -> Generator[httpx.Client, None, None]:
    merged = {**DEFAULT_HEADERS, **(headers or {})}
    with httpx.Client(headers=merged, timeout=timeout, follow_redirects=True) as client:
        yield client


@retry(
    retry=retry_if_exception_type((httpx.HTTPStatusError, httpx.TransportError)),
    wait=wait_exponential(multiplier=1, min=2, max=60),
    stop=stop_after_attempt(5),
    reraise=True,
)
def get_with_retry(
    client: httpx.Client,
    url: str,
    params: dict[str, Any] | None = None,
    delay_seconds: float = 0.0,
) -> httpx.Response:
    if delay_seconds > 0:
        time.sleep(delay_seconds)
    response = client.get(url, params=params)
    if response.status_code in {429, 500, 502, 503, 504}:
        logger.warning("Retryable HTTP %s from %s", response.status_code, url)
        response.raise_for_status()
    response.raise_for_status()
    return response
