"""
cloudflare_vectorize_tools.py
==============================
Cloudflare Vectorize integration for the S³ Global Compliance Protocol.

Creates and manages Vectorize v2 indexes (1408-dimensional Multimodal-Legacy
configuration) via the Cloudflare REST API.

Credentials are **never** hardcoded.  Supply them through environment
variables before running:

    export CF_ACCOUNT_ID="<your Cloudflare account ID>"
    export CF_API_TOKEN="<your Cloudflare API token>"

Or pass them explicitly to :class:`VectorizeClient`.

Design decisions
-----------------
* A single ``requests.Session`` is created once per :class:`VectorizeClient`
  instance so the underlying TCP/TLS connection is reused across calls.
* Every outgoing request uses an explicit timeout so the caller is never
  blocked indefinitely by a slow network or an unresponsive API endpoint.
* Credentials are resolved from environment variables at construction time
  so that the values are never present in source code or log output.
* Structured ``logging`` is used throughout; callers can attach their own
  handler/formatter without modifying this module.
"""

from __future__ import annotations

import logging
import os
from typing import Any, Optional

import requests
from requests.adapters import HTTPAdapter
from urllib3.util.retry import Retry

# ---------------------------------------------------------------------------
# Logging
# ---------------------------------------------------------------------------
logger = logging.getLogger(__name__)

# ---------------------------------------------------------------------------
# Constants
# ---------------------------------------------------------------------------

#: Cloudflare Vectorize v2 base URL template.
_CF_BASE = "https://api.cloudflare.com/client/v4/accounts/{account_id}/vectorize/v2"

#: Default request timeout in seconds (connect, read).
DEFAULT_TIMEOUT: tuple[float, float] = (10.0, 30.0)

#: Default retry strategy: 3 attempts, back-off on 429 / 5xx responses.
DEFAULT_RETRY = Retry(
    total=3,
    backoff_factor=0.5,
    status_forcelist={429, 500, 502, 503, 504},
    allowed_methods={"GET", "POST", "DELETE"},
    raise_on_status=False,
)

#: Dimensions used by the Multimodal-Legacy-1408 configuration.
MULTIMODAL_DIMENSIONS = 1408


# ---------------------------------------------------------------------------
# Client
# ---------------------------------------------------------------------------

class VectorizeClient:
    """
    Thin wrapper around the Cloudflare Vectorize v2 REST API.

    Parameters
    ----------
    account_id:
        Cloudflare account ID.  Falls back to the ``CF_ACCOUNT_ID``
        environment variable when not supplied.
    api_token:
        Cloudflare API token with *Vectorize Edit* permission.  Falls back
        to the ``CF_API_TOKEN`` environment variable when not supplied.
    timeout:
        ``(connect_timeout, read_timeout)`` in seconds.
    retry:
        ``urllib3.util.retry.Retry`` instance controlling retry behaviour.
    session:
        Pre-configured ``requests.Session`` (useful for testing).  A new
        session is created when omitted.

    Raises
    ------
    ValueError
        If neither *account_id* / *api_token* are provided nor the
        corresponding environment variables are set.
    """

    def __init__(
        self,
        account_id: Optional[str] = None,
        api_token: Optional[str] = None,
        *,
        timeout: tuple[float, float] = DEFAULT_TIMEOUT,
        retry: Retry = DEFAULT_RETRY,
        session: Optional[requests.Session] = None,
    ) -> None:
        self._account_id = account_id or os.environ.get("CF_ACCOUNT_ID")
        if not self._account_id:
            raise ValueError(
                "Cloudflare account ID is required.  "
                "Pass account_id= or set the CF_ACCOUNT_ID environment variable."
            )

        _token = api_token or os.environ.get("CF_API_TOKEN")
        if not _token:
            raise ValueError(
                "Cloudflare API token is required.  "
                "Pass api_token= or set the CF_API_TOKEN environment variable."
            )

        self._timeout = timeout
        self._base_url = _CF_BASE.format(account_id=self._account_id)

        if session is not None:
            self._session = session
        else:
            self._session = requests.Session()
            adapter = HTTPAdapter(max_retries=retry)
            self._session.mount("https://", adapter)

        # Set the Authorization header once on the session so every request
        # inherits it automatically.  The token value is held only in the
        # session headers object and is never logged.
        self._session.headers.update(
            {
                "Authorization": f"Bearer {_token}",
                "Content-Type": "application/json",
            }
        )

    # ------------------------------------------------------------------
    # Index management
    # ------------------------------------------------------------------

    def create_index(
        self,
        name: str,
        *,
        dimensions: int = MULTIMODAL_DIMENSIONS,
        metric: str = "cosine",
        description: str = "",
    ) -> dict[str, Any]:
        """
        Create a new Vectorize index.

        Parameters
        ----------
        name:
            Index name (must be unique within the account).
        dimensions:
            Vector dimensionality.  Defaults to 1408 (Multimodal-Legacy).
        metric:
            Distance metric: ``"cosine"`` (default), ``"euclidean"``, or
            ``"dot-product"``.
        description:
            Human-readable description stored with the index.

        Returns
        -------
        dict
            The parsed JSON response body from the Cloudflare API.

        Raises
        ------
        requests.HTTPError
            If the API returns a non-2xx status after all retries are
            exhausted.
        """
        url = f"{self._base_url}/indexes"
        body: dict[str, Any] = {
            "name": name,
            "config": {
                "dimensions": dimensions,
                "metric": metric,
            },
        }
        if description:
            body["description"] = description

        logger.info(
            "Creating Vectorize index name=%r dimensions=%d metric=%r",
            name,
            dimensions,
            metric,
        )
        response = self._session.post(url, json=body, timeout=self._timeout)
        self._raise_for_status(response)
        data: dict[str, Any] = response.json()
        logger.info("Vectorize index created: %s", data.get("result", {}).get("name", name))
        return data

    def get_index(self, name: str) -> dict[str, Any]:
        """
        Retrieve metadata for an existing index.

        Parameters
        ----------
        name:
            Index name.

        Returns
        -------
        dict
            Parsed JSON response from the Cloudflare API.

        Raises
        ------
        requests.HTTPError
            If the index does not exist (404) or another error occurs.
        """
        url = f"{self._base_url}/indexes/{name}"
        logger.info("Fetching Vectorize index name=%r", name)
        response = self._session.get(url, timeout=self._timeout)
        self._raise_for_status(response)
        return response.json()

    def list_indexes(self) -> list[dict[str, Any]]:
        """
        Return a list of all Vectorize indexes in the account.

        Returns
        -------
        list[dict]
            Each element is a dict describing one index.

        Raises
        ------
        requests.HTTPError
            On API error.
        """
        url = f"{self._base_url}/indexes"
        logger.info("Listing Vectorize indexes for account=%r", self._account_id)
        response = self._session.get(url, timeout=self._timeout)
        self._raise_for_status(response)
        data: dict[str, Any] = response.json()
        return data.get("result", [])

    def delete_index(self, name: str) -> dict[str, Any]:
        """
        Delete a Vectorize index.

        Parameters
        ----------
        name:
            Index name to delete.

        Returns
        -------
        dict
            Parsed JSON response from the Cloudflare API.

        Raises
        ------
        requests.HTTPError
            On API error.
        """
        url = f"{self._base_url}/indexes/{name}"
        logger.info("Deleting Vectorize index name=%r", name)
        response = self._session.delete(url, timeout=self._timeout)
        self._raise_for_status(response)
        return response.json()

    # ------------------------------------------------------------------
    # Internal helpers
    # ------------------------------------------------------------------

    @staticmethod
    def _raise_for_status(response: requests.Response) -> None:
        """Raise ``requests.HTTPError`` with the full response body included."""
        try:
            response.raise_for_status()
        except requests.HTTPError as exc:
            logger.error(
                "Cloudflare API error: status=%d body=%s",
                response.status_code,
                response.text,
            )
            raise


# ---------------------------------------------------------------------------
# Convenience entry point
# ---------------------------------------------------------------------------

def finalize_soil(
    index_name: str,
    description: str = "",
    *,
    account_id: Optional[str] = None,
    api_token: Optional[str] = None,
) -> dict[str, Any]:
    """
    Create the Multimodal-Legacy-1408 Vectorize index.

    Credentials are resolved from *account_id* / *api_token* parameters
    or from the ``CF_ACCOUNT_ID`` / ``CF_API_TOKEN`` environment variables.

    Parameters
    ----------
    index_name:
        Name of the index to create.
    description:
        Human-readable description stored with the index.
    account_id:
        Optional override for ``CF_ACCOUNT_ID``.
    api_token:
        Optional override for ``CF_API_TOKEN``.

    Returns
    -------
    dict
        Parsed JSON response from the Cloudflare API.
    """
    client = VectorizeClient(account_id=account_id, api_token=api_token)
    logger.info("STAMPING SOIL...")
    result = client.create_index(
        index_name,
        dimensions=MULTIMODAL_DIMENSIONS,
        metric="cosine",
        description=description,
    )
    logger.info("CERTIFIED: The irobs-dots are connected.")
    return result


if __name__ == "__main__":
    import sys

    logging.basicConfig(
        level=logging.INFO,
        format="%(asctime)s %(levelname)s %(name)s – %(message)s",
    )

    _index_name = os.environ.get("CF_INDEX_NAME", "Multimodal-Legacy-1408")
    _description = os.environ.get(
        "CF_INDEX_DESCRIPTION",
        "Finalized Legacy Vault for Jada, Emma, Laila, and Ivy Mae",
    )

    try:
        finalize_soil(_index_name, _description)
    except (ValueError, requests.HTTPError) as exc:
        logger.error("Failed to create index: %s", exc)
        sys.exit(1)
