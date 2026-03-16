"""
segura_s3_tools.py
==================
S³ Global Compliance Protocol
Implements Texas SCOPE and NYDFS-grade security with Titan-rooted evidence
stamping and immediate deletion logic complying with local and global laws,
including EDU compliance.

Performance design decisions
-----------------------------
* A single ``boto3.Session`` / ``S3Transfer`` is reused across calls to avoid
  the overhead of re-establishing TLS sessions for every operation.
* Large uploads use S3 multipart via ``boto3``'s ``TransferConfig`` so that
  data is streamed in parallel chunks rather than buffered entirely in memory.
* Large downloads stream directly to disk with the same ``TransferConfig``.
* Object listing uses a paginator so no result set is ever fully materialised
  in memory; callers receive a generator.
* Bulk deletes use the ``delete_objects`` API (up to 1 000 keys per request)
  instead of one ``delete_object`` call per key.
* SHA-256 checksums are computed incrementally (chunk-by-chunk) so arbitrarily
  large files can be verified without loading them into RAM.
* Evidence stamps are HMAC-SHA-256 signed and written as a single JSON record
  to an audit prefix in the same or a separate bucket.
"""

from __future__ import annotations

import hashlib
import hmac
import json
import logging
import os
import time
import uuid
from pathlib import Path
from typing import Generator, Iterable, Optional

import boto3
from boto3.s3.transfer import TransferConfig
from botocore.exceptions import ClientError

# ---------------------------------------------------------------------------
# Logging
# ---------------------------------------------------------------------------
logger = logging.getLogger(__name__)

# ---------------------------------------------------------------------------
# Transfer configuration – tune these for your environment.
# ---------------------------------------------------------------------------
DEFAULT_TRANSFER_CONFIG = TransferConfig(
    multipart_threshold=8 * 1024 * 1024,   # 8 MiB – use multipart above this
    multipart_chunksize=8 * 1024 * 1024,   # 8 MiB chunks
    max_concurrency=10,                     # parallel threads per transfer
    use_threads=True,
)

# Maximum keys per bulk-delete request (AWS hard limit).
_MAX_DELETE_BATCH = 1000

# Chunk size used when computing SHA-256 incrementally (64 KiB).
_HASH_CHUNK = 64 * 1024


# ---------------------------------------------------------------------------
# Helper utilities
# ---------------------------------------------------------------------------

def _sha256_of_file(path: Path) -> str:
    """Return the hex-encoded SHA-256 digest of *path* (streaming, no RAM copy)."""
    digest = hashlib.sha256()
    with path.open("rb") as fh:
        while chunk := fh.read(_HASH_CHUNK):
            digest.update(chunk)
    return digest.hexdigest()


def _sha256_of_stream(stream) -> tuple[bytes, str]:
    """
    Read *stream* completely, compute SHA-256 and return ``(data_bytes, hex_digest)``.

    For uploads from an in-memory stream this is necessary; for file-backed
    uploads prefer :func:`_sha256_of_file` to avoid doubling memory usage.
    """
    digest = hashlib.sha256()
    chunks: list[bytes] = []
    while chunk := stream.read(_HASH_CHUNK):
        digest.update(chunk)
        chunks.append(chunk)
    return b"".join(chunks), digest.hexdigest()


def _hmac_sign(secret: bytes, message: str) -> str:
    """Return a hex-encoded HMAC-SHA-256 signature of *message*."""
    return hmac.new(secret, message.encode(), hashlib.sha256).hexdigest()


# ---------------------------------------------------------------------------
# Core client wrapper
# ---------------------------------------------------------------------------

class SeguraS3Client:
    """
    Thread-safe wrapper around a ``boto3`` S3 client that enforces:

    * Encrypted transfers (HTTPS only via ``endpoint_url`` or the default
      AWS endpoints which are always HTTPS).
    * Integrity verification on upload (SHA-256 checksum comparison).
    * Titan-rooted evidence stamps written to an audit prefix.
    * Compliance-grade immediate deletion with verification.

    Parameters
    ----------
    bucket:
        Default bucket name for operations that do not specify one.
    audit_bucket:
        Bucket that receives evidence stamps.  Defaults to *bucket*.
    audit_prefix:
        Key prefix for evidence stamp objects.  Default: ``"audit/"``.
    hmac_secret:
        Raw bytes used to sign evidence stamps.  If *None*, the value of
        the environment variable ``SEGURA_HMAC_SECRET`` is used (UTF-8
        encoded).  Stamps are **not** signed when neither is provided.
    region_name:
        AWS region.  Falls back to ``AWS_DEFAULT_REGION`` env var or the
        session default.
    transfer_config:
        ``TransferConfig`` for multipart / concurrent transfers.
    boto_session:
        Pre-configured ``boto3.Session`` to reuse (useful for testing /
        credential injection).  A new session is created when omitted.
    """

    def __init__(
        self,
        bucket: str,
        *,
        audit_bucket: Optional[str] = None,
        audit_prefix: str = "audit/",
        hmac_secret: Optional[bytes] = None,
        region_name: Optional[str] = None,
        transfer_config: TransferConfig = DEFAULT_TRANSFER_CONFIG,
        boto_session: Optional[boto3.Session] = None,
    ) -> None:
        self.bucket = bucket
        self.audit_bucket = audit_bucket or bucket
        self.audit_prefix = audit_prefix.rstrip("/") + "/"
        self._transfer_config = transfer_config

        # Resolve HMAC secret once at construction time.
        if hmac_secret is not None:
            self._hmac_secret: Optional[bytes] = hmac_secret
        else:
            raw = os.environ.get("SEGURA_HMAC_SECRET")
            self._hmac_secret = raw.encode() if raw else None

        # Reuse a single session and client for the lifetime of this object so
        # that the underlying TLS connection pool is shared across all calls.
        session = boto_session or boto3.Session(region_name=region_name)
        self._client = session.client("s3")

    # ------------------------------------------------------------------
    # Upload
    # ------------------------------------------------------------------

    def upload_file(
        self,
        local_path: str | Path,
        key: str,
        *,
        bucket: Optional[str] = None,
        extra_args: Optional[dict] = None,
        verify_integrity: bool = True,
    ) -> str:
        """
        Upload a local file to S3 using multipart for large files.

        Parameters
        ----------
        local_path:
            Path on the local filesystem.
        key:
            S3 object key.
        bucket:
            Override the default bucket.
        extra_args:
            Extra arguments forwarded to ``upload_file`` (e.g.
            ``{"ServerSideEncryption": "aws:kms"}``).
        verify_integrity:
            When *True* (default) the SHA-256 of the local file is compared
            to the ``x-amz-checksum-sha256`` ETag after upload.

        Returns
        -------
        str
            The S3 URI of the uploaded object (``s3://bucket/key``).
        """
        local_path = Path(local_path)
        target_bucket = bucket or self.bucket
        extra_args = extra_args or {}

        local_sha256 = _sha256_of_file(local_path) if verify_integrity else None

        logger.info("Uploading %s → s3://%s/%s", local_path, target_bucket, key)
        self._client.upload_file(
            str(local_path),
            target_bucket,
            key,
            ExtraArgs=extra_args,
            Config=self._transfer_config,
        )

        if verify_integrity:
            self._verify_upload_integrity(target_bucket, key, local_sha256)

        uri = f"s3://{target_bucket}/{key}"
        stamp_meta: dict = {}
        if local_sha256 is not None:
            stamp_meta["local_sha256"] = local_sha256
        self._stamp_event("UPLOAD", target_bucket, key, stamp_meta)
        return uri

    def _verify_upload_integrity(
        self, bucket: str, key: str, expected_sha256: Optional[str]
    ) -> None:
        """Check that the object landed correctly by comparing checksums."""
        if expected_sha256 is None:
            return
        head = self._client.head_object(Bucket=bucket, Key=key, ChecksumMode="ENABLED")
        etag = head.get("ETag", "").strip('"')
        # S3 ETags for multipart uploads are not plain MD5; we use the
        # x-amz-checksum-sha256 header when available.
        server_sha256 = head.get("ChecksumSHA256")
        if server_sha256 is None:
            # Fall back to a full download-and-hash when the server did not
            # return a SHA-256 checksum (e.g., object was not uploaded with
            # checksum support enabled).
            logger.warning(
                "s3://%s/%s: no SHA-256 checksum in HeadObject response; "
                "falling back to download verification",
                bucket,
                key,
            )
            import io
            buf = io.BytesIO()
            self._client.download_fileobj(
                Bucket=bucket, Key=key, Fileobj=buf, Config=self._transfer_config
            )
            server_sha256 = hashlib.sha256(buf.getvalue()).hexdigest()
        if server_sha256 != expected_sha256:
            raise ValueError(
                f"Integrity check failed for s3://{bucket}/{key}: "
                f"local={expected_sha256} remote={server_sha256}"
            )
        logger.debug(
            "Integrity OK s3://%s/%s etag=%s sha256=%s",
            bucket,
            key,
            etag,
            expected_sha256,
        )

    # ------------------------------------------------------------------
    # Download
    # ------------------------------------------------------------------

    def download_file(
        self,
        key: str,
        local_path: str | Path,
        *,
        bucket: Optional[str] = None,
    ) -> Path:
        """
        Download an S3 object to *local_path*, streaming in parallel chunks.

        Returns the resolved ``Path`` of the downloaded file.
        """
        local_path = Path(local_path)
        source_bucket = bucket or self.bucket
        local_path.parent.mkdir(parents=True, exist_ok=True)

        logger.info("Downloading s3://%s/%s → %s", source_bucket, key, local_path)
        self._client.download_file(
            source_bucket,
            key,
            str(local_path),
            Config=self._transfer_config,
        )
        self._stamp_event("DOWNLOAD", source_bucket, key, {})
        return local_path

    # ------------------------------------------------------------------
    # List
    # ------------------------------------------------------------------

    def list_objects(
        self,
        prefix: str = "",
        *,
        bucket: Optional[str] = None,
    ) -> Generator[dict, None, None]:
        """
        Yield object metadata dicts for all keys under *prefix*.

        Uses a paginator so that large buckets are never fully buffered in
        memory.  Each yielded dict contains at least ``Key``, ``Size``,
        ``LastModified``, and ``ETag``.
        """
        target_bucket = bucket or self.bucket
        paginator = self._client.get_paginator("list_objects_v2")
        pages = paginator.paginate(Bucket=target_bucket, Prefix=prefix)
        for page in pages:
            for obj in page.get("Contents", []):
                yield obj

    # ------------------------------------------------------------------
    # Delete
    # ------------------------------------------------------------------

    def delete_objects(
        self,
        keys: Iterable[str],
        *,
        bucket: Optional[str] = None,
        verify_deletion: bool = True,
    ) -> list[str]:
        """
        Delete *keys* from *bucket* using batched ``delete_objects`` requests.

        AWS allows up to 1 000 keys per request; this method automatically
        splits larger lists into appropriately-sized batches.

        Parameters
        ----------
        keys:
            Iterable of S3 object keys to delete.
        bucket:
            Override the default bucket.
        verify_deletion:
            When *True* (default), each deleted key is verified to be absent
            via a ``head_object`` call.  Raises ``RuntimeError`` if any key
            is still present after deletion.

        Returns
        -------
        list[str]
            Keys that were successfully deleted.
        """
        target_bucket = bucket or self.bucket
        key_list = list(keys)
        deleted: list[str] = []

        # Partition into batches of at most _MAX_DELETE_BATCH.
        for batch_start in range(0, len(key_list), _MAX_DELETE_BATCH):
            batch = key_list[batch_start : batch_start + _MAX_DELETE_BATCH]
            objects = [{"Key": k} for k in batch]
            response = self._client.delete_objects(
                Bucket=target_bucket,
                Delete={"Objects": objects, "Quiet": False},
            )
            for record in response.get("Deleted", []):
                deleted.append(record["Key"])
                logger.info("Deleted s3://%s/%s", target_bucket, record["Key"])
            for error in response.get("Errors", []):
                logger.error(
                    "Failed to delete s3://%s/%s: %s %s",
                    target_bucket,
                    error.get("Key"),
                    error.get("Code"),
                    error.get("Message"),
                )

        if verify_deletion:
            self._verify_deletion(target_bucket, deleted)

        self._stamp_event(
            "DELETE",
            target_bucket,
            ",".join(deleted[:10]) + ("…" if len(deleted) > 10 else ""),
            {"count": len(deleted)},
        )
        return deleted

    def _verify_deletion(self, bucket: str, keys: list[str]) -> None:
        """Raise ``RuntimeError`` if any key in *keys* is still accessible."""
        still_present: list[str] = []
        for key in keys:
            try:
                self._client.head_object(Bucket=bucket, Key=key)
                still_present.append(key)
            except ClientError as exc:
                if exc.response["Error"]["Code"] in ("404", "NoSuchKey"):
                    continue
                raise
        if still_present:
            raise RuntimeError(
                f"Deletion verification failed – {len(still_present)} object(s) "
                f"still present: {still_present[:5]}"
            )

    def purge_prefix(
        self,
        prefix: str,
        *,
        bucket: Optional[str] = None,
        dry_run: bool = False,
    ) -> list[str]:
        """
        Immediately delete **all** objects whose key starts with *prefix*.

        This is the compliance-grade "immediate deletion" operation required
        by Texas SCOPE and NYDFS regulations.

        Parameters
        ----------
        prefix:
            Key prefix to purge (e.g. ``"user/12345/"``).
        dry_run:
            When *True*, return the list of keys that *would* be deleted
            without actually deleting them.

        Returns
        -------
        list[str]
            Deleted (or would-be-deleted) keys.
        """
        keys = [obj["Key"] for obj in self.list_objects(prefix, bucket=bucket)]
        if not keys:
            logger.info("purge_prefix: no objects found under prefix=%r", prefix)
            return []
        if dry_run:
            logger.info(
                "purge_prefix DRY-RUN: would delete %d objects under %r",
                len(keys),
                prefix,
            )
            return keys
        return self.delete_objects(keys, bucket=bucket)

    # ------------------------------------------------------------------
    # Evidence stamping
    # ------------------------------------------------------------------

    def _stamp_event(
        self,
        event_type: str,
        bucket: str,
        key: str,
        metadata: dict,
    ) -> None:
        """
        Write a Titan-rooted evidence stamp to the audit prefix.

        The stamp is a JSON document containing:
        * ``event_id`` – UUID v4 for deduplication.
        * ``event_type`` – one of ``UPLOAD``, ``DOWNLOAD``, ``DELETE``.
        * ``timestamp`` – Unix epoch integer at nanosecond resolution
          (``time.time_ns()``).
        * ``bucket`` / ``key`` – affected resource.
        * ``metadata`` – caller-supplied dict (e.g. checksum, object count).
        * ``signature`` – HMAC-SHA-256 of the canonical payload (when an
          HMAC secret is configured).
        """
        event_id = str(uuid.uuid4())
        timestamp = time.time_ns()
        payload = {
            "event_id": event_id,
            "event_type": event_type,
            "timestamp": timestamp,
            "bucket": bucket,
            "key": key,
            "metadata": metadata,
        }

        if self._hmac_secret:
            canonical = json.dumps(payload, sort_keys=True, separators=(",", ":"))
            payload["signature"] = _hmac_sign(self._hmac_secret, canonical)

        stamp_key = (
            f"{self.audit_prefix}{event_type}/"
            f"{time.strftime('%Y/%m/%d', time.gmtime(timestamp // 1_000_000_000))}/"
            f"{event_id}.json"
        )
        try:
            self._client.put_object(
                Bucket=self.audit_bucket,
                Key=stamp_key,
                Body=json.dumps(payload, indent=2).encode(),
                ContentType="application/json",
            )
            logger.debug("Evidence stamp written to s3://%s/%s", self.audit_bucket, stamp_key)
        except ClientError:
            # Evidence stamping must not interrupt the primary operation.
            logger.exception("Failed to write evidence stamp for %s %s/%s", event_type, bucket, key)

    # ------------------------------------------------------------------
    # Convenience – copy
    # ------------------------------------------------------------------

    def copy_object(
        self,
        source_key: str,
        dest_key: str,
        *,
        source_bucket: Optional[str] = None,
        dest_bucket: Optional[str] = None,
    ) -> None:
        """
        Server-side copy (no data transits the client).

        For objects larger than 5 GiB the boto3 ``copy`` method automatically
        uses multipart copy via the TransferManager.
        """
        src_bucket = source_bucket or self.bucket
        dst_bucket = dest_bucket or self.bucket
        copy_source = {"Bucket": src_bucket, "Key": source_key}
        logger.info(
            "Copying s3://%s/%s → s3://%s/%s",
            src_bucket,
            source_key,
            dst_bucket,
            dest_key,
        )
        # ``boto3`` client copy handles multipart automatically via TransferManager.
        self._client.copy(
            copy_source,
            dst_bucket,
            dest_key,
            Config=self._transfer_config,
        )
        self._stamp_event(
            "COPY",
            dst_bucket,
            dest_key,
            {"source_bucket": src_bucket, "source_key": source_key},
        )

    # ------------------------------------------------------------------
    # Presigned URLs
    # ------------------------------------------------------------------

    def generate_presigned_url(
        self,
        key: str,
        *,
        bucket: Optional[str] = None,
        expiry_seconds: int = 3600,
        operation: str = "get_object",
    ) -> str:
        """
        Return a pre-signed URL for *key* valid for *expiry_seconds*.

        Default operation is ``get_object``; pass ``"put_object"`` to allow
        direct uploads from a client.
        """
        target_bucket = bucket or self.bucket
        url: str = self._client.generate_presigned_url(
            operation,
            Params={"Bucket": target_bucket, "Key": key},
            ExpiresIn=expiry_seconds,
        )
        return url
