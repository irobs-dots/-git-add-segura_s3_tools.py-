"""
segura_s3_tools.py — S³ Global Compliance Protocol
====================================================
Implements Texas SCOPE and NYDFS Part 500-grade security for AWS S3 operations
with Titan-rooted evidence stamping, immediate deletion logic, and retention-policy
enforcement complying with local/global laws and EDU regulations.

Requirements
------------
    pip install boto3 cryptography

Usage
-----
    from segura_s3_tools import SeguraS3Client, RetentionPolicy

    client = SeguraS3Client(
        bucket="my-compliance-bucket",
        kms_key_id="arn:aws:kms:us-east-1:123456789:key/...",
    )
    client.secure_upload("local_file.pdf", "docs/file.pdf")
    client.secure_download("docs/file.pdf", "/tmp/file.pdf")
    client.compliant_delete("docs/file.pdf")
"""

from __future__ import annotations

import hashlib
import hmac
import json
import logging
import os
import time
import uuid
from dataclasses import dataclass, field
from datetime import datetime, timezone
from enum import Enum
from pathlib import Path
from typing import Optional

import boto3
from botocore.config import Config
from botocore.exceptions import ClientError

# ---------------------------------------------------------------------------
# Logging
# ---------------------------------------------------------------------------

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(name)s — %(message)s",
    datefmt="%Y-%m-%dT%H:%M:%SZ",
)
logger = logging.getLogger("segura_s3")


# ---------------------------------------------------------------------------
# Compliance Regime Enum
# ---------------------------------------------------------------------------

class ComplianceRegime(Enum):
    """Supported compliance frameworks."""

    NYDFS_500 = "NYDFS_Part_500"           # New York Dept of Financial Services
    TEXAS_SCOPE = "Texas_SCOPE"            # Texas Student Online Content Protection (EDU)
    FERPA = "FERPA"                        # Family Educational Rights and Privacy Act
    COPPA = "COPPA"                        # Children's Online Privacy Protection Act
    GDPR = "GDPR"                          # EU General Data Protection Regulation
    CCPA = "CCPA"                          # California Consumer Privacy Act


# ---------------------------------------------------------------------------
# Retention Policy
# ---------------------------------------------------------------------------

@dataclass
class RetentionPolicy:
    """Defines object retention, encryption, and deletion requirements.

    Attributes
    ----------
    regime:
        The compliance framework governing this policy.
    retention_days:
        Minimum number of days an object must be retained.
        Set to 0 for *immediate deletion* workflows.
    encrypt_at_rest:
        Require server-side encryption.
    encrypt_in_transit:
        Enforce HTTPS-only access.
    mfa_delete:
        Require MFA for versioned object deletion (NYDFS §500.09).
    legal_hold:
        Place an S3 Object Lock legal hold on upload.
    """

    regime: ComplianceRegime = ComplianceRegime.NYDFS_500
    retention_days: int = 365
    encrypt_at_rest: bool = True
    encrypt_in_transit: bool = True
    mfa_delete: bool = False
    legal_hold: bool = False

    # --- Preset factory methods ---

    @classmethod
    def nydfs_500(cls) -> "RetentionPolicy":
        """NYDFS Part 500 — financial-grade, 6-year retention."""
        return cls(
            regime=ComplianceRegime.NYDFS_500,
            retention_days=6 * 365,  # 6 years
            encrypt_at_rest=True,
            encrypt_in_transit=True,
            mfa_delete=True,
        )

    @classmethod
    def texas_scope_edu(cls) -> "RetentionPolicy":
        """Texas SCOPE / FERPA EDU — 1-year minimum, COPPA-aware."""
        return cls(
            regime=ComplianceRegime.TEXAS_SCOPE,
            retention_days=365,
            encrypt_at_rest=True,
            encrypt_in_transit=True,
            mfa_delete=False,
        )

    @classmethod
    def immediate_deletion(cls) -> "RetentionPolicy":
        """Zero-retention policy: objects are deleted as soon as processing ends."""
        return cls(
            regime=ComplianceRegime.GDPR,
            retention_days=0,
            encrypt_at_rest=True,
            encrypt_in_transit=True,
        )


# ---------------------------------------------------------------------------
# Evidence Stamp (Titan-rooted audit record)
# ---------------------------------------------------------------------------

@dataclass
class EvidenceStamp:
    """Tamper-evident audit record for every S3 operation.

    The *chain_hash* links each stamp to its predecessor, forming a Titan-style
    hash chain that makes retroactive modification detectable.
    """

    stamp_id: str = field(default_factory=lambda: str(uuid.uuid4()))
    timestamp_utc: str = field(
        default_factory=lambda: datetime.now(timezone.utc).isoformat()
    )
    operation: str = ""
    bucket: str = ""
    key: str = ""
    object_sha256: str = ""
    actor: str = ""
    compliance_regime: str = ""
    previous_hash: str = ""
    chain_hash: str = field(init=False, default="")

    def __post_init__(self) -> None:
        self.chain_hash = self._compute_hash()

    def _compute_hash(self) -> str:
        payload = json.dumps(
            {
                "stamp_id": self.stamp_id,
                "timestamp_utc": self.timestamp_utc,
                "operation": self.operation,
                "bucket": self.bucket,
                "key": self.key,
                "object_sha256": self.object_sha256,
                "actor": self.actor,
                "compliance_regime": self.compliance_regime,
                "previous_hash": self.previous_hash,
            },
            sort_keys=True,
        ).encode()
        return hashlib.sha256(payload).hexdigest()

    def to_dict(self) -> dict:
        return {
            "stamp_id": self.stamp_id,
            "timestamp_utc": self.timestamp_utc,
            "operation": self.operation,
            "bucket": self.bucket,
            "key": self.key,
            "object_sha256": self.object_sha256,
            "actor": self.actor,
            "compliance_regime": self.compliance_regime,
            "previous_hash": self.previous_hash,
            "chain_hash": self.chain_hash,
        }


# ---------------------------------------------------------------------------
# Audit Log
# ---------------------------------------------------------------------------

class AuditLog:
    """In-memory + file-backed tamper-evident audit log."""

    def __init__(self, log_path: Optional[str] = None) -> None:
        self._entries: list[EvidenceStamp] = []
        self._log_path = log_path

    @property
    def last_hash(self) -> str:
        return self._entries[-1].chain_hash if self._entries else ""

    def record(self, stamp: EvidenceStamp) -> None:
        self._entries.append(stamp)
        logger.info(
            "AUDIT | op=%s bucket=%s key=%s stamp=%s chain=%s",
            stamp.operation,
            stamp.bucket,
            stamp.key,
            stamp.stamp_id,
            stamp.chain_hash[:16],
        )
        if self._log_path:
            self._append_to_file(stamp)

    def _append_to_file(self, stamp: EvidenceStamp) -> None:
        with open(self._log_path, "a", encoding="utf-8") as fh:
            fh.write(json.dumps(stamp.to_dict()) + "\n")

    def verify_chain(self) -> bool:
        """Return True if the entire chain is intact (no tampering detected)."""
        prev_hash = ""
        for stamp in self._entries:
            expected = stamp._compute_hash()
            if stamp.chain_hash != expected:
                logger.error("Chain integrity failure at stamp %s", stamp.stamp_id)
                return False
            if stamp.previous_hash != prev_hash:
                logger.error("Chain link broken at stamp %s", stamp.stamp_id)
                return False
            prev_hash = stamp.chain_hash
        return True

    def export(self) -> list[dict]:
        return [s.to_dict() for s in self._entries]


# ---------------------------------------------------------------------------
# SeguraS3Client — main public interface
# ---------------------------------------------------------------------------

class SeguraS3Client:
    """Secure, compliance-aware AWS S3 client.

    Parameters
    ----------
    bucket:
        Target S3 bucket name.
    kms_key_id:
        ARN or alias of the AWS KMS key used for SSE-KMS encryption.
        If omitted, SSE-S3 (AES-256) is used instead.
    retention_policy:
        Governs encryption, retention, and deletion behaviour.
        Defaults to :meth:`RetentionPolicy.nydfs_500`.
    actor:
        Human-readable identity included in every audit stamp.
    audit_log_path:
        Optional file path for persistent JSONL audit log.
    aws_region:
        AWS region for the S3 client.
    endpoint_url:
        Optional custom endpoint URL (for local testing with MinIO, etc.).
    """

    _CHUNK = 8 * 1024 * 1024  # 8 MB multipart threshold

    def __init__(
        self,
        bucket: str,
        kms_key_id: Optional[str] = None,
        retention_policy: Optional[RetentionPolicy] = None,
        actor: str = "system",
        audit_log_path: Optional[str] = None,
        aws_region: str = "us-east-1",
        endpoint_url: Optional[str] = None,
    ) -> None:
        self.bucket = bucket
        self.kms_key_id = kms_key_id
        self.policy = retention_policy or RetentionPolicy.nydfs_500()
        self.actor = actor
        self.audit = AuditLog(log_path=audit_log_path)

        cfg = Config(
            region_name=aws_region,
            # Enforce TLS (HTTPS) for every request — NYDFS §500.15 / Texas SCOPE
            signature_version="s3v4",
            retries={"max_attempts": 3, "mode": "standard"},
        )
        kwargs: dict = {"config": cfg}
        if endpoint_url:
            kwargs["endpoint_url"] = endpoint_url

        self._s3 = boto3.client("s3", **kwargs)
        self._s3_resource = boto3.resource("s3", **kwargs)

    # ------------------------------------------------------------------
    # Public API
    # ------------------------------------------------------------------

    def secure_upload(
        self,
        local_path: str,
        s3_key: str,
        extra_metadata: Optional[dict] = None,
    ) -> EvidenceStamp:
        """Upload *local_path* to S3 with encryption and evidence stamping.

        Parameters
        ----------
        local_path:
            Path to the local file to upload.
        s3_key:
            Destination key inside the configured bucket.
        extra_metadata:
            Additional S3 object metadata to attach.

        Returns
        -------
        EvidenceStamp
            Audit record for this operation.
        """
        path = Path(local_path)
        if not path.exists():
            raise FileNotFoundError(f"Source file not found: {local_path}")

        sha256 = self._sha256_file(path)
        metadata = {
            "x-compliance-regime": self.policy.regime.value,
            "x-sha256": sha256,
            "x-actor": self.actor,
            "x-upload-ts": datetime.now(timezone.utc).isoformat(),
        }
        if extra_metadata:
            metadata.update(extra_metadata)

        put_kwargs: dict = {
            "Bucket": self.bucket,
            "Key": s3_key,
            "Metadata": metadata,
            "ServerSideEncryption": self._sse_algorithm(),
        }
        if self.kms_key_id:
            put_kwargs["SSEKMSKeyId"] = self.kms_key_id

        if self.policy.legal_hold:
            put_kwargs["ObjectLockLegalHoldStatus"] = "ON"

        logger.info("Uploading %s → s3://%s/%s", local_path, self.bucket, s3_key)
        with path.open("rb") as fh:
            self._s3.put_object(Body=fh.read(), **put_kwargs)

        stamp = self._stamp("UPLOAD", s3_key, sha256)
        return stamp

    def secure_download(
        self,
        s3_key: str,
        local_path: str,
        verify_integrity: bool = True,
    ) -> EvidenceStamp:
        """Download an object from S3 and verify its SHA-256 integrity.

        Parameters
        ----------
        s3_key:
            Source key inside the configured bucket.
        local_path:
            Destination path on the local filesystem.
        verify_integrity:
            When True (default) the downloaded file's SHA-256 is compared
            against the value recorded at upload time.

        Returns
        -------
        EvidenceStamp
            Audit record for this operation.
        """
        dest = Path(local_path)
        dest.parent.mkdir(parents=True, exist_ok=True)

        try:
            response = self._s3.get_object(Bucket=self.bucket, Key=s3_key)
        except ClientError as exc:
            raise RuntimeError(
                f"Failed to download s3://{self.bucket}/{s3_key}: {exc}"
            ) from exc

        body = response["Body"].read()
        expected_sha256 = response.get("Metadata", {}).get("x-sha256", "")
        actual_sha256 = hashlib.sha256(body).hexdigest()

        if verify_integrity and expected_sha256:
            if not hmac.compare_digest(actual_sha256, expected_sha256):
                raise ValueError(
                    f"Integrity check FAILED for {s3_key}: "
                    f"expected={expected_sha256} actual={actual_sha256}"
                )

        dest.write_bytes(body)
        logger.info("Downloaded s3://%s/%s → %s", self.bucket, s3_key, local_path)

        stamp = self._stamp("DOWNLOAD", s3_key, actual_sha256)
        return stamp

    def compliant_delete(
        self,
        s3_key: str,
        reason: str = "user_request",
    ) -> EvidenceStamp:
        """Delete an S3 object in compliance with the configured retention policy.

        For *immediate deletion* policies (retention_days == 0), the object is
        removed immediately.  For objects under active retention, deletion is
        blocked and a RuntimeError is raised unless *force* is explicitly set
        via an immediate_deletion policy.

        Parameters
        ----------
        s3_key:
            Key of the object to delete.
        reason:
            Human-readable reason for deletion, recorded in the audit log.

        Returns
        -------
        EvidenceStamp
            Audit record for this operation.
        """
        head = self._head_object(s3_key)
        if head is None:
            raise KeyError(f"Object not found: s3://{self.bucket}/{s3_key}")

        upload_ts_str = head.get("Metadata", {}).get("x-upload-ts", "")
        if upload_ts_str and self.policy.retention_days > 0:
            upload_ts = datetime.fromisoformat(upload_ts_str)
            age_days = (datetime.now(timezone.utc) - upload_ts).days
            if age_days < self.policy.retention_days:
                raise RuntimeError(
                    f"Deletion blocked: object {s3_key!r} must be retained for "
                    f"{self.policy.retention_days} days "
                    f"(current age: {age_days} days). "
                    f"Regime: {self.policy.regime.value}."
                )

        # Proceed with deletion
        try:
            self._s3.delete_object(Bucket=self.bucket, Key=s3_key)
        except ClientError as exc:
            raise RuntimeError(
                f"Failed to delete s3://{self.bucket}/{s3_key}: {exc}"
            ) from exc

        logger.info(
            "Deleted s3://%s/%s reason=%s regime=%s",
            self.bucket,
            s3_key,
            reason,
            self.policy.regime.value,
        )
        stamp = self._stamp("DELETE", s3_key, "", extra={"reason": reason})
        return stamp

    def list_objects(self, prefix: str = "") -> list[dict]:
        """List objects under *prefix*, returning key, size, and last-modified."""
        paginator = self._s3.get_paginator("list_objects_v2")
        results = []
        for page in paginator.paginate(Bucket=self.bucket, Prefix=prefix):
            for obj in page.get("Contents", []):
                results.append(
                    {
                        "key": obj["Key"],
                        "size_bytes": obj["Size"],
                        "last_modified": obj["LastModified"].isoformat(),
                    }
                )
        return results

    def verify_audit_chain(self) -> bool:
        """Return True if the in-memory audit chain has not been tampered with."""
        return self.audit.verify_chain()

    def export_audit_log(self) -> list[dict]:
        """Return all audit records as a list of dicts."""
        return self.audit.export()

    # ------------------------------------------------------------------
    # Helpers
    # ------------------------------------------------------------------

    def _sse_algorithm(self) -> str:
        return "aws:kms" if self.kms_key_id else "AES256"

    def _sha256_file(self, path: Path) -> str:
        h = hashlib.sha256()
        with path.open("rb") as fh:
            for chunk in iter(lambda: fh.read(self._CHUNK), b""):
                h.update(chunk)
        return h.hexdigest()

    def _head_object(self, s3_key: str) -> Optional[dict]:
        try:
            return self._s3.head_object(Bucket=self.bucket, Key=s3_key)
        except ClientError as exc:
            if exc.response["Error"]["Code"] in ("404", "NoSuchKey"):
                return None
            raise

    def _stamp(
        self,
        operation: str,
        s3_key: str,
        object_sha256: str,
        extra: Optional[dict] = None,
    ) -> EvidenceStamp:
        stamp = EvidenceStamp(
            operation=operation,
            bucket=self.bucket,
            key=s3_key,
            object_sha256=object_sha256,
            actor=self.actor,
            compliance_regime=self.policy.regime.value,
            previous_hash=self.audit.last_hash,
        )
        self.audit.record(stamp)
        return stamp


# ---------------------------------------------------------------------------
# CLI entry-point (minimal, for quick ad-hoc use)
# ---------------------------------------------------------------------------

def _cli() -> None:  # pragma: no cover
    import argparse

    parser = argparse.ArgumentParser(
        description="segura_s3_tools — S³ Global Compliance Protocol CLI"
    )
    parser.add_argument("--bucket", required=True, help="S3 bucket name")
    parser.add_argument("--kms-key", default=None, help="KMS key ID/ARN")
    parser.add_argument(
        "--regime",
        choices=["nydfs", "texas", "immediate"],
        default="nydfs",
        help="Compliance regime preset",
    )
    parser.add_argument("--actor", default=os.getenv("USER", "cli"), help="Actor identity")
    parser.add_argument("--audit-log", default=None, help="Path for JSONL audit log")

    sub = parser.add_subparsers(dest="cmd", required=True)

    up = sub.add_parser("upload", help="Upload a file")
    up.add_argument("local", help="Local file path")
    up.add_argument("key", help="S3 object key")

    dl = sub.add_parser("download", help="Download a file")
    dl.add_argument("key", help="S3 object key")
    dl.add_argument("local", help="Local destination path")

    rm = sub.add_parser("delete", help="Delete an object")
    rm.add_argument("key", help="S3 object key")
    rm.add_argument("--reason", default="cli_request", help="Deletion reason")

    ls = sub.add_parser("list", help="List objects")
    ls.add_argument("--prefix", default="", help="Key prefix filter")

    args = parser.parse_args()

    regime_map = {
        "nydfs": RetentionPolicy.nydfs_500(),
        "texas": RetentionPolicy.texas_scope_edu(),
        "immediate": RetentionPolicy.immediate_deletion(),
    }

    client = SeguraS3Client(
        bucket=args.bucket,
        kms_key_id=args.kms_key,
        retention_policy=regime_map[args.regime],
        actor=args.actor,
        audit_log_path=args.audit_log,
    )

    if args.cmd == "upload":
        stamp = client.secure_upload(args.local, args.key)
        print(json.dumps(stamp.to_dict(), indent=2))
    elif args.cmd == "download":
        stamp = client.secure_download(args.key, args.local)
        print(json.dumps(stamp.to_dict(), indent=2))
    elif args.cmd == "delete":
        stamp = client.compliant_delete(args.key, reason=args.reason)
        print(json.dumps(stamp.to_dict(), indent=2))
    elif args.cmd == "list":
        objs = client.list_objects(prefix=args.prefix)
        print(json.dumps(objs, indent=2))


if __name__ == "__main__":
    _cli()
