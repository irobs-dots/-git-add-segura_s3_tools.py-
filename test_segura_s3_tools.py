"""
Tests for segura_s3_tools.py — S³ Global Compliance Protocol.

Run with:  pytest test_segura_s3_tools.py -v
"""

from __future__ import annotations

import hashlib
import json
import os
import tempfile
from datetime import datetime, timedelta, timezone
from unittest.mock import MagicMock, patch

import pytest

from segura_s3_tools import (
    AuditLog,
    ComplianceRegime,
    EvidenceStamp,
    RetentionPolicy,
    SeguraS3Client,
)


# ---------------------------------------------------------------------------
# RetentionPolicy
# ---------------------------------------------------------------------------

class TestRetentionPolicy:
    def test_nydfs_preset(self):
        p = RetentionPolicy.nydfs_500()
        assert p.regime == ComplianceRegime.NYDFS_500
        assert p.retention_days == 2190
        assert p.encrypt_at_rest is True
        assert p.encrypt_in_transit is True
        assert p.mfa_delete is True

    def test_texas_scope_preset(self):
        p = RetentionPolicy.texas_scope_edu()
        assert p.regime == ComplianceRegime.TEXAS_SCOPE
        assert p.retention_days == 365
        assert p.encrypt_at_rest is True

    def test_immediate_deletion_preset(self):
        p = RetentionPolicy.immediate_deletion()
        assert p.retention_days == 0
        assert p.encrypt_at_rest is True


# ---------------------------------------------------------------------------
# EvidenceStamp
# ---------------------------------------------------------------------------

class TestEvidenceStamp:
    def test_chain_hash_is_set(self):
        s = EvidenceStamp(
            operation="UPLOAD",
            bucket="b",
            key="k",
            object_sha256="abc123",
            actor="tester",
            compliance_regime="NYDFS",
            previous_hash="",
        )
        assert len(s.chain_hash) == 64  # SHA-256 hex digest

    def test_chain_link(self):
        s1 = EvidenceStamp(operation="UPLOAD", bucket="b", key="k",
                           object_sha256="a", actor="x", compliance_regime="X",
                           previous_hash="")
        s2 = EvidenceStamp(operation="DELETE", bucket="b", key="k",
                           object_sha256="", actor="x", compliance_regime="X",
                           previous_hash=s1.chain_hash)
        assert s2.previous_hash == s1.chain_hash

    def test_to_dict_keys(self):
        s = EvidenceStamp(operation="DOWNLOAD", bucket="b", key="k",
                          object_sha256="z", actor="a", compliance_regime="Y",
                          previous_hash="")
        d = s.to_dict()
        for key in ("stamp_id", "timestamp_utc", "operation", "bucket",
                    "key", "object_sha256", "actor", "compliance_regime",
                    "previous_hash", "chain_hash"):
            assert key in d

    def test_deterministic_hash_same_inputs(self):
        """Two stamps with identical fields (same stamp_id, ts) must produce same hash."""
        kwargs = dict(
            operation="UPLOAD", bucket="b", key="k", object_sha256="abc",
            actor="u", compliance_regime="N", previous_hash="",
        )
        s1 = EvidenceStamp(**kwargs)
        # Override stamp_id and timestamp to match
        s2 = EvidenceStamp(**kwargs)
        s2.stamp_id = s1.stamp_id
        s2.timestamp_utc = s1.timestamp_utc
        s2.chain_hash = s2._compute_hash()
        assert s1.chain_hash == s2.chain_hash


# ---------------------------------------------------------------------------
# AuditLog
# ---------------------------------------------------------------------------

class TestAuditLog:
    def _make_stamp(self, op: str, prev: str = "") -> EvidenceStamp:
        return EvidenceStamp(
            operation=op, bucket="b", key="k",
            object_sha256="x", actor="a", compliance_regime="N",
            previous_hash=prev,
        )

    def test_verify_chain_empty(self):
        log = AuditLog()
        assert log.verify_chain() is True

    def test_verify_chain_valid(self):
        log = AuditLog()
        s1 = self._make_stamp("UPLOAD")
        s2 = self._make_stamp("DOWNLOAD", prev=s1.chain_hash)
        log.record(s1)
        log.record(s2)
        assert log.verify_chain() is True

    def test_tamper_detection(self):
        log = AuditLog()
        s1 = self._make_stamp("UPLOAD")
        log.record(s1)
        log._entries[0].operation = "TAMPERED"  # direct mutation
        assert log.verify_chain() is False

    def test_last_hash_empty_log(self):
        log = AuditLog()
        assert log.last_hash == ""

    def test_last_hash_populated(self):
        log = AuditLog()
        s = self._make_stamp("UPLOAD")
        log.record(s)
        assert log.last_hash == s.chain_hash

    def test_file_backed_log(self, tmp_path):
        log_file = str(tmp_path / "audit.jsonl")
        log = AuditLog(log_path=log_file)
        s = self._make_stamp("UPLOAD")
        log.record(s)
        with open(log_file) as fh:
            line = fh.readline()

        data = json.loads(line)
        assert data["operation"] == "UPLOAD"
        assert "chain_hash" in data

    def test_export(self):
        log = AuditLog()
        s = self._make_stamp("DELETE")
        log.record(s)
        exported = log.export()
        assert len(exported) == 1
        assert exported[0]["operation"] == "DELETE"


# ---------------------------------------------------------------------------
# SeguraS3Client (mocked boto3)
# ---------------------------------------------------------------------------

@pytest.fixture()
def mock_s3(tmp_path):
    """Return a SeguraS3Client with boto3 fully mocked."""
    with patch("segura_s3_tools.boto3") as mock_boto:
        mock_client = MagicMock()
        mock_resource = MagicMock()
        mock_boto.client.return_value = mock_client
        mock_boto.resource.return_value = mock_resource
        policy = RetentionPolicy.immediate_deletion()
        client = SeguraS3Client(
            bucket="test-bucket",
            retention_policy=policy,
            actor="pytest",
            audit_log_path=str(tmp_path / "audit.jsonl"),
        )
        client._s3 = mock_client
        yield client, mock_client


class TestSeguraS3ClientUpload:
    def test_upload_success(self, mock_s3, tmp_path):
        client, s3_mock = mock_s3
        test_file = tmp_path / "sample.txt"
        test_file.write_bytes(b"hello compliance world")

        s3_mock.put_object.return_value = {}
        stamp = client.secure_upload(str(test_file), "docs/sample.txt")

        s3_mock.put_object.assert_called_once()
        call_kwargs = s3_mock.put_object.call_args[1]
        assert call_kwargs["Bucket"] == "test-bucket"
        assert call_kwargs["Key"] == "docs/sample.txt"
        assert call_kwargs["ServerSideEncryption"] == "AES256"
        assert stamp.operation == "UPLOAD"

    def test_upload_missing_file(self, mock_s3):
        client, _ = mock_s3
        with pytest.raises(FileNotFoundError):
            client.secure_upload("/nonexistent/file.txt", "key")

    def test_upload_sha256_in_metadata(self, mock_s3, tmp_path):
        client, s3_mock = mock_s3
        data = b"test data for sha256"
        f = tmp_path / "f.bin"
        f.write_bytes(data)
        expected_sha = hashlib.sha256(data).hexdigest()

        s3_mock.put_object.return_value = {}
        client.secure_upload(str(f), "k")

        meta = s3_mock.put_object.call_args[1]["Metadata"]
        assert meta["x-sha256"] == expected_sha

    def test_upload_kms_key(self, tmp_path):
        with patch("segura_s3_tools.boto3") as mock_boto:
            mock_client = MagicMock()
            mock_boto.client.return_value = mock_client
            mock_boto.resource.return_value = MagicMock()
            c = SeguraS3Client(
                bucket="b", kms_key_id="arn:aws:kms:us-east-1:123:key/abc",
                retention_policy=RetentionPolicy.immediate_deletion(),
            )
            c._s3 = mock_client
            mock_client.put_object.return_value = {}
            f = tmp_path / "x.txt"
            f.write_bytes(b"data")
            c.secure_upload(str(f), "x.txt")
            kwargs = mock_client.put_object.call_args[1]
            assert kwargs["ServerSideEncryption"] == "aws:kms"
            assert "SSEKMSKeyId" in kwargs


class TestSeguraS3ClientDownload:
    def test_download_success(self, mock_s3, tmp_path):
        client, s3_mock = mock_s3
        data = b"downloaded content"
        sha = hashlib.sha256(data).hexdigest()
        s3_mock.get_object.return_value = {
            "Body": MagicMock(read=lambda: data),
            "Metadata": {"x-sha256": sha},
        }
        dest = str(tmp_path / "out.txt")
        stamp = client.secure_download("docs/sample.txt", dest)
        assert stamp.operation == "DOWNLOAD"
        assert open(dest, "rb").read() == data

    def test_download_integrity_failure(self, mock_s3, tmp_path):
        client, s3_mock = mock_s3
        data = b"real data"
        s3_mock.get_object.return_value = {
            "Body": MagicMock(read=lambda: data),
            "Metadata": {"x-sha256": "deadbeef" * 8},
        }
        with pytest.raises(ValueError, match="Integrity check FAILED"):
            client.secure_download("k", str(tmp_path / "out"))

    def test_download_skip_integrity(self, mock_s3, tmp_path):
        client, s3_mock = mock_s3
        data = b"data"
        s3_mock.get_object.return_value = {
            "Body": MagicMock(read=lambda: data),
            "Metadata": {"x-sha256": "wronghash"},
        }
        # Should NOT raise when verify_integrity=False
        client.secure_download("k", str(tmp_path / "out"), verify_integrity=False)


class TestSeguraS3ClientDelete:
    def _head_response(self, days_old: int = 400) -> dict:
        ts = (datetime.now(timezone.utc) - timedelta(days=days_old)).isoformat()
        return {"Metadata": {"x-upload-ts": ts}}

    def test_delete_old_object_immediate_policy(self, mock_s3):
        """Immediate deletion policy should always allow deletion."""
        client, s3_mock = mock_s3
        s3_mock.head_object.return_value = self._head_response(days_old=0)
        s3_mock.delete_object.return_value = {}
        stamp = client.compliant_delete("k")
        assert stamp.operation == "DELETE"
        s3_mock.delete_object.assert_called_once_with(Bucket="test-bucket", Key="k")

    def test_delete_blocked_by_retention(self, tmp_path):
        """NYDFS policy should block deletion of a 1-day-old object."""
        with patch("segura_s3_tools.boto3") as mock_boto:
            mock_client = MagicMock()
            mock_boto.client.return_value = mock_client
            mock_boto.resource.return_value = MagicMock()
            c = SeguraS3Client(
                bucket="b", retention_policy=RetentionPolicy.nydfs_500()
            )
            c._s3 = mock_client
            ts = (datetime.now(timezone.utc) - timedelta(days=1)).isoformat()
            mock_client.head_object.return_value = {"Metadata": {"x-upload-ts": ts}}
            with pytest.raises(RuntimeError, match="Deletion blocked"):
                c.compliant_delete("k")

    def test_delete_object_not_found(self, mock_s3):
        client, s3_mock = mock_s3
        s3_mock.head_object.side_effect = _make_client_error("404")
        with pytest.raises(KeyError):
            client.compliant_delete("missing-key")

    def test_delete_audit_stamp(self, mock_s3):
        client, s3_mock = mock_s3
        s3_mock.head_object.return_value = self._head_response()
        s3_mock.delete_object.return_value = {}
        stamp = client.compliant_delete("k", reason="gdpr_erasure")
        exported = client.export_audit_log()
        assert any(e["operation"] == "DELETE" for e in exported)


# ---------------------------------------------------------------------------
# Audit chain across multiple operations
# ---------------------------------------------------------------------------

class TestAuditChainIntegration:
    def test_chain_after_multiple_ops(self, mock_s3, tmp_path):
        client, s3_mock = mock_s3

        # Upload
        f = tmp_path / "f.txt"
        f.write_bytes(b"data")
        s3_mock.put_object.return_value = {}
        client.secure_upload(str(f), "f.txt")

        # Download
        data = b"data"
        sha = hashlib.sha256(data).hexdigest()
        s3_mock.get_object.return_value = {
            "Body": MagicMock(read=lambda: data),
            "Metadata": {"x-sha256": sha},
        }
        client.secure_download("f.txt", str(tmp_path / "out.txt"))

        # Delete (immediate policy)
        ts = datetime.now(timezone.utc).isoformat()
        s3_mock.head_object.return_value = {"Metadata": {"x-upload-ts": ts}}
        s3_mock.delete_object.return_value = {}
        client.compliant_delete("f.txt")

        assert client.verify_audit_chain() is True
        log = client.export_audit_log()
        ops = [e["operation"] for e in log]
        assert ops == ["UPLOAD", "DOWNLOAD", "DELETE"]


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _make_client_error(code: str):
    from botocore.exceptions import ClientError
    return ClientError(
        error_response={"Error": {"Code": code, "Message": "Not Found"}},
        operation_name="HeadObject",
    )
