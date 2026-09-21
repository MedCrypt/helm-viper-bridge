#!/usr/bin/env python3
"""
Tests for the /api/external-vuln-sync endpoint and its background task.
"""

import sys
import os
import math
import json
from unittest.mock import patch, MagicMock

import pytest

# Ensure project root is on sys.path
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from fastapi.testclient import TestClient


# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------

FAKE_INTERNAL_KEY = "test-internal-key-12345"
FAKE_EXTERNAL_KEY = "test-external-key-67890"


@pytest.fixture(autouse=True)
def _env_vars(monkeypatch):
    """Set required environment variables for every test."""
    monkeypatch.setenv("HELM_CLIENT_ID", "fake_helm_id")
    monkeypatch.setenv("HELM_CLIENT_SECRET", "fake_helm_secret")
    monkeypatch.setenv("VIPER_API_KEY", "fake_viper_key")


def _patch_middleware():
    """Patch rate_limit_middleware to be a no-op (avoids request.client being None in TestClient)."""
    return patch("fastapi_server.rate_limit_middleware", new=None)


@pytest.fixture()
def client():
    """
    Return a TestClient with verify_api_key overridden to accept our fake keys,
    and the background task mocked out so it doesn't run.
    """
    from fastapi_server import app, verify_api_key

    # Override auth dependency
    app.dependency_overrides[verify_api_key] = lambda: ("internal", FAKE_INTERNAL_KEY)

    # Replace the middleware to avoid request.client.host crash
    # Save and restore original middleware stack
    original_middleware = app.middleware_stack
    app.middleware_stack = None  # force rebuild

    try:
        with patch("fastapi_server._run_external_vuln_sync"), \
             patch("fastapi_server.check_rate_limit", return_value=True):
            # Rebuild middleware stack by creating TestClient
            c = TestClient(app)
            yield c
    finally:
        app.dependency_overrides.clear()
        app.middleware_stack = original_middleware


@pytest.fixture()
def client_external():
    """TestClient that authenticates as an external key."""
    from fastapi_server import app, verify_api_key

    app.dependency_overrides[verify_api_key] = lambda: ("external", FAKE_EXTERNAL_KEY)
    original_middleware = app.middleware_stack
    app.middleware_stack = None

    try:
        with patch("fastapi_server._run_external_vuln_sync"), \
             patch("fastapi_server.check_rate_limit", return_value=True):
            yield TestClient(app)
    finally:
        app.dependency_overrides.clear()
        app.middleware_stack = original_middleware


@pytest.fixture()
def client_no_auth():
    """TestClient with NO dependency override — uses real auth (will fail without valid key)."""
    from fastapi_server import app

    original_middleware = app.middleware_stack
    app.middleware_stack = None

    with patch("fastapi_server.get_all_valid_keys", return_value=(
        {FAKE_INTERNAL_KEY},
        {FAKE_EXTERNAL_KEY},
    )), patch("fastapi_server.check_rate_limit", return_value=True):
        yield TestClient(app)

    app.middleware_stack = original_middleware


def _auth(key=FAKE_INTERNAL_KEY):
    return {"Authorization": f"Bearer {key}", "Content-Type": "application/json"}


# ---------------------------------------------------------------------------
# Sample data helpers
# ---------------------------------------------------------------------------

SAMPLE_MATCHED_DGS = [
    {
        "id": "dg-001",
        "cpe": "cpe:2.3:a:vendor:product:1.0:*:*:*:*:*:*:*",
        "helmProductName": "Product A",
        "helmProductVersionName": "1.0",
        "helmSbomId": "pv-uuid-001",
    },
    {
        "id": "dg-002",
        "cpe": "cpe:2.3:a:vendor:product:2.0:*:*:*:*:*:*:*",
        "helmProductName": "Product B",
        "helmProductVersionName": "2.0",
        "helmSbomId": "pv-uuid-002",
    },
]


def _make_helm_vuln(cve_id="CVE-2024-0001", assoc_date="2024-06-15T12:00:00Z", score=7.5):
    """Build a minimal Helm-format vulnerability dict."""
    return {
        "vulnerability_key": cve_id,
        "vulnerability_summary": f"Summary for {cve_id}",
        "vendor_display_name": "TestVendor",
        "product_display_name": "TestProduct",
        "product_version_string": "1.0",
        "organization_product_name": "OrgProduct",
        "vulnerability_severity": [{"score": score}],
        "description": [{"lang_code": "en", "value": f"Description for {cve_id}"}],
        "problems": [{"lang_code": "en", "value": "Impact"}],
        "reference_link": [],
        "vulnerability_association_date": assoc_date,
    }


# ---------------------------------------------------------------------------
# Model tests
# ---------------------------------------------------------------------------

class TestModels:
    def test_external_vuln_sync_request_defaults(self):
        from models import ExternalVulnSyncRequest
        req = ExternalVulnSyncRequest(webhook_url="http://example.com/hook")
        assert req.page == 1
        assert req.pageSize == 500
        assert req.last_sync is None
        assert req.not_after is None

    def test_external_vuln_sync_request_custom(self):
        from models import ExternalVulnSyncRequest
        req = ExternalVulnSyncRequest(
            webhook_url="http://example.com/hook",
            last_sync="2024-01-01T00:00:00Z",
            not_after="2024-12-31T23:59:59Z",
            page=2,
            pageSize=100,
        )
        assert req.pageSize == 100
        assert req.last_sync == "2024-01-01T00:00:00Z"

    def test_accepted_response_defaults(self):
        from models import ExternalVulnSyncAcceptedResponse
        resp = ExternalVulnSyncAcceptedResponse(
            message="Started", matched_device_groups=3
        )
        assert resp.status == "accepted"
        assert resp.matched_device_groups == 3

    def test_request_requires_webhook_url(self):
        from models import ExternalVulnSyncRequest
        with pytest.raises(Exception):
            ExternalVulnSyncRequest()


# ---------------------------------------------------------------------------
# Transform tests (vendorId / deviceArtifactId additions)
# ---------------------------------------------------------------------------

class TestTransformFields:
    def test_vendor_id_present(self):
        from helm_viper_vuln_sync import transform_helm_vuln_to_viper
        vuln = _make_helm_vuln(cve_id="CVE-2024-9999")
        result = transform_helm_vuln_to_viper(vuln)
        assert result["vendorId"] == "CVE-2024-9999"

    def test_device_artifact_id_omitted(self):
        from helm_viper_vuln_sync import transform_helm_vuln_to_viper
        result = transform_helm_vuln_to_viper(_make_helm_vuln())
        assert "deviceArtifactId" not in result

    def test_exploit_uri_omitted_when_absent(self):
        from helm_viper_vuln_sync import transform_helm_vuln_to_viper
        vuln = _make_helm_vuln()
        vuln["reference_link"] = []
        result = transform_helm_vuln_to_viper(vuln)
        assert "exploitUri" not in result

    def test_upstream_api_omitted_when_absent(self):
        from helm_viper_vuln_sync import transform_helm_vuln_to_viper
        vuln = _make_helm_vuln()
        vuln["reference_link"] = []
        result = transform_helm_vuln_to_viper(vuln)
        assert "upstreamApi" not in result

    def test_exploit_uri_populated_when_present(self):
        from helm_viper_vuln_sync import transform_helm_vuln_to_viper
        vuln = _make_helm_vuln()
        vuln["exploit_db"] = True
        vuln["reference_link"] = [
            {"reference_link_href": "https://exploit-db.com/exploits/12345"}
        ]
        result = transform_helm_vuln_to_viper(vuln)
        assert "exploit-db.com" in result["exploitUri"]

    def test_upstream_api_populated_when_present(self):
        from helm_viper_vuln_sync import transform_helm_vuln_to_viper
        vuln = _make_helm_vuln()
        vuln["reference_link"] = [
            {"reference_link_href": "https://nvd.nist.gov/vuln/detail/CVE-2024-0001", "reference_link_source": "NVD"}
        ]
        result = transform_helm_vuln_to_viper(vuln)
        assert "nvd.nist.gov" in result["upstreamApi"]


# ---------------------------------------------------------------------------
# Endpoint tests
# ---------------------------------------------------------------------------

class TestExternalVulnSyncEndpoint:
    def test_returns_202_accepted(self, client):
        """Endpoint should return 202 with matched device group count."""
        with patch(
            "helm_viper_device_groups.get_matched_device_groups",
            return_value=SAMPLE_MATCHED_DGS,
        ):
            resp = client.post(
                "/api/external-vuln-sync",
                json={"webhook_url": "http://localhost:9999/hook"},
            )
        assert resp.status_code == 202
        body = resp.json()
        assert body["status"] == "accepted"
        assert body["matched_device_groups"] == 2

    def test_returns_202_with_external_key(self, client_external):
        """External keys should also be allowed."""
        with patch(
            "helm_viper_device_groups.get_matched_device_groups",
            return_value=SAMPLE_MATCHED_DGS,
        ):
            resp = client_external.post(
                "/api/external-vuln-sync",
                json={"webhook_url": "http://localhost:9999/hook"},
            )
        assert resp.status_code == 202

    def test_no_matched_device_groups(self, client):
        """Should return 202 with count=0 when no device groups match."""
        with patch(
            "helm_viper_device_groups.get_matched_device_groups",
            return_value=[],
        ):
            resp = client.post(
                "/api/external-vuln-sync",
                json={"webhook_url": "http://localhost:9999/hook"},
            )
        assert resp.status_code == 202
        assert resp.json()["matched_device_groups"] == 0

    def test_missing_webhook_url_returns_422(self, client):
        """webhook_url is required — missing it should 422."""
        resp = client.post(
            "/api/external-vuln-sync",
            json={},
        )
        assert resp.status_code == 422

    def test_invalid_last_sync_returns_400(self, client):
        """Bad ISO-8601 in last_sync should 400."""
        with patch(
            "helm_viper_device_groups.get_matched_device_groups",
            return_value=SAMPLE_MATCHED_DGS,
        ):
            resp = client.post(
                "/api/external-vuln-sync",
                json={"webhook_url": "http://localhost:9999/hook", "last_sync": "not-a-date"},
            )
        assert resp.status_code == 400

    def test_invalid_not_after_returns_400(self, client):
        """Bad ISO-8601 in not_after should 400."""
        with patch(
            "helm_viper_device_groups.get_matched_device_groups",
            return_value=SAMPLE_MATCHED_DGS,
        ):
            resp = client.post(
                "/api/external-vuln-sync",
                json={"webhook_url": "http://localhost:9999/hook", "not_after": "nope"},
            )
        assert resp.status_code == 400

    def test_missing_helm_creds_returns_500(self, client, monkeypatch):
        """If HELM_CLIENT_ID is missing, should 500."""
        monkeypatch.delenv("HELM_CLIENT_ID")
        resp = client.post(
            "/api/external-vuln-sync",
            json={"webhook_url": "http://localhost:9999/hook"},
        )
        assert resp.status_code == 500
        assert "Helm API credentials" in resp.json()["detail"]

    def test_missing_viper_key_returns_500(self, client, monkeypatch):
        """If VIPER_API_KEY is missing, should 500."""
        monkeypatch.delenv("VIPER_API_KEY")
        resp = client.post(
            "/api/external-vuln-sync",
            json={"webhook_url": "http://localhost:9999/hook"},
        )
        assert resp.status_code == 500
        assert "Viper API key" in resp.json()["detail"]

    def test_response_message_includes_webhook_url(self, client):
        """Response message should mention the webhook URL."""
        with patch(
            "helm_viper_device_groups.get_matched_device_groups",
            return_value=SAMPLE_MATCHED_DGS[:1],
        ):
            resp = client.post(
                "/api/external-vuln-sync",
                json={"webhook_url": "http://my-server.com/callback"},
            )
        assert resp.status_code == 202
        assert "http://my-server.com/callback" in resp.json()["message"]


# ---------------------------------------------------------------------------
# Auth tests (use real auth — no dependency override)
# ---------------------------------------------------------------------------

class TestExternalVulnSyncAuth:
    def test_unauthenticated_returns_403(self, client_no_auth):
        """No auth header should be rejected."""
        resp = client_no_auth.post(
            "/api/external-vuln-sync",
            json={"webhook_url": "http://localhost:9999/hook"},
        )
        assert resp.status_code == 403

    def test_invalid_key_returns_401(self, client_no_auth):
        """A bogus key should be rejected."""
        resp = client_no_auth.post(
            "/api/external-vuln-sync",
            json={"webhook_url": "http://localhost:9999/hook"},
            headers=_auth("totally-invalid-key"),
        )
        assert resp.status_code == 401


# ---------------------------------------------------------------------------
# Background task tests
# ---------------------------------------------------------------------------

class TestBackgroundTask:
    @patch("requests.post")
    @patch("helm_get_sbom.get_vulnerabilities_for_product_version")
    def test_posts_paginated_results_to_webhook(self, mock_get_vulns, mock_post):
        """Background task should POST paginated pages to webhook_url."""
        from fastapi_server import _run_external_vuln_sync

        vulns = [_make_helm_vuln(f"CVE-2024-{i:04d}") for i in range(5)]
        mock_get_vulns.return_value = {"success": True, "vulnerabilities": vulns}
        mock_post.return_value = MagicMock(status_code=200)

        _run_external_vuln_sync(
            matched_device_groups=SAMPLE_MATCHED_DGS[:1],
            helm_client_id="id",
            helm_client_secret="secret",
            webhook_url="http://test.local/hook",
            page_size=3,
            last_sync_epoch=None,
            not_after_epoch=None,
        )

        # 5 vulns / pageSize=3 => 2 pages
        assert mock_post.call_count == 2

        # Inspect first page payload
        first_call_payload = mock_post.call_args_list[0].kwargs.get("json") or mock_post.call_args_list[0][1].get("json")
        assert first_call_payload["page"] == 1
        assert first_call_payload["pageSize"] == 3
        assert first_call_payload["totalCount"] == 5
        assert first_call_payload["totalPages"] == 2
        assert len(first_call_payload["items"]) == 3
        assert first_call_payload["next"] is None
        assert first_call_payload["previous"] is None

        # Second page
        second_call_payload = mock_post.call_args_list[1].kwargs.get("json") or mock_post.call_args_list[1][1].get("json")
        assert second_call_payload["page"] == 2
        assert len(second_call_payload["items"]) == 2

    @patch("requests.post")
    @patch("helm_get_sbom.get_vulnerabilities_for_product_version")
    def test_date_filtering_last_sync(self, mock_get_vulns, mock_post):
        """Vulns before last_sync should be excluded."""
        from fastapi_server import _run_external_vuln_sync
        from datetime import datetime

        vulns = [
            _make_helm_vuln("CVE-OLD", assoc_date="2024-01-01T00:00:00Z"),
            _make_helm_vuln("CVE-NEW", assoc_date="2024-07-01T00:00:00Z"),
        ]
        mock_get_vulns.return_value = {"success": True, "vulnerabilities": vulns}
        mock_post.return_value = MagicMock(status_code=200)

        cutoff = datetime.fromisoformat("2024-06-01T00:00:00+00:00").timestamp()

        _run_external_vuln_sync(
            matched_device_groups=SAMPLE_MATCHED_DGS[:1],
            helm_client_id="id",
            helm_client_secret="secret",
            webhook_url="http://test.local/hook",
            page_size=500,
            last_sync_epoch=cutoff,
            not_after_epoch=None,
        )

        assert mock_post.call_count == 1
        payload = mock_post.call_args_list[0].kwargs.get("json") or mock_post.call_args_list[0][1].get("json")
        assert payload["totalCount"] == 1
        assert payload["items"][0]["vendorId"] == "CVE-NEW"

    @patch("requests.post")
    @patch("helm_get_sbom.get_vulnerabilities_for_product_version")
    def test_date_filtering_not_after(self, mock_get_vulns, mock_post):
        """Vulns after not_after should be excluded."""
        from fastapi_server import _run_external_vuln_sync
        from datetime import datetime

        vulns = [
            _make_helm_vuln("CVE-EARLY", assoc_date="2024-03-01T00:00:00Z"),
            _make_helm_vuln("CVE-LATE", assoc_date="2024-09-01T00:00:00Z"),
        ]
        mock_get_vulns.return_value = {"success": True, "vulnerabilities": vulns}
        mock_post.return_value = MagicMock(status_code=200)

        cutoff = datetime.fromisoformat("2024-06-01T00:00:00+00:00").timestamp()

        _run_external_vuln_sync(
            matched_device_groups=SAMPLE_MATCHED_DGS[:1],
            helm_client_id="id",
            helm_client_secret="secret",
            webhook_url="http://test.local/hook",
            page_size=500,
            last_sync_epoch=None,
            not_after_epoch=cutoff,
        )

        assert mock_post.call_count == 1
        payload = mock_post.call_args_list[0].kwargs.get("json") or mock_post.call_args_list[0][1].get("json")
        assert payload["totalCount"] == 1
        assert payload["items"][0]["vendorId"] == "CVE-EARLY"

    @patch("requests.post")
    @patch("helm_get_sbom.get_vulnerabilities_for_product_version")
    def test_date_filtering_both_bounds(self, mock_get_vulns, mock_post):
        """Vulns outside both last_sync and not_after should be excluded."""
        from fastapi_server import _run_external_vuln_sync
        from datetime import datetime

        vulns = [
            _make_helm_vuln("CVE-EARLY", assoc_date="2024-01-01T00:00:00Z"),
            _make_helm_vuln("CVE-MID", assoc_date="2024-06-15T00:00:00Z"),
            _make_helm_vuln("CVE-LATE", assoc_date="2024-12-01T00:00:00Z"),
        ]
        mock_get_vulns.return_value = {"success": True, "vulnerabilities": vulns}
        mock_post.return_value = MagicMock(status_code=200)

        last_sync = datetime.fromisoformat("2024-03-01T00:00:00+00:00").timestamp()
        not_after = datetime.fromisoformat("2024-09-01T00:00:00+00:00").timestamp()

        _run_external_vuln_sync(
            matched_device_groups=SAMPLE_MATCHED_DGS[:1],
            helm_client_id="id",
            helm_client_secret="secret",
            webhook_url="http://test.local/hook",
            page_size=500,
            last_sync_epoch=last_sync,
            not_after_epoch=not_after,
        )

        payload = mock_post.call_args_list[0].kwargs.get("json") or mock_post.call_args_list[0][1].get("json")
        assert payload["totalCount"] == 1
        assert payload["items"][0]["vendorId"] == "CVE-MID"

    @patch("requests.post")
    @patch("helm_get_sbom.get_vulnerabilities_for_product_version")
    def test_multiple_device_groups_aggregated(self, mock_get_vulns, mock_post):
        """Vulns from all device groups should be collected into a single list."""
        from fastapi_server import _run_external_vuln_sync

        mock_get_vulns.side_effect = [
            {"success": True, "vulnerabilities": [_make_helm_vuln("CVE-A")]},
            {"success": True, "vulnerabilities": [_make_helm_vuln("CVE-B")]},
        ]
        mock_post.return_value = MagicMock(status_code=200)

        _run_external_vuln_sync(
            matched_device_groups=SAMPLE_MATCHED_DGS,  # two groups
            helm_client_id="id",
            helm_client_secret="secret",
            webhook_url="http://test.local/hook",
            page_size=500,
            last_sync_epoch=None,
            not_after_epoch=None,
        )

        assert mock_post.call_count == 1
        payload = mock_post.call_args_list[0].kwargs.get("json") or mock_post.call_args_list[0][1].get("json")
        assert payload["totalCount"] == 2
        vendor_ids = [item["vendorId"] for item in payload["items"]]
        assert "CVE-A" in vendor_ids
        assert "CVE-B" in vendor_ids

    @patch("requests.post")
    @patch("helm_get_sbom.get_vulnerabilities_for_product_version")
    def test_empty_results_still_posts_one_page(self, mock_get_vulns, mock_post):
        """Even zero vulns should produce one page (totalCount=0)."""
        from fastapi_server import _run_external_vuln_sync

        mock_get_vulns.return_value = {"success": True, "vulnerabilities": []}
        mock_post.return_value = MagicMock(status_code=200)

        _run_external_vuln_sync(
            matched_device_groups=SAMPLE_MATCHED_DGS[:1],
            helm_client_id="id",
            helm_client_secret="secret",
            webhook_url="http://test.local/hook",
            page_size=500,
            last_sync_epoch=None,
            not_after_epoch=None,
        )

        assert mock_post.call_count == 1
        payload = mock_post.call_args_list[0].kwargs.get("json") or mock_post.call_args_list[0][1].get("json")
        assert payload["totalCount"] == 0
        assert payload["items"] == []

    @patch("requests.post")
    @patch("helm_get_sbom.get_vulnerabilities_for_product_version")
    def test_webhook_retry_on_failure(self, mock_get_vulns, mock_post):
        """Should retry up to 3 times on webhook POST failure."""
        from fastapi_server import _run_external_vuln_sync

        mock_get_vulns.return_value = {
            "success": True,
            "vulnerabilities": [_make_helm_vuln()],
        }
        # Fail all 3 attempts
        mock_post.return_value = MagicMock(status_code=500)

        with patch("time.sleep"):  # skip actual sleeps
            _run_external_vuln_sync(
                matched_device_groups=SAMPLE_MATCHED_DGS[:1],
                helm_client_id="id",
                helm_client_secret="secret",
                webhook_url="http://test.local/hook",
                page_size=500,
                last_sync_epoch=None,
                not_after_epoch=None,
            )

        assert mock_post.call_count == 3

    @patch("requests.post")
    @patch("helm_get_sbom.get_vulnerabilities_for_product_version")
    def test_webhook_succeeds_on_second_attempt(self, mock_get_vulns, mock_post):
        """Should stop retrying after a successful POST."""
        from fastapi_server import _run_external_vuln_sync

        mock_get_vulns.return_value = {
            "success": True,
            "vulnerabilities": [_make_helm_vuln()],
        }
        mock_post.side_effect = [
            MagicMock(status_code=500),
            MagicMock(status_code=200),
        ]

        with patch("time.sleep"):
            _run_external_vuln_sync(
                matched_device_groups=SAMPLE_MATCHED_DGS[:1],
                helm_client_id="id",
                helm_client_secret="secret",
                webhook_url="http://test.local/hook",
                page_size=500,
                last_sync_epoch=None,
                not_after_epoch=None,
            )

        assert mock_post.call_count == 2

    @patch("requests.post")
    @patch("helm_get_sbom.get_vulnerabilities_for_product_version")
    def test_helm_failure_skipped_gracefully(self, mock_get_vulns, mock_post):
        """If Helm returns failure for one device group, others still process."""
        from fastapi_server import _run_external_vuln_sync

        mock_get_vulns.side_effect = [
            {"success": False, "error": "timeout"},
            {"success": True, "vulnerabilities": [_make_helm_vuln("CVE-GOOD")]},
        ]
        mock_post.return_value = MagicMock(status_code=200)

        _run_external_vuln_sync(
            matched_device_groups=SAMPLE_MATCHED_DGS,
            helm_client_id="id",
            helm_client_secret="secret",
            webhook_url="http://test.local/hook",
            page_size=500,
            last_sync_epoch=None,
            not_after_epoch=None,
        )

        assert mock_post.call_count == 1
        payload = mock_post.call_args_list[0].kwargs.get("json") or mock_post.call_args_list[0][1].get("json")
        assert payload["totalCount"] == 1

    @patch("requests.post")
    @patch("helm_get_sbom.get_vulnerabilities_for_product_version")
    def test_vuln_without_assoc_date_included(self, mock_get_vulns, mock_post):
        """Vulns with no association date should be included regardless of date filters."""
        from fastapi_server import _run_external_vuln_sync
        from datetime import datetime

        vuln = _make_helm_vuln("CVE-NODATE")
        vuln["vulnerability_association_date"] = None
        mock_get_vulns.return_value = {"success": True, "vulnerabilities": [vuln]}
        mock_post.return_value = MagicMock(status_code=200)

        _run_external_vuln_sync(
            matched_device_groups=SAMPLE_MATCHED_DGS[:1],
            helm_client_id="id",
            helm_client_secret="secret",
            webhook_url="http://test.local/hook",
            page_size=500,
            last_sync_epoch=datetime.fromisoformat("2024-01-01T00:00:00+00:00").timestamp(),
            not_after_epoch=None,
        )

        payload = mock_post.call_args_list[0].kwargs.get("json") or mock_post.call_args_list[0][1].get("json")
        assert payload["totalCount"] == 1


# ---------------------------------------------------------------------------
# Integration test — real local webhook server
# ---------------------------------------------------------------------------

import threading
from http.server import HTTPServer, BaseHTTPRequestHandler


class _WebhookCollector(BaseHTTPRequestHandler):
    """Tiny HTTP handler that stores every POST body and headers it receives."""

    received_pages = []  # class-level, shared across requests
    received_headers = []  # class-level, stores headers per request

    def do_POST(self):
        length = int(self.headers.get("Content-Length", 0))
        body = json.loads(self.rfile.read(length)) if length else {}
        _WebhookCollector.received_pages.append(body)
        _WebhookCollector.received_headers.append(dict(self.headers))
        self.send_response(200)
        self.end_headers()
        self.wfile.write(b"ok")

    def log_message(self, fmt, *args):
        pass  # silence console output


class TestWebhookIntegration:
    """Spin up a real HTTP server and verify the background task POSTs to it."""

    @patch("helm_get_sbom.get_vulnerabilities_for_product_version")
    def test_webhook_receives_paginated_posts(self, mock_get_vulns):
        """Background task should deliver real HTTP POSTs to a local webhook."""
        from fastapi_server import _run_external_vuln_sync

        # Reset collector
        _WebhookCollector.received_pages = []
        _WebhookCollector.received_headers = []

        # Start local webhook server on a random port
        server = HTTPServer(("127.0.0.1", 0), _WebhookCollector)
        port = server.server_address[1]
        thread = threading.Thread(target=server.serve_forever, daemon=True)
        thread.start()

        try:
            # 7 vulns, pageSize=3 => 3 pages (3 + 3 + 1)
            vulns = [_make_helm_vuln(f"CVE-2024-{i:04d}") for i in range(7)]
            mock_get_vulns.return_value = {"success": True, "vulnerabilities": vulns}

            _run_external_vuln_sync(
                matched_device_groups=SAMPLE_MATCHED_DGS[:1],
                helm_client_id="id",
                helm_client_secret="secret",
                webhook_url=f"http://127.0.0.1:{port}/webhook",
                page_size=3,
                last_sync_epoch=None,
                not_after_epoch=None,
                viper_api_key="test-viper-key-abc123",
            )

            # Verify we received 3 pages
            pages = _WebhookCollector.received_pages
            assert len(pages) == 3

            # Verify Authorization header on every request
            for i, hdrs in enumerate(_WebhookCollector.received_headers):
                assert hdrs.get("Authorization") == "Bearer test-viper-key-abc123", \
                    f"Page {i+1} missing Authorization header"

            # Page 1
            assert pages[0]["page"] == 1
            assert pages[0]["pageSize"] == 3
            assert pages[0]["totalCount"] == 7
            assert pages[0]["totalPages"] == 3
            assert len(pages[0]["items"]) == 3
            assert pages[0]["next"] is None
            assert pages[0]["previous"] is None

            # Page 2
            assert pages[1]["page"] == 2
            assert len(pages[1]["items"]) == 3

            # Page 3 (remainder)
            assert pages[2]["page"] == 3
            assert len(pages[2]["items"]) == 1

            # Verify all 7 CVEs arrived across all pages
            all_vendor_ids = []
            for page in pages:
                for item in page["items"]:
                    all_vendor_ids.append(item["vendorId"])
            assert len(all_vendor_ids) == 7
            assert all_vendor_ids == [f"CVE-2024-{i:04d}" for i in range(7)]

            # Verify each item has the expected Viper fields
            sample_item = pages[0]["items"][0]
            assert "cveId" in sample_item
            assert "sarif" in sample_item
            assert "vendorId" in sample_item
            # Optional fields should be omitted when no value, not empty strings
            assert "deviceArtifactId" not in sample_item
            assert "exploitUri" not in sample_item  # test vulns have no exploit links
            assert "upstreamApi" not in sample_item  # test vulns have no references

        finally:
            server.shutdown()

    @patch("helm_get_sbom.get_vulnerabilities_for_product_version")
    def test_webhook_receives_filtered_results(self, mock_get_vulns):
        """Webhook should only receive vulns within the date bounds."""
        from fastapi_server import _run_external_vuln_sync
        from datetime import datetime

        _WebhookCollector.received_pages = []
        _WebhookCollector.received_headers = []

        server = HTTPServer(("127.0.0.1", 0), _WebhookCollector)
        port = server.server_address[1]
        thread = threading.Thread(target=server.serve_forever, daemon=True)
        thread.start()

        try:
            vulns = [
                _make_helm_vuln("CVE-OLD", assoc_date="2024-01-15T00:00:00Z"),
                _make_helm_vuln("CVE-IN-RANGE", assoc_date="2024-06-15T00:00:00Z"),
                _make_helm_vuln("CVE-FUTURE", assoc_date="2024-11-15T00:00:00Z"),
            ]
            mock_get_vulns.return_value = {"success": True, "vulnerabilities": vulns}

            _run_external_vuln_sync(
                matched_device_groups=SAMPLE_MATCHED_DGS[:1],
                helm_client_id="id",
                helm_client_secret="secret",
                webhook_url=f"http://127.0.0.1:{port}/webhook",
                page_size=500,
                last_sync_epoch=datetime.fromisoformat("2024-03-01T00:00:00+00:00").timestamp(),
                not_after_epoch=datetime.fromisoformat("2024-09-01T00:00:00+00:00").timestamp(),
                viper_api_key="test-viper-key-filtered",
            )

            pages = _WebhookCollector.received_pages
            assert len(pages) == 1
            assert pages[0]["totalCount"] == 1
            assert pages[0]["items"][0]["vendorId"] == "CVE-IN-RANGE"

        finally:
            server.shutdown()


# ---------------------------------------------------------------------------
# EXTERNAL_ENDPOINTS set test
# ---------------------------------------------------------------------------

class TestExternalEndpointsSet:
    def test_external_vuln_sync_in_external_endpoints(self):
        from fastapi_server import EXTERNAL_ENDPOINTS
        assert "/api/external-vuln-sync" in EXTERNAL_ENDPOINTS
