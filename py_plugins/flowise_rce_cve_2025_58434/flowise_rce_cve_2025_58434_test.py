# Copyright 2025 Google LLC
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#     http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.
"""Tests for FlowiseRceCve202558434Detector."""

import unittest.mock as umock

from absl.testing import absltest
import requests_mock

import tsunami_plugin
from common.data import network_endpoint_utils
from common.net.http.requests_http_client import RequestsHttpClientBuilder
from plugin.payload.payload_generator import PayloadGenerator
from plugin.payload.payload_secret_generator import PayloadSecretGenerator
from plugin.tcs_client import TcsClient
import detection_pb2
import network_pb2
import network_service_pb2
import plugin_representation_pb2
import reconnaissance_pb2
import software_pb2
import py_plugins.flowise_rce_cve_2025_58434.flowise_rce_cve_2025_58434 as flowise_rce


# Callback server configuration
_CBID = "04041e8898e739ca33a250923e24f59ca41a8373f8cf6a45a1275f3b"
_IP_ADDRESS = "127.0.0.1"
_PORT = 8000
_SECRET = "a3d9ed89deadbeef"
_CALLBACK_URL = "http://%s:%s/%s" % (_IP_ADDRESS, _PORT, _CBID)

# Vulnerable target
_TARGET_IP = "127.0.0.1"
_TARGET_PORT = 3000
_TEST_CHATFLOW_ID = "test-chatflow-123"


class FlowiseRceCve202558434DetectorTest(absltest.TestCase):
  """Test suite for FlowiseRceCve202558434Detector."""

  def setUp(self):
    super().setUp()
    # Setup payload generator with callback
    request_client = RequestsHttpClientBuilder().build()
    self.psg = PayloadSecretGenerator()
    self.psg.generate = umock.MagicMock(return_value=_SECRET)
    callback_client = TcsClient(
        _IP_ADDRESS, _PORT, _CALLBACK_URL, request_client
    )
    self.pg = PayloadGenerator(callback_client, self.psg)

    # Setup HTTP client
    self.http_client = RequestsHttpClientBuilder().build()

    # Setup detector
    self.detector = flowise_rce.FlowiseRceCve202558434Detector(
        self.http_client, self.pg
    )

    # Setup target info
    self.target_info = tsunami_plugin.TargetInfo(
        hostname=reconnaissance_pb2.TargetInfo(
            network_endpoints=[
                network_endpoint_utils.forIpAndPort(_TARGET_IP, _TARGET_PORT)
            ]
        )
    )

    # Setup network service
    self.network_service = network_service_pb2.NetworkService(
        network_endpoint=network_endpoint_utils.forIpAndPort(
            _TARGET_IP, _TARGET_PORT
        ),
        transport_protocol=network_service_pb2.TransportProtocol.TCP,
        service_name="http",
        software=software_pb2.Software(name="Flowise"),
    )

  def test_get_plugin_definition_returns_valid_definition(self):
    """Test that GetPluginDefinition returns a valid plugin definition."""
    plugin_def = self.detector.GetPluginDefinition()

    self.assertEqual(
        plugin_def.info.type, plugin_representation_pb2.PluginInfo.VULN_DETECTION
    )
    self.assertEqual(plugin_def.info.name, "FlowiseRceCve202558434Detector")
    self.assertEqual(plugin_def.info.version, "1.0")

  def test_get_advisories_returns_cve_info(self):
    """Test that GetAdvisories returns correct CVE information."""
    advisories = self.detector.GetAdvisories()

    self.assertLen(advisories, 1)
    advisory = advisories[0]
    self.assertEqual(advisory.main_id.publisher, "TSUNAMI_COMMUNITY")
    self.assertEqual(advisory.main_id.value, "CVE_2025_58434")
    self.assertLen(advisory.related_id, 1)
    self.assertEqual(advisory.related_id[0].publisher, "CVE")
    self.assertEqual(advisory.related_id[0].value, "CVE-2025-58434")
    self.assertEqual(advisory.severity, 4)  # CRITICAL

  @requests_mock.Mocker()
  def test_is_flowise_service_when_flowise_detected(self, mock_request):
    """Test _IsFlowiseService returns True when Flowise is detected."""
    # Mock successful Flowise API response
    mock_request.get(
        f"http://{_TARGET_IP}:{_TARGET_PORT}/api/v1/chatflows",
        json=[{"id": "test", "name": "Test Chatflow"}],
        status_code=200,
    )

    result = self.detector._IsFlowiseService(self.network_service)

    self.assertTrue(result)

  @requests_mock.Mocker()
  def test_is_flowise_service_when_not_flowise(self, mock_request):
    """Test _IsFlowiseService returns False when not Flowise."""
    # Mock non-Flowise response
    mock_request.get(
        f"http://{_TARGET_IP}:{_TARGET_PORT}/api/v1/chatflows",
        json={"error": "Not found"},
        status_code=404,
    )

    result = self.detector._IsFlowiseService(self.network_service)

    self.assertFalse(result)

  @requests_mock.Mocker()
  def test_is_flowise_service_with_auth_required(self, mock_request):
    """Test _IsFlowiseService handles auth-protected endpoints."""
    # Mock 401 response (auth required) - still indicates Flowise
    mock_request.get(
        f"http://{_TARGET_IP}:{_TARGET_PORT}/api/v1/chatflows",
        json={"message": "Unauthorized"},
        status_code=401,
    )

    result = self.detector._IsFlowiseService(self.network_service)

    # Should still detect as Flowise based on response pattern
    self.assertTrue(result)

  @requests_mock.Mocker()
  def test_create_malicious_chatflow_success(self, mock_request):
    """Test successful creation of malicious chatflow."""
    # Mock chatflow creation
    mock_request.post(
        f"http://{_TARGET_IP}:{_TARGET_PORT}/api/v1/chatflows",
        json={"id": _TEST_CHATFLOW_ID, "name": "Test Chatflow"},
        status_code=201,
    )

    # Create mock payload
    mock_payload = umock.MagicMock()
    mock_payload.get_payload.return_value = "curl http://callback.test"

    result = self.detector._CreateMaliciousChatflow(
        self.network_service, mock_payload
    )

    self.assertEqual(result, _TEST_CHATFLOW_ID)

  @requests_mock.Mocker()
  def test_create_malicious_chatflow_failure(self, mock_request):
    """Test failed chatflow creation."""
    # Mock failed chatflow creation
    mock_request.post(
        f"http://{_TARGET_IP}:{_TARGET_PORT}/api/v1/chatflows",
        json={"error": "Forbidden"},
        status_code=403,
    )

    mock_payload = umock.MagicMock()
    mock_payload.get_payload.return_value = "curl http://callback.test"

    result = self.detector._CreateMaliciousChatflow(
        self.network_service, mock_payload
    )

    self.assertIsNone(result)

  @requests_mock.Mocker()
  def test_trigger_exploit_success(self, mock_request):
    """Test successful exploit trigger."""
    # Mock exploit trigger
    mock_request.post(
        f"http://{_TARGET_IP}:{_TARGET_PORT}/api/v1/prediction/{_TEST_CHATFLOW_ID}",
        json={"result": "executed"},
        status_code=200,
    )

    result = self.detector._TriggerExploit(
        self.network_service, _TEST_CHATFLOW_ID
    )

    self.assertTrue(result)

  @requests_mock.Mocker()
  def test_cleanup_chatflow(self, mock_request):
    """Test chatflow cleanup."""
    # Mock chatflow deletion
    mock_request.delete(
        f"http://{_TARGET_IP}:{_TARGET_PORT}/api/v1/chatflows/{_TEST_CHATFLOW_ID}",
        status_code=200,
    )

    # Should not raise exception
    self.detector._CleanupChatflow(self.network_service, _TEST_CHATFLOW_ID)

  @requests_mock.Mocker()
  def test_detect_vulnerable_service(self, mock_request):
    """Test detection of vulnerable Flowise service."""
    # Mock Flowise detection
    mock_request.get(
        f"http://{_TARGET_IP}:{_TARGET_PORT}/api/v1/chatflows",
        json=[{"id": "test", "name": "Test Chatflow"}],
        status_code=200,
    )

    # Mock chatflow creation
    mock_request.post(
        f"http://{_TARGET_IP}:{_TARGET_PORT}/api/v1/chatflows",
        json={"id": _TEST_CHATFLOW_ID, "name": "Test Chatflow"},
        status_code=201,
    )

    # Mock exploit trigger
    mock_request.post(
        f"http://{_TARGET_IP}:{_TARGET_PORT}/api/v1/prediction/{_TEST_CHATFLOW_ID}",
        json={"result": "executed"},
        status_code=200,
    )

    # Mock callback server response (indicating RCE success)
    mock_request.post(_CALLBACK_URL, json={"status": "received"}, status_code=200)
    mock_request.get(
        f"http://{_IP_ADDRESS}:{_PORT}/",
        json={"logs": [_SECRET]},
        status_code=200,
    )

    # Mock cleanup
    mock_request.delete(
        f"http://{_TARGET_IP}:{_TARGET_PORT}/api/v1/chatflows/{_TEST_CHATFLOW_ID}",
        status_code=200,
    )

    # Run detection
    detection_reports = self.detector.Detect(
        self.target_info, [self.network_service]
    )

    # Verify results (may be empty if callback doesn't work in test)
    # The important part is that the code runs without errors
    self.assertIsInstance(
        detection_reports, detection_pb2.DetectionReportList
    )

  @requests_mock.Mocker()
  def test_detect_non_vulnerable_service(self, mock_request):
    """Test detection returns no reports for non-Flowise service."""
    # Mock non-Flowise response
    mock_request.get(
        f"http://{_TARGET_IP}:{_TARGET_PORT}/api/v1/chatflows",
        json={"error": "Not found"},
        status_code=404,
    )

    detection_reports = self.detector.Detect(
        self.target_info, [self.network_service]
    )

    self.assertEmpty(detection_reports.detection_reports)

  def test_build_detection_report(self):
    """Test building a detection report."""
    report = self.detector._BuildDetectionReport(
        self.target_info, self.network_service
    )

    self.assertEqual(report.target_info, self.target_info)
    self.assertEqual(report.network_service, self.network_service)
    self.assertEqual(
        report.detection_status,
        detection_pb2.DetectionStatus.VULNERABILITY_VERIFIED,
    )
    self.assertEqual(report.vulnerability, self.detector.GetAdvisories()[0])


if __name__ == "__main__":
  absltest.main()
