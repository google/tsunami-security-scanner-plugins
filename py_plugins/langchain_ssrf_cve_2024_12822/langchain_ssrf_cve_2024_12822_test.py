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
"""Tests for LangChainSsrfCve202412822Detector."""

from absl.testing import absltest
import requests_mock

import tsunami_plugin
from common.data import network_endpoint_utils
from common.net.http.requests_http_client import RequestsHttpClientBuilder
from plugin.payload.payload_generator import PayloadGenerator
import detection_pb2
import network_service_pb2
import plugin_representation_pb2
import reconnaissance_pb2
import software_pb2
import py_plugins.langchain_ssrf_cve_2024_12822.langchain_ssrf_cve_2024_12822 as langchain_ssrf


_TARGET_IP = "127.0.0.1"
_TARGET_PORT = 8000


class LangChainSsrfCve202412822DetectorTest(absltest.TestCase):
  """Test suite for LangChainSsrfCve202412822Detector."""

  def setUp(self):
    super().setUp()
    # Setup HTTP client
    self.http_client = RequestsHttpClientBuilder().build()

    # Setup payload generator (mock)
    self.pg = None  # SSRF detection doesn't need full payload generator

    # Setup detector
    self.detector = langchain_ssrf.LangChainSsrfCve202412822Detector(
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
        software=software_pb2.Software(name="LangChain"),
    )

  def test_get_plugin_definition_returns_valid_definition(self):
    """Test that GetPluginDefinition returns a valid plugin definition."""
    plugin_def = self.detector.GetPluginDefinition()

    self.assertEqual(
        plugin_def.info.type, plugin_representation_pb2.PluginInfo.VULN_DETECTION
    )
    self.assertEqual(plugin_def.info.name, "LangChainSsrfCve202412822Detector")
    self.assertEqual(plugin_def.info.version, "1.0")

  def test_get_advisories_returns_cve_info(self):
    """Test that GetAdvisories returns correct CVE information."""
    advisories = self.detector.GetAdvisories()

    self.assertLen(advisories, 1)
    advisory = advisories[0]
    self.assertEqual(advisory.main_id.publisher, "TSUNAMI_COMMUNITY")
    self.assertEqual(advisory.main_id.value, "CVE_2024_12822")
    self.assertEqual(advisory.related_id[0].publisher, "CVE")
    self.assertEqual(advisory.related_id[0].value, "CVE-2024-12822")
    self.assertEqual(advisory.related_id[1].publisher, "CWE")
    self.assertEqual(advisory.related_id[1].value, "CWE-918")
    self.assertEqual(advisory.severity, 3)  # HIGH

  @requests_mock.Mocker()
  def test_is_langchain_service_when_detected(self, mock_request):
    """Test _IsLangChainService returns True when LangChain is detected."""
    # Mock API docs endpoint with LangChain content
    mock_request.get(
        f"http://{_TARGET_IP}:{_TARGET_PORT}/api/docs",
        text="LangChain API Documentation - DocumentLoader and Retriever",
        status_code=200,
    )

    result = self.detector._IsLangChainService(self.network_service)

    self.assertTrue(result)

  @requests_mock.Mocker()
  def test_is_langchain_service_when_not_detected(self, mock_request):
    """Test _IsLangChainService returns False when not LangChain."""
    # Mock non-LangChain responses
    mock_request.get(
        f"http://{_TARGET_IP}:{_TARGET_PORT}/api/docs",
        text="Generic API Documentation",
        status_code=404,
    )
    mock_request.get(
        f"http://{_TARGET_IP}:{_TARGET_PORT}/docs",
        text="Generic docs",
        status_code=404,
    )
    mock_request.get(
        f"http://{_TARGET_IP}:{_TARGET_PORT}/openapi.json",
        status_code=404,
    )
    mock_request.get(
        f"http://{_TARGET_IP}:{_TARGET_PORT}/",
        text="Hello World",
        status_code=200,
    )

    result = self.detector._IsLangChainService(self.network_service)

    self.assertFalse(result)

  def test_get_callback_url_returns_url(self):
    """Test that _GetCallbackUrl returns a valid URL."""
    url = self.detector._GetCallbackUrl()

    self.assertIsNotNone(url)
    self.assertIn("http", url)

  @requests_mock.Mocker()
  def test_test_ssrf_on_endpoint_with_ssrf_indicator(self, mock_request):
    """Test SSRF detection when server shows SSRF indicators."""
    callback_url = "http://callback.test/check"
    
    # Mock response that indicates SSRF attempt
    mock_request.post(
        f"http://{_TARGET_IP}:{_TARGET_PORT}/api/load",
        text=f"Error: Failed to fetch {callback_url}: Connection refused",
        status_code=500,
    )

    result = self.detector._TestSsrfOnEndpoint(
        f"http://{_TARGET_IP}:{_TARGET_PORT}",
        "/api/load",
        callback_url,
    )

    self.assertTrue(result)

  @requests_mock.Mocker()
  def test_test_ssrf_on_endpoint_no_ssrf(self, mock_request):
    """Test SSRF detection when no SSRF is present."""
    callback_url = "http://callback.test/check"
    
    # Mock normal response without SSRF indicators
    mock_request.post(
        f"http://{_TARGET_IP}:{_TARGET_PORT}/api/load",
        json={"error": "Invalid request"},
        status_code=400,
    )
    mock_request.get(
        f"http://{_TARGET_IP}:{_TARGET_PORT}/api/load?url={callback_url}",
        json={"error": "Invalid request"},
        status_code=400,
    )

    result = self.detector._TestSsrfOnEndpoint(
        f"http://{_TARGET_IP}:{_TARGET_PORT}",
        "/api/load",
        callback_url,
    )

    self.assertFalse(result)

  @requests_mock.Mocker()
  def test_detect_vulnerable_service(self, mock_request):
    """Test detection of vulnerable LangChain service."""
    callback_url = "http://callback.tsunami-scanner.test/ssrf-check"
    
    # Mock LangChain detection
    mock_request.get(
        f"http://{_TARGET_IP}:{_TARGET_PORT}/api/docs",
        text="LangChain DocumentLoader API",
        status_code=200,
    )

    # Mock SSRF vulnerable endpoint
    mock_request.post(
        f"http://{_TARGET_IP}:{_TARGET_PORT}/api/load",
        text=f"Error: Connection timeout while fetching {callback_url}",
        status_code=500,
    )

    # Run detection
    detection_reports = self.detector.Detect(
        self.target_info, [self.network_service]
    )

    # Should detect vulnerability
    self.assertLen(detection_reports.detection_reports, 1)
    report = detection_reports.detection_reports[0]
    self.assertEqual(
        report.detection_status,
        detection_pb2.DetectionStatus.VULNERABILITY_VERIFIED,
    )

  @requests_mock.Mocker()
  def test_detect_non_vulnerable_service(self, mock_request):
    """Test detection returns no reports for non-LangChain service."""
    # Mock non-LangChain responses
    mock_request.get(
        f"http://{_TARGET_IP}:{_TARGET_PORT}/api/docs",
        status_code=404,
    )
    mock_request.get(
        f"http://{_TARGET_IP}:{_TARGET_PORT}/docs",
        status_code=404,
    )
    mock_request.get(
        f"http://{_TARGET_IP}:{_TARGET_PORT}/openapi.json",
        status_code=404,
    )
    mock_request.get(
        f"http://{_TARGET_IP}:{_TARGET_PORT}/",
        text="Not a LangChain app",
        status_code=200,
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
