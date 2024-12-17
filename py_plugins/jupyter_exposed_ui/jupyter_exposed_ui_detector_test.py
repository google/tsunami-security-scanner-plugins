# Copyright 2023 Google LLC
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
"""Tests for JupyterExposedUiDetector."""

import unittest
from absl.testing import absltest
import requests_mock


from common.data import network_endpoint_utils
from common.net.http.requests_http_client import RequestsHttpClientBuilder
from plugin.payload.payload_generator import PayloadGenerator
from plugin.payload.payload_secret_generator import PayloadSecretGenerator
from plugin.payload.payload_utility import get_parsed_payload
from plugin.tcs_client import TcsClient
import detection_pb2
import network_pb2
import network_service_pb2
import reconnaissance_pb2
import software_pb2
import vulnerability_pb2
from third_party.tsunami_plugins.py_plugins.jupyter_exposed_ui import jupyter_exposed_ui_detector
from third_party.tsunami_plugins.py_plugins.jupyter_exposed_ui.jupyter_exposed_ui_detector import _VULN_REMEDIATION


_TARGET_URL = 'vuln-target.com'
_TARGET_PATH = 'terminals/1'
_TARGET_PORT = 80


class JupyterExposedUiDetectorTest(absltest.TestCase):
  def setUp(self):
    super().setUp()
    self.psg = PayloadSecretGenerator()
    self.client = RequestsHttpClientBuilder().build()
    self.detector = jupyter_exposed_ui_detector.JupyterExposedUiDetector(
        self.client, PayloadGenerator(
            PayloadSecretGenerator(),
            get_parsed_payload(),
            TcsClient('', 80, '', self.client))
    )

  @requests_mock.mock()
  def test_detect_when_jupyter_does_not_redirect_to_login_returns_vuln(
      self, mock):
    body = (
        "<img src='mock_image' alt='Jupyter Notebook'/>"
        " data-ws-path='terminals/websocket/1'"
        )
    mock.register_uri(
        'GET',
        'http://%s/%s' % (_TARGET_URL, _TARGET_PATH),
        content=body.encode('utf-8'),
        status_code=200,
    )
    network_service = network_service_pb2.NetworkService(
        network_endpoint=network_endpoint_utils.for_hostname_and_port(
            _TARGET_URL, _TARGET_PORT
        ),
        transport_protocol=network_pb2.TransportProtocol.TCP,
        software=software_pb2.Software(name='Jupyter Notebook'),
        service_name='http',
    )
    target_info = reconnaissance_pb2.TargetInfo(
        network_endpoints=[network_service.network_endpoint]
    )
    detection_reports = self.detector.Detect(target_info, [network_service])
    self.assertEqual(
        detection_pb2.DetectionReport(
            target_info=target_info,
            network_service=network_service,
            detection_status=detection_pb2.DetectionStatus.VULNERABILITY_VERIFIED,
            vulnerability=vulnerability_pb2.Vulnerability(
                main_id=vulnerability_pb2.VulnerabilityId(
                    publisher='GOOGLE', value='JUPYTER_NOTEBOOK_EXPOSED_UI'
                ),
                severity=vulnerability_pb2.Severity.CRITICAL,
                title='Jupyter Notebook Exposed Ui',
                recommendation=_VULN_REMEDIATION,
                description=('Jupyter Notebook is not password or token'
                             ' protected'),
            ),
        ),
        detection_reports.detection_reports[0],
    )

  @requests_mock.mock()
  def test_detect_when_jupyter_latest_v_does_not_redirect_to_login_returns_vuln(
      self, mock):
    body = (
        "<img src='mock_image' alt='Jupyter Notebook'/>"
        " data-ws-path='jupyter-config-data'"
        )
    mock.register_uri(
        'GET',
        'http://%s/%s' % (_TARGET_URL, _TARGET_PATH),
        content=body.encode('utf-8'),
        status_code=200,
    )
    network_service = network_service_pb2.NetworkService(
        network_endpoint=network_endpoint_utils.for_hostname_and_port(
            _TARGET_URL, _TARGET_PORT
        ),
        transport_protocol=network_pb2.TransportProtocol.TCP,
        software=software_pb2.Software(name='Jupyter Notebook'),
        service_name='http',
    )
    target_info = reconnaissance_pb2.TargetInfo(
        network_endpoints=[network_service.network_endpoint]
    )
    detection_reports = self.detector.Detect(target_info, [network_service])
    self.assertEqual(
        detection_pb2.DetectionReport(
            target_info=target_info,
            network_service=network_service,
            detection_status=detection_pb2.DetectionStatus.VULNERABILITY_VERIFIED,
            vulnerability=vulnerability_pb2.Vulnerability(
                main_id=vulnerability_pb2.VulnerabilityId(
                    publisher='GOOGLE', value='JUPYTER_NOTEBOOK_EXPOSED_UI'
                ),
                severity=vulnerability_pb2.Severity.CRITICAL,
                title='Jupyter Notebook Exposed Ui',
                recommendation=_VULN_REMEDIATION,
                description=('Jupyter Notebook is not password or token'
                             ' protected'),
            ),
        ),
        detection_reports.detection_reports[0],
    )

  @requests_mock.mock()
  def test_detect_when_jupyter_redirects_to_login_returns_no_vuln(self, mock):
    body = 'Token authentication is enabled'
    mock.register_uri(
        'GET',
        'http://%s/%s' % (_TARGET_URL, _TARGET_PATH),
        content=body.encode('utf-8'),
        status_code=200,
    )
    network_service = network_service_pb2.NetworkService(
        network_endpoint=network_endpoint_utils.for_hostname_and_port(
            _TARGET_URL, _TARGET_PORT
        ),
        transport_protocol=network_pb2.TransportProtocol.TCP,
        software=software_pb2.Software(name='Jupyter Notebook'),
    )
    target_info = reconnaissance_pb2.TargetInfo(
        network_endpoints=[network_service.network_endpoint]
    )
    detection_reports = self.detector.Detect(target_info, [network_service])
    self.assertEmpty(detection_reports.detection_reports)

  @requests_mock.mock()
  def test_detect_when_jupyter_is_token_protected_returns_no_vuln(self, mock):
    body = 'Jupyter Notebook login page.'
    mock.register_uri(
        'GET',
        'http://%s/%s' % (_TARGET_URL, _TARGET_PATH),
        content=body.encode('utf-8'),
        status_code=200,
    )
    network_service = network_service_pb2.NetworkService(
        network_endpoint=network_endpoint_utils.for_hostname_and_port(
            _TARGET_URL, _TARGET_PORT
        ),
        transport_protocol=network_pb2.TransportProtocol.TCP,
        software=software_pb2.Software(name='Jupyter Notebook'),
    )
    target_info = reconnaissance_pb2.TargetInfo(
        network_endpoints=[network_service.network_endpoint]
    )
    detection_reports = self.detector.Detect(target_info, [network_service])
    self.assertEmpty(detection_reports.detection_reports)

  @requests_mock.mock()
  def test_detect_when_target_is_not_jupyter_returns_no_vuln(self, mock):
    mock.register_uri(
        'GET',
        'http://%s/%s' % (_TARGET_URL, _TARGET_PATH),
        status_code=200,
    )
    network_service = network_service_pb2.NetworkService(
        network_endpoint=network_endpoint_utils.for_hostname_and_port(
            _TARGET_URL, _TARGET_PORT
        ),
        transport_protocol=network_pb2.TransportProtocol.TCP,
        software=software_pb2.Software(name='WordPress'),
        service_name='http',
    )
    target_info = reconnaissance_pb2.TargetInfo(
        network_endpoints=[network_service.network_endpoint]
    )
    detection_reports = self.detector.Detect(target_info, [network_service])
    self.assertEmpty(detection_reports.detection_reports)

  def test_detect_with_exception_returns_no_vuln(self):
    self.client.send = unittest.mock.MagicMock(return_value=Exception())
    detector = jupyter_exposed_ui_detector.JupyterExposedUiDetector(
        self.client, PayloadGenerator(
            PayloadSecretGenerator(),
            get_parsed_payload(),
            TcsClient('', 80, '', self.client))
    )
    network_service = network_service_pb2.NetworkService(
        network_endpoint=network_endpoint_utils.for_hostname_and_port(
            _TARGET_URL, _TARGET_PORT
        ),
        transport_protocol=network_pb2.TransportProtocol.TCP,
        software=software_pb2.Software(name='Jupyter Notebook'),
        service_name='http',
    )
    target_info = reconnaissance_pb2.TargetInfo(
        network_endpoints=[network_service.network_endpoint]
    )
    detection_reports = detector.Detect(target_info, [network_service])
    self.assertEmpty(detection_reports.detection_reports)

  @requests_mock.mock()
  def test_detect_when_empty_network_service_returns_empty_report(self, mock):
    mock.register_uri(
        'GET',
        'http://%s/%s' % (_TARGET_URL, _TARGET_PATH),
        status_code=200,
    )
    detection_reports = self.detector.Detect(
        reconnaissance_pb2.TargetInfo(), [])
    self.assertEmpty(detection_reports.detection_reports)

if __name__ == '__main__':
  absltest.main()
