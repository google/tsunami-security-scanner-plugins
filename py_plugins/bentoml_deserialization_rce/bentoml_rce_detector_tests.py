# Copyright 2024 Google LLC
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
"""Tests for Cve20242912Detector."""
import unittest.mock as umock

import requests_mock
from absl.testing import absltest

import network_pb2
import network_service_pb2
import plugin_representation_pb2
import reconnaissance_pb2
import software_pb2
import tsunami_plugin
from common.data import network_endpoint_utils
from common.net.http.requests_http_client import RequestsHttpClientBuilder
from plugin.payload.payload_generator import PayloadGenerator
from plugin.payload.payload_secret_generator import PayloadSecretGenerator
from plugin.payload.payload_utility import get_parsed_payload
from plugin.tcs_client import TcsClient
from py_plugins.bentoml_rce_detector import Cve20242912Detector
from py_plugins.bentoml_rce_detector import _VULN_DESCRIPTION

# Callback server
_CBID = '04041e8898e739ca33a250923e24f59ca41a8373f8cf6a45a1275f3b'
_IP_ADDRESS = '127.0.0.1'
_PORT = 8000
_SECRET = 'a3d9ed89deadbeef'
_CALLBACK_URL = 'http://%s:%s/%s' % (_IP_ADDRESS, _PORT, _CBID)

# Vulnerable target
_TARGET_URL = 'vuln-target.com'
_TARGET_PORT = 9001

_DOCS_BODY = '''{
            "openapi": "3.0.2",
            "paths": {
                "/summarize": {
                    "post": {
                        "tags": [
                            "Service APIs"
                        ]
                    }
                }
            },
            "servers": [
                {
                    "url": "."
                }
            ]
        }'''.encode('utf-8')


class Cve20242912DetectorTest(absltest.TestCase):
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
        self.detector = Cve20242912Detector(
            request_client, self.payload_generator
        )

    @requests_mock.mock()
    def test_detect_vuln_target_with_callback_server_returns_empty(self, mock):
        # detector without callback
        disabled_client = TcsClient('', 0, '', RequestsHttpClientBuilder().build())
        self.detector.payload_generator = PayloadGenerator(
            self.psg, self.payloads, disabled_client
        )
        mock.register_uri(
            'GET',
            'http://%s:%s/docs.json' % (_TARGET_URL, _TARGET_PORT),
            content=_DOCS_BODY,
            status_code=200,
        )
        mock.register_uri(
            'POST', 'http://%s:%s/summarize' % (_TARGET_URL, _TARGET_PORT),
            status_code=200
        )
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

    #  OK
    def test_get_plugin_definition_returns_plugin_definition(self):
        self.assertEqual(
            tsunami_plugin.PluginDefinition(
                info=plugin_representation_pb2.PluginInfo(
                    type=plugin_representation_pb2.PluginInfo.VULN_DETECTION,
                    name='Cve20242912VulnDetector',
                    version='1.0',
                    description=_VULN_DESCRIPTION,
                    author='secureness (nosecureness@gmail.com)',
                )
            ),
            self.detector.GetPluginDefinition(),
        )

    @requests_mock.mock()
    def test_detect_healthy_target_with_callback_server_returns_empty(self, mock):
        # detector without callback
        disabled_client = TcsClient('', 0, '', RequestsHttpClientBuilder().build())
        self.detector.payload_generator = PayloadGenerator(
            self.psg, self.payloads, disabled_client
        )
        mock.register_uri(
            'GET',
            'http://%s:%s/docs.json' % (_TARGET_URL, _TARGET_PORT),
            content=_DOCS_BODY,
            status_code=200,
        )
        mock.register_uri(
            'POST', 'http://%s:%s/summarize' % (_TARGET_URL, _TARGET_PORT),
            status_code=200
        )
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


if __name__ == '__main__':
    absltest.main()
