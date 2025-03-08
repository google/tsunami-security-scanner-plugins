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
import pickle
import threading
import time

import detection_pb2
import network_pb2
import network_service_pb2
import plugin_representation_pb2
import reconnaissance_pb2
import requests_mock
import software_pb2
import tsunami_plugin
import vulnerability_pb2
from absl.testing import absltest

import py_plugins.ragflow_deserialization_rce as ragflow_rce
from common.data import network_endpoint_utils
from common.net.http.requests_http_client import RequestsHttpClientBuilder
from plugin.payload.payload_generator import PayloadGenerator
from plugin.payload.payload_secret_generator import PayloadSecretGenerator
from plugin.payload.payload_utility import get_parsed_payload
from plugin.tcs_client import TcsClient
import unittest.mock as umock
from multiprocessing.connection import Listener

from py_plugins.ragflow_deserialization_rce import RagFlowRceDetector

# Callback server
_CBID = "04041e8898e739ca33a250923e24f59ca41a8373f8cf6a45a1275f3b"
_IP_ADDRESS = "127.0.0.1"
_PORT = 8000
_SECRET = "a3d9ed89deadbeef"
_CALLBACK_URL = "http://%s:%s/%s" % (_IP_ADDRESS, _PORT, _CBID)

# Vulnerable target
_TARGET_IP = "127.0.0.1"
_TARGET_PORT = 7861


class RPCHandler:
    def __init__(self):
        self._functions = {}

    def register_function(self, func):
        self._functions[func.__name__] = func

    def handle_connection(self, address):
        sock = Listener(address, authkey=b"infiniflow-token4kevinhu")
        connection = sock.accept()
        try:
            while True:
                # Receive a message
                func_name, args, kwargs = pickle.loads(connection.recv())
                # Run the RPC and send a response
                try:
                    r = self._functions[func_name](*args, **kwargs)
                    connection.send(pickle.dumps(r))
                except Exception as e:
                    connection.send(pickle.dumps(e))
        except EOFError:
            pass
        except ValueError:
            # Ignore unpickling errors
            pass


def rpc_server(handler, address):
    try:
        t = threading.Thread(target=handler.handle_connection, args=(address,))
        t.daemon = True
        t.start()
    except Exception as e:
        print("【EXCEPTION】:", str(e))


class RagFlowRceDetectorTest(absltest.TestCase):

    def setUp(self):
        super().setUp()
        # payload generator and client with callback
        request_client = RequestsHttpClientBuilder().build()
        self.psg = PayloadSecretGenerator()
        self.psg.generate = umock.MagicMock(return_value=_SECRET)
        callback_client = TcsClient(_IP_ADDRESS, _PORT, _CALLBACK_URL, request_client)
        self.payloads = get_parsed_payload()
        self.payload_generator = PayloadGenerator(
            self.psg, self.payloads, callback_client
        )
        self.detector = ragflow_rce.RagFlowRceDetector(
            request_client, self.payload_generator
        )

    @requests_mock.mock()
    def test_detect_service_with_callback_server_returns_vul(self, mock):
        # response for callback server
        body = '{ "has_dns_interaction":false, "has_http_interaction":true}'
        mock.register_uri(
            "GET",
            "%s/?secret=%s" % (_CALLBACK_URL, _SECRET),
            content=body.encode("utf-8"),
        )
        network_service = network_service_pb2.NetworkService(
            network_endpoint=network_endpoint_utils.for_ip_and_port(
                _TARGET_IP, _TARGET_PORT
            ),
            transport_protocol=network_pb2.TransportProtocol.TCP,
            software=software_pb2.Software(name="tcp"),
        )
        target_info = reconnaissance_pb2.TargetInfo(
            network_endpoints=[network_service.network_endpoint]
        )

        rpc_server(RPCHandler(), (_TARGET_IP, _TARGET_PORT))
        time.sleep(1)
        ragflow_rce._SLEEP_TIME_SEC = 5
        detection_reports = self.detector.Detect(target_info, [network_service])
        detection_reports.detection_reports[0]
        self.assertEqual(
            detection_pb2.DetectionReport(
                target_info=target_info,
                network_service=network_service,
                detection_status=detection_pb2.VULNERABILITY_VERIFIED,
                vulnerability=vulnerability_pb2.Vulnerability(
                    main_id=vulnerability_pb2.VulnerabilityId(
                        publisher="TSUNAMI_COMMUNITY", value="RagFlowRceDetector"
                    ),
                    severity=vulnerability_pb2.Severity.CRITICAL,
                    title="RAGFlow RPC Server Insecure Deserialization RCE",
                    recommendation=(
                        'Users should not expose "rag/llm/rpc_server.py" to the internet.'
                    ),
                    description=ragflow_rce._VULN_DESCRIPTION,
                ),
            ),
            detection_reports.detection_reports[0],
        )

    #  OK
    @requests_mock.mock()
    def test_detect_vuln_target_with_callback_server_returns_empty(self, mock):
        # detector without callback
        disabled_client = TcsClient("", 0, "", RequestsHttpClientBuilder().build())
        self.detector.payload_generator = PayloadGenerator(
            self.psg, self.payloads, disabled_client
        )
        mock.register_uri(
            "GET", "%s/?secret=%s" % (_CALLBACK_URL, _SECRET), status_code=404
        )
        network_service = network_service_pb2.NetworkService(
            network_endpoint=network_endpoint_utils.for_ip_and_port(
                _TARGET_IP, _TARGET_PORT
            ),
            transport_protocol=network_pb2.TransportProtocol.TCP,
            software=software_pb2.Software(name="http"),
            service_name="http",
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
                    name="RagFlowRceDetector",
                    version="1.0",
                    description=ragflow_rce._VULN_DESCRIPTION,
                    author="am0o0",
                )
            ),
            self.detector.GetPluginDefinition(),
        )


if __name__ == "__main__":
    absltest.main()
