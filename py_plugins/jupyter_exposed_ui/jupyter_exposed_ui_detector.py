
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
"""A Tsunami plugin for detecting exposed UI from Jupyter."""

from absl import logging
from google.protobuf import timestamp_pb2
import tsunami_plugin
from common.data import network_service_utils
from common.net.http.http_client import HttpClient
from common.net.http.http_request import HttpRequest
from common.net.http.http_status import HttpStatus
import detection_pb2
import plugin_representation_pb2
import vulnerability_pb2

_VULN_DESCRIPTION = (
    'This detector checks whether a unauthenticated Jupyter Notebook is'
    ' exposed. Jupyter allows by design to run arbitrary code on the host'
    ' machine. Having it exposed puts the hosting VM at risk of RCE.'
)
_VULN_REMEDIATION = (
    'Either:\n'
    '- Use Google Colab (go/colab) for Google internal use cases.\n'
    '- If it is necessary to keep running this instance of Jupyter, DO NOT'
    ' expose it externally, in favor of using SSH tunnels to access it. In'
    ' addition, the service should only listen on localhost (127.0.0.1), and'
    ' consider restrict the access to the Jupyter Notebook using an'
    ' authentication method. See'
    ' https://jupyter-notebook.readthedocs.io/en/stable/security.html \n'
    '\n Note that this recommendation also applies if Jupyter was set up using'
    ' Docker.\n'
)


class JupyterExposedUiDetector(tsunami_plugin.VulnDetector):
  """A TsunamiPlugin that detects exposed UI on the Jupyter target."""

  def __init__(self, http_client: HttpClient, _):
    self.http_client = http_client

  def GetPluginDefinition(self) -> tsunami_plugin.PluginDefinition:
    """Defines the PluginDefinition for JupyterExposedUiDetector.

    Returns:
      The PluginDefinition used for the Tsunami engine to identify this plugin.
    """
    return tsunami_plugin.PluginDefinition(
        info=plugin_representation_pb2.PluginInfo(
            type=plugin_representation_pb2.PluginInfo.VULN_DETECTION,
            name='JupyterExposedUiDetector',
            version='0.1',
            description=_VULN_DESCRIPTION,
            author='Tsunami Team (tsunami-dev@google.com)',
        )
    )

  def Detect(
      self,
      target: tsunami_plugin.TargetInfo,
      matched_services: list[tsunami_plugin.NetworkService],
  ) -> tsunami_plugin.DetectionReportList:
    """Run detection logic for the Jupyter target.

    Args:
      target: TargetInfo about Jupyter.
      matched_services: A list of network services whose vulnerabilities could
        be detected by this plugin.

    Returns:
      A tsunami_plugin.DetectionReportList for all the vulnerabilities of the
      scanning target.
    """
    logging.info('JupyterExposedUiDetector starts detecting.')
    vulnerable_services = [
        s for s in matched_services if network_service_utils.is_web_service(s)
    ]
    return detection_pb2.DetectionReportList(
        detection_reports=[
            self._BuildDetectionReport(target, service)
            for service in vulnerable_services
            if self._IsServiceVulnerable(service)
        ]
    )

  def _IsServiceVulnerable(
      self, network_service: tsunami_plugin.NetworkService
  ) -> bool:
    url = (
        network_service_utils.build_web_application_root_url(network_service)
        + 'terminals/1'
    )
    try:
      response = self.http_client.send(
          HttpRequest.get(url).with_empty_headers().build(), network_service
      )
      return response.status == HttpStatus.OK and (
          'Jupyter Notebook' in response.body_string()
          and (
              'terminals/websocket/1' in response.body_string()
              or 'jupyter-config-data' in response.body_string()
          )
          and 'authentication is enabled' not in response.body_string()
      )
    except Exception:  # pylint: disable=broad-exception-caught
      logging.exception('Unable to query %s', url)
    return False

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
                publisher='GOOGLE', value='JUPYTER_NOTEBOOK_EXPOSED_UI'
            ),
            severity=vulnerability_pb2.Severity.CRITICAL,
            title='Jupyter Notebook Exposed Ui',
            recommendation=_VULN_REMEDIATION,
            description='Jupyter Notebook is not password or token protected',
        ),
    )
