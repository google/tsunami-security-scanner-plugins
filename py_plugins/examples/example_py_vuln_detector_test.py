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
"""Tests for example_py_vuln_detector."""

from absl.testing import absltest

from google3.google.protobuf import timestamp_pb2
from google3.third_party.java_src.tsunami.plugin_server.py import tsunami_plugin
from google3.third_party.java_src.tsunami.proto import detection_pb2
from google3.third_party.java_src.tsunami.proto import network_service_pb2
from google3.third_party.java_src.tsunami.proto import reconnaissance_pb2
from google3.third_party.java_src.tsunami.proto import vulnerability_pb2
from google3.third_party.tsunami_plugins.py_plugins.examples import example_py_vuln_detector


class ExamplePyVulnDetectorTest(absltest.TestCase):

  def setUp(self):
    super().setUp()
    self.detector = example_py_vuln_detector.ExamplePyVulnDetector()

  def test_get_plugin_definition_always_returns_example_plugin_definition(self):
    self.assertEqual(
        tsunami_plugin.PluginDefinition(
            info=example_py_vuln_detector.PluginInfo(
                type=example_py_vuln_detector.PluginInfo.VULN_DETECTION,
                name='ExamplePyVulnDetector',
                version='0.1',
                description='This is an example python plugin',
                author='Alice (alice@company.com)')),
        self.detector.GetPluginDefinition())

  def test_detect_always_returns_vulnerability(self):
    target = reconnaissance_pb2.TargetInfo()
    service = network_service_pb2.NetworkService()
    detection_reports = self.detector.Detect(target, [service])
    self.assertLen(detection_reports.detection_reports, 1)
    self.assertEqual(
        detection_pb2.DetectionReport(
            target_info=target,
            network_service=service,
            detection_timestamp=timestamp_pb2.Timestamp().GetCurrentTime(),
            detection_status=detection_pb2.VULNERABILITY_VERIFIED,
            vulnerability=vulnerability_pb2.Vulnerability(
                main_id=vulnerability_pb2.VulnerabilityId(
                    publisher='vulnerability_id_publisher',
                    value='VULNERABILITY_ID'),
                severity=vulnerability_pb2.CRITICAL,
                title='Vulnerability Title',
                description='Verbose description of the issue',
                recommendation='Verbose recommended solution',
                additional_details=[
                    vulnerability_pb2.AdditionalDetail(
                        text_data=vulnerability_pb2.TextData(
                            text='Some additional technical details.'))
                ])), detection_reports.detection_reports[0])


if __name__ == '__main__':
  absltest.main()
