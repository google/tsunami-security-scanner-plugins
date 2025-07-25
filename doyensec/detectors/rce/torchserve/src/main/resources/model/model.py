#!/usr/bin/env python

# Copyright 2023 Google LLC
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#     https://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.

"""
This Python script is part of a vulnerability detection plugin for Google's Tsunami Security Scanner.
The plugin is designed to assess the Remote Code Execution (RCE) capability of systems by deploying
this script as a model in TorchServe. It handles specific HTTP request headers to simulate various
actions without creating additional attack surface. The script's behaviors include:

- Calculating an MD5 hash for the 'tsunami-execute' header value to simulate command execution.
- Sending a GET request to a specified URL in the 'tsunami-callback' header to validate data exfiltration.
- Collecting basic system information in response to the 'tsunami-info' header for aiding vulnerability mitigation.
- Logging the value of the 'tsunami-log' header to the container's standard output.

This script is a part of an automated testing process and does not perform any malicious activities.
In case of unexpected termination of the Tsunami plugin, this script may remain on the system. To verify
its origin and purpose, please refer to the following repositories:

- Tsunami Security Scanner: https://github.com/google/tsunami-security-scanner
- Tsunami RCE Plugin for TorchServe: https://github.com/google/tsunami-security-scanner-plugins/tree/master/doyensec/detectors/rce/torchserve

The plugin attempts to clean up by removing the model post-execution, with the primary output being a log entry.
"""

import hashlib
import urllib.request
import platform
import json

def produce_conformant_output(string, length):
    """Produce a list of length `length` with `string` as the first element."""
    return [string] + ["Ok"] * (length - 1)

def handle(data, context):
    """Handle a request to the model. Echoes the input string, unless special headers are set."""
    if (context is None) or (data is None):
        return None

    headers = context.get_all_request_header(0)
    if headers is None:
        return data

    response = data[0]
    if "tsunami-execute" in headers:
        # Simulate command execution by calculating an MD5 hash of the headers value
        response = hashlib.md5(headers["tsunami-execute"].encode()).hexdigest()
    elif "tsunami-callback" in headers:
        # Validates data exfiltration by sending a GET request to the specified URL
        try:
            urllib.request.urlopen(headers["tsunami-callback"])
        except:
            pass
    elif "tsunami-info" in headers:
        # Collects basic system info to simplify vulnerability mitigation
        info = {
            "platform": platform.platform(),
            "python": platform.python_version(),
            "hostname": platform.node()
        }
        response = json.dumps(info)

    elif "tsunami-log" in headers:
        # Logs the value of the 'tsunami-log' header to the container's standard output
        print(headers["tsunami-log"])

    return produce_conformant_output(response, len(data))
