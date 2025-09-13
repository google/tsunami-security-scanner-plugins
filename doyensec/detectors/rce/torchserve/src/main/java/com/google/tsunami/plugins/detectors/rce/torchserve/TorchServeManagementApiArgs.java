/*
 * Copyright 2023 Google LLC
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 * http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */
package com.google.tsunami.plugins.detectors.rce.torchserve;

import com.beust.jcommander.Parameter;
import com.beust.jcommander.Parameters;
import com.google.tsunami.common.cli.CliOption;

@Parameters(separators = "=")
public class TorchServeManagementApiArgs implements CliOption {
  // Default mode is SSRF, which uses regular Tsunami Callback server to confirm vulnerability.
  // Note that it does not observe the code execution on the target directly.
  @Parameter(
      names = "--torchserve-management-api-mode",
      description =
          "Exploitation mode used to confirm vulnerability [auto (default), basic, ssrf, static,"
              + " local]")
  public String exploitationMode;

  // Static mode requires an infected model to be hosted on a static URL.
  @Parameter(
      names = "--torchserve-management-api-model-static-url",
      description = "Static URL of the infected model, to be added to TorchServe.")
  public String staticUrl;

  // Local mode means the plugin will attempt to serve an infected model directly. Bind host
  // and port indicate where plugin will bind the HTTP server to, accessible URL is the URL
  // of the server from the outside.
  @Parameter(
      names = "--torchserve-management-api-local-bind-host",
      description = "Path to the infected model, to be added to TorchServe.")
  public String localBindHost;

  @Parameter(
      names = "--torchserve-management-api-local-bind-port",
      description = "Port to bind the local TorchServe instance to.")
  public int localBindPort;

  @Parameter(
      names = "--torchserve-management-api-local-accessible-url",
      description = "URL of the local TorchServe instance accessible from the outside.")
  public String localAccessibleUrl;

  @Override
  public void validate() {
    // Nothing to do here, because we need to merge the config with the CLI args and it cannot be
    // done here.
  }
}
