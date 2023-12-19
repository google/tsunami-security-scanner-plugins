package com.google.tsunami.plugins.detectors.rce.torchserve;

import com.google.tsunami.common.config.annotations.ConfigProperties;

@ConfigProperties("plugins.doyensec.torchserve")
public class TorchServeManagementApiConfig {
  // --torchserve-management-api-mode
  public String exploitationMode = "auto";

  // --torchserve-management-api-model-static-url
  public String staticUrl;

  // --torchserve-management-api-local-bind-host
  public String localBindHost;
  // --torchserve-management-api-local-bind-port
  public int localBindPort;
  // --torchserve-management-api-local-accessible-url
  public String localAccessibleUrl;
}
