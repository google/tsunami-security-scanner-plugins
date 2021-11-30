/*
 * Copyright 2020 Google LLC
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
package com.google.tsunami.plugins.portscan.nmap.option;

import com.beust.jcommander.Parameter;
import com.beust.jcommander.Parameters;
import com.google.tsunami.common.cli.CliOption;
import com.google.tsunami.plugins.portscan.nmap.option.validator.PortRangeValidator;
import java.util.List;

/** Command line arguments for the Nmap port scanner plugin. */
@Parameters(separators = "=")
public final class NmapPortScannerCliOptions implements CliOption {
  @Parameter(
      names = "--root-paths-target",
      description = "A list of application root paths to scan on the scanning target.")
  public List<String> rootPathsTarget;

  @Parameter(
      names = "--port-ranges-target",
      description =
          "A list of port ranges to scan on the scanning target. Specify the protocol to use by"
              + " prepending 'T:' (TCP), 'U:' (UDP) or 'S:' (SCTP).",
      validateWith = PortRangeValidator.class)
  // Splitting and conversion is done by the NmapPortScanner itself.
  public String portRangesTarget;

  @Override
  public void validate() {}
}
