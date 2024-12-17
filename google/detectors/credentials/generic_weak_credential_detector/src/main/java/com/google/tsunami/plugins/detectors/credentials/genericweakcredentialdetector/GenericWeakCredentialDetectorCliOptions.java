/*
 * Copyright 2022 Google LLC
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
package com.google.tsunami.plugins.detectors.credentials.genericweakcredentialdetector;

import com.beust.jcommander.Parameter;
import com.beust.jcommander.Parameters;
import com.google.tsunami.common.cli.CliOption;
import java.util.List;

/** Command line arguments for the Ncrack weak credential detector plugin. */
@Parameters(separators = "=")
public final class GenericWeakCredentialDetectorCliOptions implements CliOption {
  @Parameter(
      names = "--ncrack-excluded-target-services",
      description =
          "A list of service targets to exclude in the ncrack weak"
              + " credential scan. Each service target should be the String value of TargetService"
              + " enum. ")
  public List<String> excludedTargetServices;

  @Parameter(
      names = "--enable-hydra",
      description =
          "Enable hydra for weak credential scanning, given that hydra is installed in the"
              + " environment.")
  public boolean enableHydra;

  @Override
  public void validate() {}
}
