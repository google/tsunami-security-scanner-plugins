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
package com.google.tsunami.plugins.detectors.credentials.genericweakcredentialdetector.clients.hydra;

import static com.google.common.base.Preconditions.checkArgument;

import com.beust.jcommander.Parameter;
import com.beust.jcommander.Parameters;
import com.google.common.annotations.VisibleForTesting;
import com.google.common.base.Ascii;
import com.google.common.collect.ImmutableList;
import com.google.common.collect.Lists;
import com.google.errorprone.annotations.CanIgnoreReturnValue;
import com.google.tsunami.common.cli.CliOption;
import com.google.tsunami.common.command.CommandExecutor;
import com.google.tsunami.common.command.CommandExecutorFactory;
import com.google.tsunami.common.data.NetworkEndpointUtils;
import com.google.tsunami.plugins.detectors.credentials.genericweakcredentialdetector.clients.hydra.HydraAnnotations.EnableHydra;
import com.google.tsunami.plugins.detectors.credentials.genericweakcredentialdetector.clients.hydra.HydraAnnotations.HydraBinaryPath;
import com.google.tsunami.plugins.detectors.credentials.genericweakcredentialdetector.clients.hydra.data.HydraRun;
import com.google.tsunami.plugins.detectors.credentials.genericweakcredentialdetector.clients.hydra.parser.NormalParser;
import com.google.tsunami.plugins.detectors.credentials.genericweakcredentialdetector.proto.TargetService;
import com.google.tsunami.plugins.detectors.credentials.genericweakcredentialdetector.provider.TestCredential;
import com.google.tsunami.proto.NetworkEndpoint;
import java.io.File;
import java.io.FileInputStream;
import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Paths;
import java.nio.file.StandardOpenOption;
import java.util.ArrayList;
import java.util.List;
import java.util.concurrent.CompletableFuture;
import java.util.concurrent.ExecutionException;
import javax.inject.Inject;

/**
 * Client for the open-source hydra tool. Hydra is a network authentication tool that supports a
 * wide range of protocols as well as paral. For more details, check <a
 * href="https://github.com/vanhauser-thc/thc-hydra">link</a>.
 *
 * <p>The following client focuses on simplicity and allows targeting one service at a time.
 *
 * <p>Example brute forcing host 1.1.1.1 ssh service on port 2222:
 *
 * <pre>
 *    HydraClient client =
 *         new HydraClient(hydraFile.getAbsolutePath())
 *             .withNetworkEndpoint(NetworkEndpoints.forIp("1.1.1.1"))
 *             .onTargetService(TargetService.RDP)
 *             .usingUsernamePasswordPair(ImmutableList.of(
 *                  TestCredential.create("root", Optional.of("toor"),
 *                  TestCredential.create("admin", Optional.of("password"))));
 * </pre>
 */
public class HydraClient {
  private static final String CREDS = "creds";

  private final String hydraBinaryPath;
  private final File reportFile;
  private final File credFile;
  private final HydraClientCliOptions clioptions;
  private final boolean enableHydra;
  private boolean quitHydraCrackingAfterOneFound = false;
  private ImmutableList<TestCredential> testCredentials;
  private TargetService targetService;
  private NetworkEndpoint networkEndpoint;

  /** HydraClientCliOptions provides configuration options for {@link HydraClient}. */
  @Parameters(separators = "=")
  public static class HydraClientCliOptions implements CliOption {
    @Parameter(
        names = "--hydra-parallel-connects",
        description = "the number of connects in parallel (default: 16)")
    protected int parallelConnects;

    @Override
    public void validate() {}
  }

  /** Constructor using hydra runtime path. */
  @Inject
  @VisibleForTesting
  HydraClient(
      @HydraBinaryPath String hydraBinaryPath,
      @EnableHydra boolean enableHydra,
      HydraClientCliOptions options)
      throws IOException {
    this(
        hydraBinaryPath,
        enableHydra,
        File.createTempFile(CREDS, ".txt"),
        File.createTempFile("hydra", ".report"),
        options);
  }

  /**
   * Client constructor.
   *
   * @param hydraBinaryPath Path to the hydra binary.
   * @param report File to write Hydra output to.
   * @param options Cli options passed by JCommander framework.
   */
  public HydraClient(
      String hydraBinaryPath,
      boolean enableHydra,
      File creds,
      File report,
      HydraClientCliOptions options) {
    if (enableHydra) {
      checkArgument(
          Files.exists(Paths.get(hydraBinaryPath)), "Binary %s do not exist", hydraBinaryPath);
    }
    this.hydraBinaryPath = hydraBinaryPath;
    this.enableHydra = enableHydra;
    this.reportFile = report;
    this.clioptions = options;
    this.credFile = creds;
  }

  /**
   * Start brute forcing by executing the hydra binary, waits for the process to finish and then
   * parses and returns results.
   */
  public HydraRun run() throws IOException, InterruptedException, ExecutionException {
    createCredInputFiles();
    List<String> argList = buildRunCommandArgs();
    String[] args = argList.toArray(new String[0]);
    CommandExecutor commandExecutor = CommandExecutorFactory.create(args);
    Process currentProcess = commandExecutor.executeAsync();
    // Wait for all descendants to finish as hydra creates many threads
    currentProcess.onExit().join();
    currentProcess.descendants().map(ProcessHandle::onExit).forEach(CompletableFuture::join);
    return NormalParser.parse(new FileInputStream(reportFile));
  }

  private void createCredInputFiles() throws IOException {
    for (TestCredential cred : testCredentials) {
      Files.writeString(
          credFile.toPath(),
          String.format(
              "%s:%s%s", cred.username(), cred.password().orElse(""), System.lineSeparator()),
          StandardOpenOption.APPEND);
    }
  }

  public NetworkEndpoint getNetworkEndpoint() {
    return networkEndpoint;
  }

  public TargetService getTargetService() {
    return targetService;
  }

  public boolean isEnableHydra() {
    return enableHydra;
  }

  public ImmutableList<TestCredential> getTestCredentials() {
    return testCredentials;
  }

  public List<String> buildRunCommandArgs() {
    ArrayList<String> runCommandArgs = Lists.newArrayList();
    runCommandArgs.add(hydraBinaryPath);
    runCommandArgs.add("-C");
    runCommandArgs.add(credFile.getAbsolutePath());

    if (quitHydraCrackingAfterOneFound) {
      runCommandArgs.add("-F");
    }

    if (clioptions != null && clioptions.parallelConnects > 0) {
      runCommandArgs.add("-t");
      runCommandArgs.add(String.valueOf(clioptions.parallelConnects));
    }

    if (NetworkEndpointUtils.isIpV6Endpoint(networkEndpoint)) {
      runCommandArgs.add("-6");
    }

    runCommandArgs.add("-o");
    runCommandArgs.add(reportFile.getAbsolutePath());

    runCommandArgs.add(buildServiceCommandValue(networkEndpoint));

    return runCommandArgs;
  }

  private String buildServiceCommandValue(NetworkEndpoint networkEndpoint) {
    // hydra ... <server> -s <port_num> <service>
    return String.format(
        "%s://%s", getFlag(targetService), NetworkEndpointUtils.toUriAuthority(networkEndpoint));
  }

  /**
   * Enables brute forcing using a pair of username and password.
   *
   * @param testCredentials A list of username/password credentials.
   */
  @CanIgnoreReturnValue
  public HydraClient usingUsernamePasswordPair(List<TestCredential> testCredentials) {
    this.testCredentials = ImmutableList.copyOf(testCredentials);
    return this;
  }

  /**
   * Sets the network endpoints to brute force.
   *
   * @param networkEndpoint The network endpoint to scan.
   */
  @CanIgnoreReturnValue
  public HydraClient withNetworkEndpoint(NetworkEndpoint networkEndpoint) {
    this.networkEndpoint = networkEndpoint;
    return this;
  }

  /**
   * Sets the target service to brute force.
   *
   * @param targetService Target service to brute force.
   */
  @CanIgnoreReturnValue
  public HydraClient onTargetService(TargetService targetService) {
    this.targetService = targetService;
    return this;
  }

  /** Stops brute force once a working one is found. */
  @CanIgnoreReturnValue
  public HydraClient withQuitCrackingAfterOneFound() {
    this.quitHydraCrackingAfterOneFound = true;
    return this;
  }

  private static String getFlag(TargetService service) {
    return Ascii.toLowerCase(service.name());
  }
}
