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
package com.google.tsunami.plugins.detectors.credentials.genericweakcredentialdetector.clients.ncrack;

import static com.google.common.base.Preconditions.checkArgument;

import com.beust.jcommander.Parameter;
import com.beust.jcommander.Parameters;
import com.google.common.base.Ascii;
import com.google.common.collect.ImmutableList;
import com.google.common.collect.Lists;
import com.google.common.collect.Multimap;
import com.google.errorprone.annotations.CanIgnoreReturnValue;
import com.google.tsunami.common.cli.CliOption;
import com.google.tsunami.common.command.CommandExecutor;
import com.google.tsunami.common.command.CommandExecutorFactory;
import com.google.tsunami.common.data.NetworkEndpointUtils;
import com.google.tsunami.plugins.detectors.credentials.genericweakcredentialdetector.clients.ncrack.data.NcrackRun;
import com.google.tsunami.plugins.detectors.credentials.genericweakcredentialdetector.clients.ncrack.parser.NormalParser;
import com.google.tsunami.plugins.detectors.credentials.genericweakcredentialdetector.proto.TargetService;
import com.google.tsunami.proto.NetworkEndpoint;
import java.io.File;
import java.io.FileInputStream;
import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Paths;
import java.util.ArrayList;
import java.util.Collection;
import java.util.List;
import java.util.Optional;
import java.util.concurrent.ExecutionException;
import java.util.concurrent.Executor;
import javax.inject.Inject;

/**
 * Client for the open-source ncrack tool. Ncrack is a network authentication tool with a high-speed
 * parallel engine and modular architecture. For more details, check <a
 * href="https://nmap.org/ncrack/man.html">link</a>.
 *
 * <p>The following client focuses on simplicity and allows targeting one service at a time.
 *
 * <p>Example brute forcing host 1.1.1.1 ssh service on port 2222:
 *
 * <pre>
 *    NcrackClient client =
 *         new NcrackClient(ncrackFile.getAbsolutePath())
 *             .withTarget(IPv4Target.createFromString("1.1.1.1"))
 *             .onTargetService(TargetService.SSH)
 *             .usingUsernameList(ImmutableList.of("root", "admin"))
 *             .usingPasswordList(ImmutableList.of("toor", "password"));
 * </pre>
 *
 * <p>Some services may require extra parameters, like DB for MangoDB or Path for Wordpress
 * bruteforcing. The following is an example bruteforcing wordpress on host 1.1.1.1 and path
 * /blog/wp-login.php.
 *
 * <pre>
 *   NcrackClient client =
 *         new NcrackClient(ncrackFile.getAbsolutePath())
 *             .withTarget(IPv4Target.createFromString("1.1.1.1"))
 *             .onTargetService(TargetService.WORDPRESS)
 *             .withSslEnabled()
 *             .onPath("/blog/wp-login.php")
 *             .usingUsernameList(ImmutableList.of("root", "admin"))
 *             .usingPasswordList(ImmutableList.of("toor", "password"));
 * </pre>
 */
public class NcrackClient {
  /**
   * Timing templates controlling min connection limit (cl), max connection limit (CL),
   * authentication attempts per connection (at), delay between each connection initiation (cd),
   * caps number of connection attempts (cr) and timeout (to). For details on the values for each
   * template, check <a
   * href="https://github.com/nmap/ncrack/blob/0eb0d998eb0e76457bcf6b3b6253e81b8d3f822e/services.cc#L473">source
   * code</a>.
   */
  public enum TimingTemplate {
    PARANOID(0),
    SNEAKY(1),
    POLITE(2),
    NORMAL(3),
    AGGRESSIVE(4),
    INSANE(5);

    private final int value;

    TimingTemplate(int value) {
      this.value = value;
    }

    String getFlag() {
      // Ncrack supports two mode to set the timing template, -T<0-5> or
      // -T <paranoid|sneaky|polite|normal|aggressive|insane>.
      // To maintain coherence with the nmap client, we are using -T<0-5>.
      return String.format("-T%d", this.value);
    }
  }

  private final List<NetworkEndpoint> networkEndpoints = new ArrayList<>();
  private final String ncrackBinaryPath;
  private final File reportFile;
  private final NcrackClientCliOptions clioptions;
  private boolean pairwiseMode = false;
  private boolean sslEnabled = false;
  private boolean quitCrackingAfterOneFound = false;
  private Optional<String> db = Optional.empty();
  private Optional<String> domain = Optional.empty();
  private Optional<String> path = Optional.empty();
  private Optional<TimingTemplate> timing = Optional.empty();
  private ImmutableList<String> usernameList;
  private ImmutableList<String> passwordList;
  private TargetService targetService;

  /** NcrackClientCliOptions provides configuration options for {@link NcrackClient}. */
  @Parameters(separators = "=")
  public static class NcrackClientCliOptions implements CliOption {
    @Parameter(
        names = "--ncrack-max-time",
        description = "Maximum time for a single ncrack run. Example: --ncrack-max-time=3h")
    protected String maxTime;

    @Override
    public void validate() {}

    /**
     * Sets the maximum time for a single ncrack run.
     *
     * @param maxtime String to specify time in nmap timing format.
     */
    public NcrackClientCliOptions withMaxTime(String maxtime) {
      this.maxTime = maxtime;
      return this;
    }
  }

  /** Constructor using ncrack runtime path. */
  @Inject
  public NcrackClient(@NcrackBinaryPath String ncrackBinaryPath, NcrackClientCliOptions options)
      throws IOException {
    this(ncrackBinaryPath, File.createTempFile("ncrack", ".report"), options);
  }

  /**
   * Client constructor.
   *
   * @param ncrackBinaryPath Path to the ncrack binary.
   * @param report File to write Ncrack output to.
   * @param options Cli options passed by JCommander framework.
   */
  public NcrackClient(String ncrackBinaryPath, File report, NcrackClientCliOptions options) {
    checkArgument(
        Files.exists(Paths.get(ncrackBinaryPath)), "Binary %s do not exist", ncrackBinaryPath);
    this.ncrackBinaryPath = ncrackBinaryPath;
    this.reportFile = report;
    this.clioptions = options;
  }

  /**
   * Start brute forcing by executing the ncrack binary, waits for the process to finish and then
   * parses and returns results.
   *
   * @param executor Executor to collect process output and error streams. Important to use an
   *     executor suitable for long running and IO blocking tasks. {@link
   *     java.util.concurrent.ThreadPoolExecutor} is a viable option.
   */
  public NcrackRun run(Executor executor)
      throws IOException, InterruptedException, ExecutionException {
    List<String> argList = buildRunCommandArgs();
    String[] args = argList.toArray(new String[0]);
    CommandExecutor commandExecutor = CommandExecutorFactory.create(args);
    Process currentProcess = commandExecutor.execute(executor);
    currentProcess.waitFor();
    return NormalParser.parse(new FileInputStream(reportFile));
  }

  public ImmutableList<NetworkEndpoint> getNetworkEndpoints() {
    return ImmutableList.copyOf(networkEndpoints);
  }

  public TargetService getTargetService() {
    return targetService;
  }

  public Optional<String> getMaxTime() {
    if (clioptions != null) {
      return Optional.ofNullable(clioptions.maxTime);
    } else {
      return Optional.empty();
    }
  }

  public ImmutableList<String> getUsernameList() {
    return usernameList;
  }

  public ImmutableList<String> getPasswordList() {
    return passwordList;
  }

  public List<String> buildRunCommandArgs() {
    ArrayList<String> runCommandArgs = Lists.newArrayList();
    runCommandArgs.add(ncrackBinaryPath);
    timing.ifPresent(value -> runCommandArgs.add(value.getFlag()));
    runCommandArgs.add("--user");
    runCommandArgs.add(String.join(",", usernameList));
    runCommandArgs.add("--pass");
    runCommandArgs.add(String.join(",", passwordList));
    if (pairwiseMode) {
      runCommandArgs.add("--pairwise");
    }
    if (quitCrackingAfterOneFound) {
      runCommandArgs.add("-f");
    }
    if (networkEndpoints.stream().anyMatch(NetworkEndpointUtils::isIpV6Endpoint)) {
      runCommandArgs.add("-6");
    }
    for (NetworkEndpoint networkEndpoint : networkEndpoints) {
      runCommandArgs.add(buildServiceCommandValue(networkEndpoint));
    }
    getMaxTime().ifPresent(maxtime -> runCommandArgs.add("-g to=" + maxtime));
    runCommandArgs.add("-oN");
    runCommandArgs.add(reportFile.getAbsolutePath());
    return runCommandArgs;
  }

  private String buildServiceCommandValue(NetworkEndpoint networkEndpoint) {
    StringBuilder flag = new StringBuilder();
    flag.append(
        String.format(
            "%s://%s",
            getFlag(targetService), NetworkEndpointUtils.toUriAuthority(networkEndpoint)));
    path.ifPresent(value -> flag.append(String.format(",path=%s", value)));
    domain.ifPresent(value -> flag.append(String.format(",domain=%s", value)));
    db.ifPresent(value -> flag.append(String.format(",db=%s", value)));
    if (sslEnabled) {
      flag.append(",ssl");
    }
    return flag.toString();
  }

  /**
   * Sets the list of usernames.
   *
   * @param usernameList List of usernames.
   */
  public NcrackClient usingUsernameList(Collection<String> usernameList) {
    this.usernameList = ImmutableList.copyOf(usernameList);
    return this;
  }

  /**
   * Sets the password list.
   *
   * @param passwordList List of passwords.
   */
  @CanIgnoreReturnValue
  public NcrackClient usingPasswordList(Collection<String> passwordList) {
    this.passwordList = ImmutableList.copyOf(passwordList);
    return this;
  }

  /**
   * Enables brute forcing using a pair of username and password. This useful to brute force default
   * credentials. The method accepts a {@link Multimap} to support multiple password for the same
   * username.
   *
   * @param usernamePasswordPair A map of username to password.
   */
  @CanIgnoreReturnValue
  public NcrackClient usingUsernamePasswordPair(Multimap<String, String> usernamePasswordPair) {
    ImmutableList.Builder<String> usernameListBuilder = ImmutableList.builder();
    ImmutableList.Builder<String> passwordListBuilder = ImmutableList.builder();
    // If a username is duplicated, we make sure the username is added multiple times as Ncrack
    // will iterate over the list in order.
    for (String username : usernamePasswordPair.keySet()) {
      for (String password : usernamePasswordPair.get(username)) {
        usernameListBuilder.add(username);
        passwordListBuilder.add(password);
      }
    }

    this.usernameList = usernameListBuilder.build();
    this.passwordList = passwordListBuilder.build();
    this.pairwiseMode = true;
    return this;
  }

  /**
   * Sets the network endpoints to brute force, multiple targets can be set by calling the method
   * multiple time.
   *
   * @param networkEndpoint The network endpoint to scan.
   */
  public NcrackClient withNetworkEndpoint(NetworkEndpoint networkEndpoint) {
    this.networkEndpoints.add(networkEndpoint);
    return this;
  }

  /**
   * Sets the target service to brute force.
   *
   * @param targetService Target service to brute force.
   */
  public NcrackClient onTargetService(TargetService targetService) {
    this.targetService = targetService;
    return this;
  }

  /**
   * Set the database, used by MangoDB service for instance.
   *
   * @param db String database to use by the target service.
   */
  public NcrackClient onDb(String db) {
    this.db = Optional.of(db);
    return this;
  }

  /**
   * Sets the domain, used by WinRM target service for instance.
   *
   * @param domain String domain to use by the target service.
   */
  public NcrackClient onDomain(String domain) {
    this.domain = Optional.of(domain);
    return this;
  }

  /**
   * Sets the path, used by Wordpress target service for instance.
   *
   * @param path String path to use by the target service.
   */
  public NcrackClient onPath(String path) {
    this.path = Optional.of(path);
    return this;
  }

  /** Enables SSL for the target service. */
  public NcrackClient withSslEnabled() {
    this.sslEnabled = true;
    return this;
  }

  /** Stops brute force once a working one is found. */
  public NcrackClient withQuitCrackingAfterOneFound() {
    this.quitCrackingAfterOneFound = true;
    return this;
  }

  /**
   * Sets the timing template to use. Timing templates controls min, max and initial RTT timeout,
   * max retries, scan delay, TCP and UDP scan delay, host timeout and max parallelism. For the
   * exact values set for each configurable parameter, check <a
   * href="https://nmap.org/book/performance-timing-templates.html">link</a>.
   */
  public NcrackClient withTimingTemplate(TimingTemplate template) {
    this.timing = Optional.of(template);
    return this;
  }

  private static String getFlag(TargetService service) {
    return Ascii.toLowerCase(service.name());
  }
}
