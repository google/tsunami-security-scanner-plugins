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
package com.google.tsunami.plugins.fingerprinters.web.tools;

import static java.nio.charset.StandardCharsets.UTF_8;

import com.beust.jcommander.JCommander;
import com.beust.jcommander.Parameter;
import com.beust.jcommander.ParameterException;
import com.beust.jcommander.Parameters;
import com.google.common.flogger.GoogleLogger;
import com.google.common.io.Files;
import com.google.protobuf.util.JsonFormat;
import com.google.tsunami.plugins.fingerprinters.web.proto.Fingerprints;
import java.io.File;
import java.io.IOException;
import java.nio.file.Paths;

/** Converts protobuf file between Json and Binary. */
public final class FingerprintFileConverter {
  private static final GoogleLogger logger = GoogleLogger.forEnclosingClass();

  private final Options options;

  FingerprintFileConverter(Options options) {
    this.options = options;
  }

  public void convert() throws IOException {
    dump(load());
  }

  private Fingerprints load() throws IOException {
    logger.atInfo().log("Loading data from %s.", options.input);
    return Files.getFileExtension(options.input).equals("json")
        ? loadFromJson()
        : loadFromBinProto();
  }

  private Fingerprints loadFromJson() throws IOException {
    Fingerprints.Builder fingerprintsBuilder = Fingerprints.newBuilder();
    JsonFormat.parser()
        .merge(
            Files.asCharSource(Paths.get(options.input).toFile(), UTF_8).read(),
            fingerprintsBuilder);
    return fingerprintsBuilder.build();
  }

  @SuppressWarnings("ProtoParseWithRegistry")
  private Fingerprints loadFromBinProto() throws IOException {
    return Fingerprints.parseFrom(
        Files.asByteSource(Paths.get(options.input).toFile()).openBufferedStream());
  }

  private void dump(Fingerprints data) throws IOException {
    logger.atInfo().log("Write data file to %s.", options.output);
    if (Files.getFileExtension(options.output).equals("json")) {
      Files.asCharSink(new File(options.output), UTF_8).write(JsonFormat.printer().print(data));
    } else {
      Files.asByteSink(new File(options.output)).write(data.toByteArray());
    }
  }

  public static void main(String[] args) throws IOException {
    new FingerprintFileConverter(Options.parse(args)).convert();
  }

  /** {@code Options} holds CLI parameters for the {@link FingerprintFileConverter}. */
  @Parameters(separators = "=")
  public static final class Options {
    @Parameter(names = "--input", description = "The path to the input data file.", required = true)
    public String input;

    @Parameter(
        names = "--output",
        description = "The path to the output data file.",
        required = true)
    public String output;

    public static Options parse(String[] args) {
      var options = new Options();
      var jCommander = new JCommander();
      jCommander.setProgramName("ProtoConverter");
      jCommander.addObject(options);

      // Parse command arguments or die.
      try {
        jCommander.parse(args);
        return options;
      } catch (ParameterException e) {
        jCommander.usage();
        throw e;
      }
    }
  }
}
