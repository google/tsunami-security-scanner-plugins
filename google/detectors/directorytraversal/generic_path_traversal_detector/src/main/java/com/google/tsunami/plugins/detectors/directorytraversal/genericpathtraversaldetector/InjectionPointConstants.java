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
package com.google.tsunami.plugins.detectors.directorytraversal.genericpathtraversaldetector;

import com.google.common.collect.ImmutableSet;
import java.util.regex.Pattern;

/** A collection of constants that are shared among InjectionPoints. */
final class InjectionPointConstants {
  public static final ImmutableSet<String> COMMON_PATHS =
      ImmutableSet.of(
          // go/keep-sorted start
          "admin",
          "album",
          "app",
          "assets",
          "bin",
          "console",
          "css",
          "demo",
          "doc",
          "eqx",
          "files",
          "fs",
          "html",
          "img-sys",
          "jquery_ui",
          "js",
          "media",
          "public",
          "scripts",
          "static",
          "tmp",
          "upload",
          "xls"
          // go/keep-sorted end
          );

  public static final ImmutableSet<String> PROMISING_PARAMETER_NAMES =
      ImmutableSet.of(
          // go/keep-sorted start
          "file", "filename", "filepath", "path", "url"
          // go/keep-sorted end
          );

  public static final Pattern FILE_EXTENSION_PATTERN = Pattern.compile(".+\\.[^\\.]+");

  private InjectionPointConstants() {}
}
