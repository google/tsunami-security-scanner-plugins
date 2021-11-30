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
package com.google.tsunami.plugins.detectors.rce.tomcat.ghostcat.ajp;

import java.io.IOException;

/** An helper that performs the Ghostcat exploit against a given exposed AJP connector. */
public interface AjpConnection {

  AjpResponse performGhostcat(String reqUri, String path) throws IOException;

  /** The factory of {@link AjpConnection} types for usage with assisted injection. */
  interface Factory {
    AjpConnection create(String ip, int port);
  }
}
