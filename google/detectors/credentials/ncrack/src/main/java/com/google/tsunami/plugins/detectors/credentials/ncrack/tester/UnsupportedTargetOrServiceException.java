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
package com.google.tsunami.plugins.detectors.credentials.ncrack.tester;

/**
 * Thrown by {@link CredentialTester} to indicate that the target of service being tested are not
 * supported.
 */
public final class UnsupportedTargetOrServiceException extends RuntimeException {

  /**
   * Constructs a <code>UnsupportedTargetOrServiceException</code> with <tt>null</tt> as its error
   * message string.
   */
  public UnsupportedTargetOrServiceException() {
    super();
  }

  /**
   * Constructs a <code>UnsupportedTargetOrServiceException</code>, saving a reference to the error
   * message string <tt>message</tt> for later retrieval by the <tt>getMessage</tt> method.
   *
   * @param message the detail message.
   */
  public UnsupportedTargetOrServiceException(String message) {
    super(message);
  }
}
