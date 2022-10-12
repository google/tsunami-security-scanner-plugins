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

import static com.google.common.truth.Truth.assertThat;

import com.google.common.collect.ImmutableSet;
import com.google.tsunami.common.net.http.HttpRequest;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.junit.runners.JUnit4;

/** Unit tests for {@link GetParameterInjection}. */
@RunWith(JUnit4.class)
public final class GetParameterInjectionTest {
  private static final GetParameterInjection INJECTION_POINT = new GetParameterInjection();

  private static final HttpRequest REQUEST_WITHOUT_GET_PARAMETERS =
      HttpRequest.get("https://google.com").withEmptyHeaders().build();
  private static final HttpRequest REQUEST_WITH_GET_PARAMETERS =
      HttpRequest.get("https://google.com?key=value&other=test").withEmptyHeaders().build();

  @Test
  public void injectPayload_onRelativePathTraversalPayloadWithGetParameters_generatesExploits() {
    ImmutableSet<HttpRequest> requestsWithFuzzedGetParameters =
        ImmutableSet.of(
            HttpRequest.get("https://google.com?key=../../../../etc/passwd&other=test")
                .withEmptyHeaders()
                .build(),
            HttpRequest.get("https://google.com?key=value&other=../../../../etc/passwd")
                .withEmptyHeaders()
                .build());

    assertThat(INJECTION_POINT.injectPayload(REQUEST_WITH_GET_PARAMETERS, "../../../../etc/passwd"))
        .containsAtLeastElementsIn(requestsWithFuzzedGetParameters);
  }

  @Test
  public void
      injectPayload_onRelativePathTraversalPayloadWithoutGetParameters_generatesNoExploits() {
    assertThat(
            INJECTION_POINT.injectPayload(REQUEST_WITHOUT_GET_PARAMETERS, "../../../../etc/passwd"))
        .isEmpty();
  }
}
