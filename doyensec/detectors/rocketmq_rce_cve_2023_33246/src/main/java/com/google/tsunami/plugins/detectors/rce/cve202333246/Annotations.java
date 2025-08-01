/*
 * Copyright 2024 Google LLC
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
package com.google.tsunami.plugins.detectors.rce.cve202333246;

import static java.lang.annotation.ElementType.FIELD;
import static java.lang.annotation.ElementType.METHOD;
import static java.lang.annotation.ElementType.PARAMETER;

import java.lang.annotation.Retention;
import java.lang.annotation.RetentionPolicy;
import java.lang.annotation.Target;
import javax.inject.Qualifier;

/** Annotation for {@link RocketMqCve202333246Detector}. */
final class Annotations {
  @Qualifier
  @Retention(RetentionPolicy.RUNTIME)
  @Target({PARAMETER, METHOD, FIELD})
  @interface OobSleepDuration {}

  @Qualifier
  @Retention(RetentionPolicy.RUNTIME)
  @Target({PARAMETER, METHOD, FIELD})
  @interface SocketFactoryInstance {}

  private Annotations() {}
}
