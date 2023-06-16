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
package com.google.tsunami.plugins.detectors.credentials.genericweakcredentialdetector.provider;

import com.google.tsunami.proto.NetworkService;
import java.util.Iterator;

/**
 * Credential providers are responsible for the generation of test credentials using an {@link
 * Iterator<TestCredential>}. Credentials are provided using a bulk mode to suit all tester use
 * cases.
 *
 * <p>For examples of provider implementations, check the provider folder.
 */
public abstract class CredentialProvider {

  public abstract String name();

  public abstract String description();

  public abstract Iterator<TestCredential> generateTestCredentials(NetworkService networkService);
}
