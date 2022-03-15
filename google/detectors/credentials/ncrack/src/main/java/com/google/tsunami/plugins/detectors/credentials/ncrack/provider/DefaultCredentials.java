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
package com.google.tsunami.plugins.detectors.credentials.ncrack.provider;

import com.google.common.collect.ImmutableList;
import com.google.common.collect.ImmutableMap;
import com.google.tsunami.common.data.NetworkServiceUtils;
import com.google.tsunami.proto.NetworkService;
import java.util.Collections;
import java.util.Iterator;
import java.util.Optional;

/**
 * Credential provider that provides the default username/password combination for popular web
 * services.
 */
public final class DefaultCredentials extends CredentialProvider {

  private static final ImmutableMap<String, String> SERVICE_TO_USERNAME =
      ImmutableMap.<String, String>builder()
          .put(
              "cassandra",
              "cassandra") // https://cassandra.apache.org/doc/latest/cassandra/operating/security.html#operation-roles
          .put("redis", "default") // https://redis.io/topics/acl
          .put("postgresql", "postgres") // https://serverfault.com/a/325596
          .put("mysql", "root") // https://dev.mysql.com/doc/refman/8.0/en/default-privileges.html
          .put(
              "ms-sql-s",
              "sa") // https://docs.microsoft.com/en-us/azure/azure-sql/virtual-machines/windows/security-considerations-best-practices#manage-accounts
          .put("mongod", "myUserAdmin") // https://docs.mongodb.com/manual/tutorial/create-users
          .put(
              "wordpress",
              "admin") // https://varyingvagrantvagrants.org/docs/en-US/default-credentials/
          .buildOrThrow();

  // Explicitly set passwords to empty to ensure it's not accidentally omitted
  private static final ImmutableMap<String, String> SERVICE_TO_PASSWORD =
      ImmutableMap.<String, String>builder()
          .put("cassandra", "cassandra")
          .put("redis", "")
          .put("postgresql", "")
          .put("mysql", "")
          .put("ms-sql-s", "")
          .put("mongod", "")
          .put("wordpress", "password")
          .buildOrThrow();

  DefaultCredentials() {}

  @Override
  public String name() {
    return "DefaultCredentials";
  }

  @Override
  public String description() {
    return "For a given service, returns the default credentials";
  }

  @Override
  public Iterator<TestCredential> generateTestCredentials(NetworkService networkService) {
    String serviceName = NetworkServiceUtils.getServiceName(networkService);

    if (SERVICE_TO_USERNAME.containsKey(serviceName)) {
      return ImmutableList.of(
              TestCredential.create(
                  SERVICE_TO_USERNAME.get(serviceName),
                  // Since
                  // NcrackCredentialTester.generateTestCredentialsMapFromListOfCredentials
                  // sets null passwords to empty string anyway, we just pass empty strings
                  // directly to the Optional to simplify the logic here.
                  Optional.of(SERVICE_TO_PASSWORD.get(serviceName))))
          .iterator();
    }

    return Collections.<TestCredential>emptyIterator();
  }
}
