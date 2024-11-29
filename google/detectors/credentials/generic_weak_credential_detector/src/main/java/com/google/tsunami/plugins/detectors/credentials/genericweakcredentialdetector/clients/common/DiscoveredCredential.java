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
package com.google.tsunami.plugins.detectors.credentials.genericweakcredentialdetector.clients.common;

import com.google.auto.value.AutoValue;
import com.google.tsunami.proto.NetworkEndpoint;
import java.util.Optional;

/**
 * An identified credential with contextual data, like service, target and port.
 *
 * <p>IMPORTANT: Ncrack do not escape credentials in the output. For instance if a password if value
 * ab'cd is discovered, it is printed as 'ab'cd'.
 */
@AutoValue
public abstract class DiscoveredCredential {
  public abstract NetworkEndpoint networkEndpoint();

  public abstract String service();

  // Empty credentials or simply empty password may exist if the service don't have authentication
  // enabled or only accepts a single secret value.
  public abstract Optional<String> username();

  public abstract Optional<String> password();

  public static Builder builder() {
    return new AutoValue_DiscoveredCredential.Builder();
  }

  /** Builder for {@link DiscoveredCredential}. */
  @AutoValue.Builder
  public abstract static class Builder {
    public abstract Builder setNetworkEndpoint(NetworkEndpoint networkEndpoint);

    public abstract Builder setService(String service);

    public abstract Builder setUsername(Optional<String> username);

    public abstract Builder setUsername(String username);

    public abstract Builder setPassword(Optional<String> password);

    public abstract Builder setPassword(String password);

    public abstract DiscoveredCredential build();
  }
}
