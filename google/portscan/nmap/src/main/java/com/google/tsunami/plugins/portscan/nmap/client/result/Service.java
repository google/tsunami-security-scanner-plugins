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
package com.google.tsunami.plugins.portscan.nmap.client.result;

import com.google.auto.value.AutoValue;
import com.google.common.collect.ImmutableList;

/** Service element of nmap XML result. */
@AutoValue
public abstract class Service {
  public abstract String name();
  public abstract String conf();
  public abstract String method();
  public abstract String version();
  public abstract String product();
  public abstract String extraInfo();
  public abstract String tunnel();
  public abstract String proto();
  public abstract String rpcNum();
  public abstract String lowVer();
  public abstract String highVer();
  public abstract String hostname();
  public abstract String osType();
  public abstract String deviceType();
  public abstract String serviceFp();
  public abstract ImmutableList<Cpe> cpes();

  public abstract Builder toBuilder();
  public static Builder builder() {
    return new AutoValue_Service.Builder();
  }

  /** Builder for {@link Service}. */
  @AutoValue.Builder
  public abstract static class Builder {
    public abstract Builder setName(String value);
    public abstract Builder setConf(String value);
    public abstract Builder setMethod(String value);
    public abstract Builder setVersion(String value);
    public abstract Builder setProduct(String value);
    public abstract Builder setExtraInfo(String value);
    public abstract Builder setTunnel(String value);
    public abstract Builder setProto(String value);
    public abstract Builder setRpcNum(String value);
    public abstract Builder setLowVer(String value);
    public abstract Builder setHighVer(String value);
    public abstract Builder setHostname(String value);
    public abstract Builder setOsType(String value);
    public abstract Builder setDeviceType(String value);
    public abstract Builder setServiceFp(String value);

    public abstract Builder setCpes(Iterable<Cpe> value);
    abstract ImmutableList.Builder<Cpe> cpesBuilder();
    public Builder addCpe(Cpe value) {
      cpesBuilder().add(value);
      return this;
    }

    public abstract Service build();
  }
}
