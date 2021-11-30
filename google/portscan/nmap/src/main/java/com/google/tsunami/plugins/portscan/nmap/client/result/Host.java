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

import static com.google.common.collect.ImmutableList.toImmutableList;

import com.google.auto.value.AutoValue;
import com.google.common.collect.ImmutableList;

/** Host element of nmap XML result. */
@AutoValue
public abstract class Host {
  public abstract String startTime();
  public abstract String endTime();
  public abstract String comment();

  abstract ImmutableList<Object> valueElements();
  private <T> ImmutableList<T> getElements(Class<T> clazz) {
    return valueElements().stream()
        .filter(clazz::isInstance)
        .map(clazz::cast)
        .collect(toImmutableList());
  }
  public ImmutableList<Status> statuses() {
    return getElements(Status.class);
  }
  public ImmutableList<Address> addresses() {
    return getElements(Address.class);
  }
  public ImmutableList<Hostnames> hostnames() {
    return getElements(Hostnames.class);
  }
  public ImmutableList<Smurf> smurfs() {
    return getElements(Smurf.class);
  }
  public ImmutableList<Ports> ports() {
    return getElements(Ports.class);
  }
  public ImmutableList<Os> oses() {
    return getElements(Os.class);
  }
  public ImmutableList<Distance> distances() {
    return getElements(Distance.class);
  }
  public ImmutableList<Uptime> uptimes() {
    return getElements(Uptime.class);
  }
  public ImmutableList<TcpSequence> tcpSequences() {
    return getElements(TcpSequence.class);
  }
  public ImmutableList<IpIdSequence> ipIdSequences() {
    return getElements(IpIdSequence.class);
  }
  public ImmutableList<TcpTsSequence> tcpTsSequences() {
    return getElements(TcpTsSequence.class);
  }
  public ImmutableList<HostScript> hostScripts() {
    return getElements(HostScript.class);
  }
  public ImmutableList<Trace> traces() {
    return getElements(Trace.class);
  }
  public ImmutableList<Times> times() {
    return getElements(Times.class);
  }

  public abstract Builder toBuilder();
  public static Builder builder() {
    return new AutoValue_Host.Builder();
  }

  /** Builder for {@link Host}. */
  @AutoValue.Builder
  public abstract static class Builder {
    public abstract Builder setStartTime(String value);
    public abstract Builder setEndTime(String value);
    public abstract Builder setComment(String value);

    abstract ImmutableList.Builder<Object> valueElementsBuilder();
    public Builder addValueElement(Object valueElement) {
      valueElementsBuilder().add(valueElement);
      return this;
    }

    public abstract Host build();
  }
}
