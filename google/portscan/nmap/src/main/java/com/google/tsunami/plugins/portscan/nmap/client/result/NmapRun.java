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

/** NmapRun element of nmap XML result. */
@AutoValue
public abstract class NmapRun {
  public abstract String scanner();
  public abstract String args();
  public abstract String start();
  public abstract String startStr();
  public abstract String version();
  public abstract String profileName();
  public abstract String xmlOutputVersion();
  public abstract ImmutableList<ScanInfo> scanInfos();
  public abstract Verbose verbose();
  public abstract Debugging debugging();
  public abstract RunStats runStats();

  abstract ImmutableList<Object> valueElements();
  private <T> ImmutableList<T> getElements(Class<T> clazz) {
    return valueElements().stream()
        .filter(clazz::isInstance)
        .map(clazz::cast)
        .collect(toImmutableList());
  }
  public ImmutableList<Target> targets() {
    return getElements(Target.class);
  }
  public ImmutableList<TaskBegin> taskBegins() {
    return getElements(TaskBegin.class);
  }
  public ImmutableList<TaskProgress> taskProgresses() {
    return getElements(TaskProgress.class);
  }
  public ImmutableList<TaskEnd> taskEnds() {
    return getElements(TaskEnd.class);
  }
  public ImmutableList<PreScript> preScripts() {
    return getElements(PreScript.class);
  }
  public ImmutableList<PostScript> postScripts() {
    return getElements(PostScript.class);
  }
  public ImmutableList<Host> hosts() {
    return getElements(Host.class);
  }
  public ImmutableList<Output> outputs() {
    return getElements(Output.class);
  }

  public abstract Builder toBuilder();
  public static Builder builder() {
    return new AutoValue_NmapRun.Builder();
  }

  /** Builder for {@link NmapRun}. */
  @AutoValue.Builder
  public abstract static class Builder {
    public abstract Builder setScanner(String value);
    public abstract Builder setArgs(String value);
    public abstract Builder setStart(String value);
    public abstract Builder setStartStr(String value);
    public abstract Builder setVersion(String value);
    public abstract Builder setProfileName(String value);
    public abstract Builder setXmlOutputVersion(String value);
    public abstract Builder setVerbose(Verbose value);
    public abstract Builder setDebugging(Debugging value);
    public abstract Builder setRunStats(RunStats value);
    public abstract Builder setScanInfos(Iterable<ScanInfo> value);
    abstract ImmutableList.Builder<ScanInfo> scanInfosBuilder();
    public Builder addScanInfo(ScanInfo value) {
      scanInfosBuilder().add(value);
      return this;
    }

    abstract ImmutableList.Builder<Object> valueElementsBuilder();
    public Builder addValueElement(Object valueElement) {
      valueElementsBuilder().add(valueElement);
      return this;
    }

    public abstract NmapRun build();
  }
}
