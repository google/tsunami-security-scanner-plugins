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
package com.google.tsunami.plugins.portscan.nmap.client.testing;

import static com.google.common.base.Preconditions.checkArgument;
import static com.google.common.base.Preconditions.checkNotNull;
import static org.mockito.Mockito.spy;

import com.google.common.base.Strings;
import com.google.inject.AbstractModule;
import com.google.inject.Provides;
import com.google.tsunami.plugins.portscan.nmap.client.NmapClient;
import java.io.File;
import java.io.IOException;
import java.lang.annotation.Retention;
import java.lang.annotation.RetentionPolicy;
import javax.inject.Qualifier;
import javax.inject.Singleton;

/** Binds a {@code spy()} {@link NmapClient}. */
public class SpyNmapClientModule extends AbstractModule {
  private final String fakeNmapFile;
  private final File fakeOutputFile;

  public SpyNmapClientModule(String fakeNmapFile, File fakeOutputFile) {
    checkArgument(!Strings.isNullOrEmpty(fakeNmapFile));
    this.fakeNmapFile = fakeNmapFile;
    this.fakeOutputFile = checkNotNull(fakeOutputFile);
  }

  @Qualifier
  @Retention(RetentionPolicy.RUNTIME)
  private @interface Delegate {}

  @Provides
  @Delegate
  NmapClient provideDelegateNmapClient() throws IOException {
    return new NmapClient(fakeNmapFile, fakeOutputFile);
  }

  @Provides
  @Singleton
  NmapClient provideSpyNmapClient(@Delegate NmapClient nmapClient) {
    return spy(nmapClient);
  }
}
