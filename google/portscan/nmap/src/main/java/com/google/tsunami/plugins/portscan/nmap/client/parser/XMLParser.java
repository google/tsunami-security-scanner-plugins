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
package com.google.tsunami.plugins.portscan.nmap.client.parser;

import com.google.tsunami.plugins.portscan.nmap.client.data.xml.Nmaprun;
import java.io.InputStream;
import javax.xml.bind.JAXBContext;
import javax.xml.bind.JAXBException;
import javax.xml.bind.Unmarshaller;

/** Parser for nmap XML report. */
public class XMLParser {

  /**
   * Parses nmap's XML output and return an NmapRun object with all the scan info.
   *
   * <p>NmapRun is generated from nmap's DTD and is maintained by nmap. The DTD is located at <a
   * href="https://nmap.org/book/nmap-dtd.html">link</a>.
   *
   * @param stream Input stream with XML report.
   * @return NmapRun root object.
   */
  public static Nmaprun parse(InputStream stream) throws JAXBException {
    JAXBContext context = JAXBContext.newInstance(Nmaprun.class);
    Unmarshaller unmarshaller = context.createUnmarshaller();
    return (Nmaprun) unmarshaller.unmarshal(stream);
  }

  private XMLParser() {}
}
