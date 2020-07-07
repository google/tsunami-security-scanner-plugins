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

import com.google.tsunami.plugins.portscan.nmap.client.result.NmapRun;
import java.io.IOException;
import java.io.InputStream;
import javax.xml.parsers.ParserConfigurationException;
import javax.xml.parsers.SAXParser;
import javax.xml.parsers.SAXParserFactory;
import org.xml.sax.SAXException;

/** Parser for nmap XML report. */
public class XMLParser {

  /**
   * Parses nmap's XML output and return an NmapRun object with all the scan info.
   *
   * @param stream Input stream with XML report.
   * @return NmapRun root object.
   */
  public static NmapRun parse(InputStream stream)
      throws ParserConfigurationException, SAXException, IOException {
    SAXParser parser = createParser();
    NmapResultHandler resultHandler = new NmapResultHandler();
    parser.parse(stream, resultHandler);
    return resultHandler.getNmapRun();
  }

  private static SAXParser createParser() throws ParserConfigurationException, SAXException {
    SAXParserFactory factory = SAXParserFactory.newInstance();
    factory.setValidating(false);
    factory.setXIncludeAware(false);
    return factory.newSAXParser();
  }

  private XMLParser() {}
}
