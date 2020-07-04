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

import static com.google.common.base.Preconditions.checkNotNull;

import org.xml.sax.Attributes;

/** Attributes for an XML element. */
public final class XmlAttributes {
  private final Attributes attributes;

  private XmlAttributes(Attributes attributes) {
    this.attributes = checkNotNull(attributes);
  }

  public static XmlAttributes from(Attributes attributes) {
    return new XmlAttributes(attributes);
  }

  /**
   * Look up an attribute's value by its name.
   *
   * @param name the name of the XML attribute.
   * @return the value of the XML attribute, or null if attribute not found.
   */
  public String getValue(String name) {
    return attributes.getValue(name);
  }

  /**
   * Look up an attribute's value by its name.
   *
   * @param name the name of the XML attribute.
   * @param def the default value for the XML attribute, if name not found.
   * @return the value of the XML attribute, or the default value if name not found.
   */
  public String getValue(String name, String def) {
    String value = getValue(name);
    return value == null ? def : value;
  }
}
