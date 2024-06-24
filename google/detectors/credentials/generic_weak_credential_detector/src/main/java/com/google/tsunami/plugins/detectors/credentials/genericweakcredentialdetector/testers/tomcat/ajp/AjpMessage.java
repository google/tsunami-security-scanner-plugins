/*
 * libajp13 - AjpMessage.java
 *
 * Copyright (c) 2017 Luca Carettoni - Doyensec LLC. 
 * Copyright (c) 2010 Espen Wiborg
 *
 * Licensed under the Apache License, Version 2.0
 */
package com.google.tsunami.plugins.detectors.credentials.genericweakcredentialdetector.testers.ajp13;

import java.io.IOException;
import java.io.OutputStream;

/**
 * Generic interface for all AJP messages (requests and responses)
 */
public interface AjpMessage
{

    byte[] getBytes(); //returns the raw bytes

    void writeTo(OutputStream out) throws IOException; //writes to a given outputstream

    String getName(); //returns a meaningful name for the packet type

    String getDescription(); //returns a description for the packet type, with actual field values
}
