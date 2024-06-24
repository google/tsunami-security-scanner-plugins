/*
 * libajp13 - GetBodyChunckMessage.java
 *
 * Copyright (c) 2017 Luca Carettoni - Doyensec LLC. 
 * Copyright (c) 2010 Espen Wiborg
 *
 * Licensed under the Apache License, Version 2.0
 */
package com.google.tsunami.plugins.detectors.credentials.genericweakcredentialdetector.testers.ajp13;

import java.io.IOException;
import java.io.InputStream;

/**
 * AJP's Get Body Chunk message, from the J2EE container to the web server
 */
public class GetBodyChunkMessage
        extends AbstractAjpMessage
{

    final int length;

    /**
     * GetBodyChunkMessage constructor
     *
     * @param length int The expected body chunk message size
     */
    public GetBodyChunkMessage(int length)
    {
        super(Constants.PACKET_TYPE_GET_BODY_CHUNK);
        this.length = length;
        writeInt(length);
    }

    static GetBodyChunkMessage readFrom(InputStream in) throws IOException
    {
        int length = AjpReader.readInt(in);
        return new GetBodyChunkMessage(length);
    }

    /**
     * Returns the expected body chunk message size
     *
     * @return the expected body chunk message size
     */
    public int getLength()
    {
        return length;
    }

    /**
     * Returns a meaningful name for the packet type
     *
     * @return Name of the packet type
     */
    @Override
    public String getName()
    {
        return "Get Body Chunk";
    }

    /**
     * Returns a description for the packet type
     *
     * @return Description of the packet type.
     */
    @Override
    public String getDescription()
    {
        return "Get further data (" + length + " bytes) from the request if it hasn't all been transferred yet";
    }
}
