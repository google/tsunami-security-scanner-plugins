/*
 * libajp13 - EndResponseMessage.java
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
 * AJP's EndResponseMessage, from the J2EE container to the web server
 */
public class EndResponseMessage
        extends AbstractAjpMessage
{

    final boolean reuse;

    /**
     * EndResponseMessage constructor
     *
     * @param reuse boolean A boolean flag to indicate whether the client (e.g. web
     * server) should close the TCP connection, or re-use the same
     */
    public EndResponseMessage(boolean reuse)
    {
        super(Constants.PACKET_TYPE_END_RESPONSE);
        this.reuse = reuse;
        writeBoolean(reuse);
    }

    @Override
    public String toString()
    {
        return String.format("Reuse? %s", reuse ? "Yes" : "No");
    }

    static EndResponseMessage readFrom(InputStream in) throws IOException
    {
        return new EndResponseMessage(AjpReader.readBoolean(in));
    }

    /**
     * Returns the reuse flag
     *
     * @return true if the client (e.g. web server) should close the TCP
     * connection, false otherwise
     */
    public boolean getReuse()
    {
        return reuse;
    }

    /**
     * Returns a meaningful name for the packet type
     *
     * @return Name of the packet type
     */
    @Override
    public String getName()
    {
        return "End Response";
    }

    /**
     * Returns a description for the packet type
     *
     * @return Description of the packet type.
     */
    @Override
    public String getDescription()
    {
        return "Marks the end of the response (and thus the request-handling cycle). " + this.toString();
    }
}
