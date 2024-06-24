/*
 * libajp13 - PingMessage.java
 *
 * Copyright (c) 2017 Luca Carettoni - Doyensec LLC. 
 * Copyright (c) 2010 Espen Wiborg
 *
 * Licensed under the Apache License, Version 2.0
 */
package com.google.tsunami.plugins.detectors.credentials.genericweakcredentialdetector.testers.ajp13;

/**
 * AJP's Ping, from the web server to the J2EE container
 * <p>
 * This is different from a CPing message
 *
 * TODO - Reverse any implementation of the ping type handler
 */
public class PingMessage
        extends AbstractAjpMessage
{

    /**
     * PingMessage constructor
     *
     */
    public PingMessage()
    {
        super(Constants.PACKET_TYPE_PING);
    }

    /**
     * Returns a meaningful name for the packet type
     *
     * @return Name of the packet type
     */
    @Override
    public String getName()
    {
        return "Ping";
    }

    /**
     * Returns a description for the packet type
     *
     * @return Description of the packet type.
     */
    @Override
    public String getDescription()
    {
        return "The web server asks the container to take control (secure login phase)";
    }
}
