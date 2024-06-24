/*
 * libajp13 - SendBodyChunkMessage.java
 *
 * Copyright (c) 2017 Luca Carettoni - Doyensec LLC.
 * Copyright (c) 2010 Espen Wiborg
 *
 * Licensed under the Apache License, Version 2.0
 */
package com.google.tsunami.plugins.detectors.credentials.genericweakcredentialdetector.testers.ajp13;

import java.io.IOException;
import java.io.InputStream;
import java.io.UnsupportedEncodingException;

/**
 * AJP's Send Body Chunk message, from the J2EE container to the web server
 */
public class SendBodyChunkMessage
        extends AbstractAjpMessage
{

    final int length;
    final byte[] bytes;

    /**
     * SendBodyChunkMessage constructor
     *
     * @param bytes[] The body chunk message content
     * @throws IOException Generic IOException
     */
    public SendBodyChunkMessage(byte[] bytes) throws IOException
    {
        super(Constants.PACKET_TYPE_SEND_BODY_CHUNK);
        this.length = bytes.length;
        writeInt(length);
        this.bytes = bytes;
        //We assume no trailing null byte. Correct?
        writeBytes(bytes);
    }

    /**
     * Returns the body chunk message size
     *
     * @return the body chunk message size
     */
    public int getLength()
    {
        return length;
    }

    /**
     * Returns the body chunk content
     *
     * @return the body chunk message
     */
    public byte[] getBodyChunk()
    {
        return bytes;
    }

    @Override
    public String toString()
    {
        try {
            return new String(bytes, "UTF-8");
        } catch (UnsupportedEncodingException ex) {
            System.out.println("[!] SendBodyChunkMessage UnsupportedEncodingException: " + ex.getLocalizedMessage());
            return "InvalidEncoding";
        }
    }

    static SendBodyChunkMessage readFrom(InputStream in) throws IOException
    {
        int length = AjpReader.readInt(in);
        byte[] bytes = new byte[length];
        AjpReader.fullyRead(bytes, in);
        return new SendBodyChunkMessage(bytes);
    }

    /**
     * Returns a meaningful name for the packet type
     *
     * @return Name of the packet type
     */
    @Override
    public String getName()
    {
        return "Send Body Chunk";
    }

    /**
     * Returns a description for the packet type
     *
     * @return Description of the packet type.
     */
    @Override
    public String getDescription()
    {
        return "Send a chunk of the body from the servlet container to the web server."
                + "\nContent (HEX):\n0x" + AjpReader.getHex(bytes)
                + "\nContent (Ascii):\n" + this.toString();
    }
}
