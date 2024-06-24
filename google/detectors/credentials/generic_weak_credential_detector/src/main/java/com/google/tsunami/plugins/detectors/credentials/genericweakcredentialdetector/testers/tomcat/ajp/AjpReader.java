/*
 * libajp13 - AjpReader.java
 *
 * Copyright (c) 2017 Luca Carettoni - Doyensec LLC. 
 * Copyright (c) 2010 Espen Wiborg
 *
 * Licensed under the Apache License, Version 2.0
 */
package com.google.tsunami.plugins.detectors.credentials.genericweakcredentialdetector.testers.ajp13;

import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.util.Arrays;

/**
 * This class provides several utility methods for parsing and displaying AJP
 * messages
 */
final public class AjpReader
{

    /**
     * Parse and create an AJP message from an array of bytes
     *
     * @param reply bytes[] Message
     * @throws IOException Generic IOException
     * @return Instance of AjpMessage
     */
    static public AjpMessage parseMessage(byte[] reply) throws IOException
    {
        //AJP_TAG + size (2 bytes) + [type]
        InputStream in = new ByteArrayInputStream(reply);
        byte[] header = readBytes(2, false, in);
        if (Arrays.equals(header, Constants.AJP_TAG_REQ) || Arrays.equals(header, Constants.AJP_TAG_RESP)) {
            int length = readInt(in);
            if (length <= 0) {
                return null; //empty AjpMessage
            }
            int type = readByte(in);
            byte[] bytes = new byte[length - 1];
            fullyRead(bytes, in);

            switch (type) {
                //From Web Server to J2EE Container
                case Constants.PACKET_TYPE_CPING:
                    return new CPingMessage();
                case Constants.PACKET_TYPE_FORWARD_REQUEST:
                    return ForwardRequestMessage.readFrom(new ByteArrayInputStream(bytes));
                case Constants.PACKET_TYPE_SHUTDOWN:
                    return new ShutdownMessage();
                case Constants.PACKET_TYPE_PING:
                    return new PingMessage();
                //From J2EE Container to Web Server
                case Constants.PACKET_TYPE_CPONG:
                    return new CPongMessage();
                case Constants.PACKET_TYPE_SEND_HEADERS:
                    return SendHeadersMessage.readFrom(new ByteArrayInputStream(bytes));
                case Constants.PACKET_TYPE_SEND_BODY_CHUNK:
                    return SendBodyChunkMessage.readFrom(new ByteArrayInputStream(bytes));
                case Constants.PACKET_TYPE_GET_BODY_CHUNK:
                    return GetBodyChunkMessage.readFrom(new ByteArrayInputStream(bytes));
                case Constants.PACKET_TYPE_END_RESPONSE:
                    return EndResponseMessage.readFrom(new ByteArrayInputStream(bytes));
                default:
                    //Probably a Data packet (without any prefix code for the type)
                    ByteArrayOutputStream outputStream = new ByteArrayOutputStream();
                    outputStream.write(type);
                    outputStream.write(bytes);
                    return BodyMessage.readFrom(new ByteArrayInputStream(outputStream.toByteArray()));
            }
        } else {
            System.out.println("[!] AjpReader Unexpected Header Bytes: " + getHex(header));
            return null;
        }
    }

    static int readInt(InputStream in) throws IOException
    {
        byte[] buf = new byte[2];
        fullyRead(buf, in);
        return makeInt(buf[0], buf[1]);
    }

    static int makeInt(int b1, int b2)
    {
        return b1 << 8 | (b2 & 0xff);
    }

    static String readString(InputStream in) throws IOException
    {
        int len = readInt(in);
        return readString(len, in);
    }

    static String readString(int len, InputStream in) throws IOException
    {
        byte[] strContent = readBytes(len, true, in);
        if (strContent != null && strContent.length > 0) {
            return new String(strContent, "UTF-8");
        } else {
            return "";
        }
    }

    static byte[] readBytes(int len, InputStream in) throws IOException
    {
        //do not expect a null byte
        return readBytes(len, false, in);
    }

    private static byte[] readBytes(int len, boolean nullByte, InputStream in) throws IOException
    {
        if (len < 1) {
            return null;
        }
        byte[] buf = new byte[len];
        fullyRead(buf, in);
        // Skip the terminating \0 if we're retrieving a String
        if (nullByte) {
            in.read();
        }
        return buf;
    }

    static void fullyRead(byte[] buffer, InputStream in) throws IOException
    {
        int totalRead = 0;
        int read = 0;
        while ((read = in.read(buffer, totalRead, buffer.length - totalRead)) > 0) {
            totalRead += read;
        }
        if (totalRead != buffer.length) {
            System.out.println("[!] AjpReader Short Read. Buffer: " + buffer.length + ", Read: " + totalRead);
        }
    }

    static int readByte(InputStream in) throws IOException
    {
        return in.read();
    }

    static boolean readBoolean(InputStream in) throws IOException
    {
        return readByte(in) > 0;
    }

    /**
     * Convert a byte array to a string representation of hex values
     *
     * @param raw bytes[] input (e.g. [65,..])
     * @return input converted as string representation of hex values (e.g. [41,..])
     */
    public static String getHex(byte[] raw)
    {
        final String HEXES = "0123456789ABCDEF";
        if (raw == null) {
            return null;
        }
        final StringBuilder hex = new StringBuilder(2 * raw.length);
        for (final byte b : raw) {
            hex.append(HEXES.charAt((b & 0xF0) >> 4)).append(HEXES.charAt((b & 0x0F)));
        }
        return hex.toString();
    }

    /**
     * Convert a string representation of hex values to byte array
     *
     * @param s String input (e.g. "41")
     * @return input converted as byte array (e.g. [65,..])
     */
    public static byte[] toHex(String s)
    {
        int len = s.length();
        byte[] data = new byte[len / 2];
        for (int i = 0; i < len; i += 2) {
            data[i / 2] = (byte) ((Character.digit(s.charAt(i), 16) << 4)
                    + Character.digit(s.charAt(i + 1), 16));
        }
        return data;
    }
}
