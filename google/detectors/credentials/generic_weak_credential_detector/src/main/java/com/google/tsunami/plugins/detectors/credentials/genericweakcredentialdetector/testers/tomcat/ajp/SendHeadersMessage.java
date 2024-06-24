/*
 * libajp13 - SendHeadersMessage.java
 *
 * Copyright (c) 2017 Luca Carettoni - Doyensec LLC. 
 * Copyright (c) 2010 Espen Wiborg
 *
 * Licensed under the Apache License, Version 2.0
 */
package com.google.tsunami.plugins.detectors.credentials.genericweakcredentialdetector.testers.ajp13;

import java.io.IOException;
import java.io.InputStream;
import java.util.LinkedList;
import java.util.List;
import java.util.Map;

/**
 * AJP's Send Headers message, from the J2EE container to the web server
 */
public class SendHeadersMessage
        extends AbstractAjpMessage
{

    private int statusCode;
    private String statusMessage;
    private List<Pair<String, String>> headers;

    /**
     * SendHeadersMessage constructor
     *
     * @param statusCode The HTTP status code (e.g. 200)
     * @param statusMessage The status message (e.g. OK)
     * @param headers A list of Pair[String, String] containing all headers
     * @throws IOException Generic IOException
     */
    public SendHeadersMessage(int statusCode, String statusMessage, List<Pair<String, String>> headers) throws IOException
    {
        super(Constants.PACKET_TYPE_SEND_HEADERS);
        this.statusCode = statusCode;
        writeInt(statusCode);
        this.statusMessage = statusMessage;
        writeString(statusMessage, true);
        this.headers = headers;
        int numHeaders = headers.size();
        writeInt(numHeaders);
        for (Pair<String, String> header : headers) {
            String name = header.a;
            String value = header.b;

            if (Constants.RESPONSE_HEADERS.containsKey(name.toLowerCase())) {
                //Send HeaderName as Byte
                writeByte(Constants.HEADERS_GENERIC);
                writeByte(Constants.RESPONSE_HEADERS.get(name.toLowerCase()));
            } else {
                //Send HeaderName as String
                writeString(name, true);
            }
            //Send HeaderValue
            writeString(value, true);
        }
    }

    /**
     * Returns the HTTP status code (e.g. 200)
     *
     * @return the message's status code
     */
    public int getStatusCode()
    {
        return statusCode;
    }

    /**
     * Returns the status message (e.g. OK)
     *
     * @return the message's status
     */
    public String getStatusMessage()
    {
        return statusMessage;
    }

    /**
     * Returns the message HTTP headers
     *
     * @return the message's headers as List[Pair[String, String]]
     */
    public List<Pair<String, String>> getHeaders()
    {
        return headers;
    }


    @Override
    public String toString()
    {
        StringBuilder ret = new StringBuilder();
        ret.append(statusCode).append(" ").append(statusMessage).append("\n");
        ret.append("Headers:\n");
        for (Pair<String, String> header : headers) {
            ret.append(header.a).append(": ").append(header.b).append("\n");
        }
        return ret.toString();
    }

    static SendHeadersMessage readFrom(InputStream in) throws IOException
    {
        int statusCode = AjpReader.readInt(in);
        String statusMessage = AjpReader.readString(in);
        int numHeaders = AjpReader.readInt(in);
        List<Pair<String, String>> headers = new LinkedList<>();
        for (int i = 0; i < numHeaders; i++) {
            int b1 = AjpReader.readByte(in);
            int b2 = AjpReader.readByte(in);

            String name = "";
            if (b1 == Constants.HEADERS_GENERIC && Constants.RESPONSE_HEADERS.containsValue(b2)) {
                for (Map.Entry<String, Integer> entry : Constants.RESPONSE_HEADERS.entrySet()) {
                    String key = entry.getKey();
                    Integer value = entry.getValue();
                    if (value == b2) {
                        //According to RFC 7230, header field names are case-insensitive
                        name = key;
                    }
                }
            } else {
                name = AjpReader.readString(AjpReader.makeInt(b1, b2), in);
            }
            headers.add(Pair.make(name, AjpReader.readString(in)));
        }
        return new SendHeadersMessage(statusCode, statusMessage, headers);
    }

    /**
     * Returns a meaningful name for the packet type
     *
     * @return Name of the packet type
     */
    @Override
    public String getName()
    {
        return "Send Headers";
    }

    /**
     * Returns a description for the packet type
     *
     * @return Description of the packet type.
     */
    @Override
    public String getDescription()
    {
        return "Send the response headers from the servlet container to the web server.\nContent:\n" + this.toString();
    }
}
