/*
 * libajp13 - ForwardRequestMessage.java
 *
 * Copyright (c) 2017 Luca Carettoni - Doyensec LLC. 
 * Copyright (c) 2010 Espen Wiborg
 *
 * Licensed under the Apache License, Version 2.0
 */
package com.google.tsunami.plugins.detectors.credentials.genericweakcredentialdetector.testers.ajp13;

import java.io.IOException;
import java.io.InputStream;
import java.net.InetAddress;
import java.net.URL;
import java.net.UnknownHostException;
import java.util.LinkedList;
import java.util.List;
import java.util.Map;

/**
 * AJP's ForwardRequestMessage, from the web server to the J2EE container
 * <p>
 * This class begins the request-processing cycle from the server to the
 * container
 */
public class ForwardRequestMessage
        extends AbstractAjpMessage
{

    //Mandatory fields
    private int method;
    private String protocol;
    private String requestUri;
    private String remoteAddr;
    private String remoteHost;
    private String serverName;
    private int serverPort;
    private boolean isSsl;
    private List<Pair<String, String>> headers = new LinkedList<>();
    //Optional fields
    private List<Pair<String, String>> attributes = new LinkedList<>();

    /**
     * Simplified ForwardRequestMessage constructor
     *
     * @param method int The HTTP verb
     * @param url URL The message URL
     * @param headers The request HTTP headers
     * @param attributes The request HTTP attributes
     * @throws UnknownHostException Generic UnknownHostException
     */
    public ForwardRequestMessage(int method, URL url,
            List<Pair<String, String>> headers,
            List<Pair<String, String>> attributes) throws UnknownHostException
    {
        this(method, "HTTP/1.1", url.getPath(), InetAddress.getLocalHost().getHostAddress(),
                InetAddress.getLocalHost().getCanonicalHostName(), url.getHost(),
                ((url.getPort() == -1) ? url.getDefaultPort() : url.getPort()),
                url.getProtocol().equalsIgnoreCase("https"), headers, attributes);

        if (url.getQuery() != null) {
            addAttribute(Constants.ATTRIBUTE_QUERY_STRING, url.getQuery());
        }
    }

    /**
     * Complete ForwardRequestMessage constructor
     *
     * @param method int The HTTP verb
     * @param protocol String The HTTP protocol version (HTTP/1.0 or HTTP/1.1)
     * @param requestUri String The request path (e.g. /logs/)
     * @param remoteAddr String The client's IP address (e.g. web server's IP)
     * @param remoteHost String The client's hostname (e.g. web server's hostname)
     * @param serverName String The server's IP domain name (e.g. container's FQDN)
     * @param serverPort int The server's TCP port
     * @param isSsl boolean Does it use SSL?
     * @param headers The request HTTP headers
     * @param attributes The request HTTP attributes
     */
    public ForwardRequestMessage(int method, String protocol, String requestUri,
            String remoteAddr, String remoteHost, String serverName,
            int serverPort, boolean isSsl, List<Pair<String, String>> headers,
            List<Pair<String, String>> attributes)
    {

        super(Constants.PACKET_TYPE_FORWARD_REQUEST);

        this.method = method;
        writeByte(method);
        this.protocol = protocol; //e.g HTTP/1.1
        writeString(protocol, true);
        this.requestUri = requestUri;
        writeString(requestUri, true);
        this.remoteAddr = remoteAddr; //e.g. 127.0.0.1
        writeString(remoteAddr, true);
        this.remoteHost = remoteHost;
        writeString(remoteHost, true); //e.g. localhost
        this.serverName = serverName;
        writeString(serverName, true);
        this.serverPort = serverPort;
        writeInt(serverPort);
        this.isSsl = isSsl;
        writeBoolean(isSsl);

        //headers
        if (headers == null) {
            headers = new LinkedList<>();
        }
        this.headers = headers;
        if (headers.isEmpty()) {
            //If empty, add default Host header. Otherwise, assume that it's user-supplied
            addHeader("Host", serverName + ":" + serverPort);
        }
        writeInt(headers.size());
        for (Pair<String, String> header : headers) {
            String name = header.a;
            String value = header.b;

            if (Constants.COMMON_HEADERS.containsKey(name.toLowerCase())) {
                //Send HeaderName as Byte
                writeByte(Constants.HEADERS_GENERIC);
                writeByte(Constants.COMMON_HEADERS.get(name.toLowerCase()));
            } else {
                //Send HeaderName as String
                writeString(name, true);
            }
            //Send HeaderValue
            writeString(value, true);
        }

        //attributes (optionals)
        if (attributes == null) {
            attributes = new LinkedList<>();
        }
        this.attributes = attributes;
        for (Pair<String, String> attribute : attributes) {
            String name = attribute.a;
            String value = attribute.b;

            if (Constants.COMMON_ATTRIBUTES.containsKey(name.toLowerCase())) {
                //Known attribute type
                writeByte(Constants.COMMON_ATTRIBUTES.get(name.toLowerCase()));
            } else {
                //Extra attribute type
                writeByte(Constants.COMMON_ATTRIBUTES.get(Constants.ATTRIBUTE_REQATTR_STRING));
                //Send attribute name
                writeString(name, true);
            }
            //Send attribute value
            writeString(value, true);
        }

        //End of the packet
        writeByte(Constants.REQUEST_TERMINATOR);
    }

    /**
     * ForwardRequestMessageGetBuilder. An easy way to create ForwardRequest
     * messages for HTTP GET request
     *
     * @param url URL The message URL
     * @throws UnknownHostException Generic UnknownHostException
     * @return Instance of ForwardRequestMessage
     */
    static public ForwardRequestMessage ForwardRequestMessageGetBuilder(URL url) throws UnknownHostException
    {
        return new ForwardRequestMessage(2, url, null, null);
    }

    /**
     * ForwardRequestMessagePostBuilder. An easy way to create ForwardRequest
     * messages for HTTP POST request
     *
     * @param url URL The message URL
     * @param contentLength int The expected Content-Length
     * @throws UnknownHostException Generic UnknownHostException
     * @return Instance of ForwardRequestMessage
     */
    static public ForwardRequestMessage ForwardRequestMessagePostBuilder(URL url, int contentLength) throws UnknownHostException
    {
        List<Pair<String, String>> headers = new LinkedList<>();
        headers.add(Pair.make("Content-Length", String.valueOf(contentLength)));
        if (contentLength > 0) {
            headers.add(Pair.make("Content-Type", "application/x-www-form-urlencoded"));
        }
        return new ForwardRequestMessage(4, url, headers, null);
    }

    /**
     * Returns the HTTP verb used by this message
     *
     * @return the verb used within the ForwardRequestMessage
     */
    public int getMethod()
    {
        return method;
    }

    /**
     * Returns the HTTP protocol used by this message
     *
     * @return the version of the HTTP protocol
     */
    public String getProtocol()
    {
        return protocol;
    }

    /**
     * Returns the HTTP Uri
     *
     * @return the message's URI
     */
    public String getRequestUri()
    {
        return requestUri;
    }

    /**
     * Returns the client's IP address
     *
     * @return Client's IP address
     */
    public String getRemoteAddr()
    {
        return remoteAddr;
    }

    /**
     * Returns the client's hostname
     *
     * @return Client's hostname
     */
    public String getRemoteHost()
    {
        return remoteHost;
    }

    /**
     * Returns the server's FQDM
     *
     * @return Server's domain name
     */
    public String getServerName()
    {
        return serverName;
    }

    /**
     * Returns the server's TCP port
     *
     * @return Server's TCP port
     */
    public int getServerPort()
    {
        return serverPort;
    }

    /**
     * Returns whether the HTTP request is over HTTP or HTTPS
     *
     * @return true if over SSL,false otherwise
     */
    public boolean isSsl()
    {
        return isSsl;
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

    final void addHeader(String name, String value)
    {
        headers.add(Pair.make(name, value));
    }

    final void addAttribute(String name, String value)
    {
        attributes.add(Pair.make(name, value));
    }

    /**
     * Returns the number of headers in the ForwardRequestMessage packet
     *
     * @return the number of headers
     */
    public int numHeaders()
    {
        return headers.size();
    }

    /**
     * Returns the number of attributes in the ForwardRequestMessage packet
     *
     * @return the number of attributes
     */
    public int numAttributes()
    {
        return attributes.size();
    }

    static ForwardRequestMessage readFrom(InputStream in) throws IOException
    {
        int method = AjpReader.readByte(in);
        String protocol = AjpReader.readString(in);
        String requestUri = AjpReader.readString(in);
        String remoteAddr = AjpReader.readString(in);
        String remoteHost = AjpReader.readString(in);
        String serverName = AjpReader.readString(in);
        int serverPort = AjpReader.readInt(in);
        boolean isSsl = AjpReader.readBoolean(in);
        int numHeaders = AjpReader.readInt(in);

        List<Pair<String, String>> headers = new LinkedList<>();
        for (int i = 0; i < numHeaders; i++) {
            int b1 = AjpReader.readByte(in);
            int b2 = AjpReader.readByte(in);

            String name = "";
            if (b1 == Constants.HEADERS_GENERIC && Constants.COMMON_HEADERS.containsValue(b2)) {
                for (Map.Entry<String, Integer> entry : Constants.COMMON_HEADERS.entrySet()) {
                    String key = entry.getKey();
                    Integer value = entry.getValue();
                    if (value == b2) {
                        name = key;
                    }
                }
            } else {
                name = AjpReader.readString(AjpReader.makeInt(b1, b2), in);
            }
            headers.add(Pair.make(name, AjpReader.readString(in)));
        }

        //read 'till the end
        List<Pair<String, String>> attributes = new LinkedList<>();
        while (in.available() > 0) {
            int next = AjpReader.readByte(in);
            if (next == Constants.REQUEST_TERMINATOR) {
                break;
            } else if (Constants.COMMON_ATTRIBUTES.containsValue(next)) {
                String name = "";
                for (Map.Entry<String, Integer> entry : Constants.COMMON_ATTRIBUTES.entrySet()) {
                    String key = entry.getKey();
                    Integer value = entry.getValue();
                    if (value == next) {
                        name = key;
                        //Exception for req_attribute
                        if (name.equalsIgnoreCase(Constants.ATTRIBUTE_REQATTR_STRING)) {
                            name = AjpReader.readString(in);
                        }
                    }
                }
                attributes.add(Pair.make(name, AjpReader.readString(in)));
            } else {
                System.out.println("[!] ForwardRequestMessage Unexpected Attribute: " + next);
            }
        }

        return new ForwardRequestMessage(method, protocol, requestUri, remoteAddr,
                remoteHost, serverName, serverPort, isSsl, headers, attributes);
    }

    @Override
    public String toString()
    {
        StringBuilder sb = new StringBuilder();
        sb.append("Method: ").append(method).append("\n");
        sb.append("Protocol: ").append(protocol).append("\n");
        sb.append("RequestUri: ").append(requestUri).append("\n");
        sb.append("RemoteAddr: ").append(remoteAddr).append("\n");
        sb.append("RemoteHost: ").append(remoteHost).append("\n");
        sb.append("ServerName: ").append(serverName).append("\n");
        sb.append("ServerPort: ").append(serverPort).append("\n");
        sb.append("isSsl: ").append(isSsl).append("\n");
        for (Pair<String, String> header : headers) {
            String name = header.a;
            String value = header.b;
            sb.append("Header: ").append(name).append(" ").append(value).append("\n");
        }

        for (Pair<String, String> attribute : attributes) {
            String name = attribute.a;
            String value = attribute.b;
            sb.append("Attribute: ").append(name).append(" ").append(value).append("\n");
        }

        return sb.toString();
    }

    /**
     * Returns a meaningful name for the packet type
     *
     * @return Name of the packet type
     */
    @Override
    public String getName()
    {
        return "Forward Request (begin the request-processing cycle)";
    }

    /**
     * Returns a description for the packet type
     *
     * @return Description of the packet type.
     */
    @Override
    public String getDescription()
    {
        return "Begin the request-processing cycle with the following data.\n" + this.toString();
    }
}
