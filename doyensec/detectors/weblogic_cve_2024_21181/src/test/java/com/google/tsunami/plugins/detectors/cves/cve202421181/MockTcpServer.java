package com.google.tsunami.plugins.detectors.cves.cve202421181;

import java.io.BufferedInputStream;
import java.io.BufferedOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.util.ArrayList;
import java.util.Collections;
import java.util.List;

public class MockTcpServer extends Thread {
  BufferedInputStream in;
  BufferedOutputStream out;
  List<byte[]> mockResponses = new ArrayList<>();
  private final List<byte[]> requestsReceived = new ArrayList<>();

  public MockTcpServer(InputStream in, OutputStream out) {
    this.setDaemon(true);
    this.in = new BufferedInputStream(in);
    this.out = new BufferedOutputStream(out);
  }

  public void enqueue(byte[]... responses) {
    Collections.addAll(mockResponses, responses);
  }

  public int getRequestCount() {
    return requestsReceived.size();
  }

  public List<byte[]> getRequestsReceived() {
    return requestsReceived;
  }

  public byte[] getRequestReceived(int idx) {
    return requestsReceived.get(idx);
  }

  @Override
  public void run() {
    for (byte[] mockResponse : mockResponses) {
      try {
        if (this.isInterrupted()) {
          return;
        }

        byte[] requestBytes = new byte[8192];
        int readBytes = in.read(requestBytes);
        requestsReceived.add(requestBytes);
        System.out.printf("Received %d bytes%n", readBytes);

        if (this.isInterrupted()) {
          return;
        }

        out.write(mockResponse);
        out.flush();
        System.out.printf("Sent %d bytes%n", mockResponse.length);
      } catch (IOException e) {
        e.printStackTrace();
      }
    }
  }
}
