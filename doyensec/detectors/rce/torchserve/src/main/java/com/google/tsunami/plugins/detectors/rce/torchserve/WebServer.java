package com.google.tsunami.plugins.detectors.rce.torchserve;

import com.google.common.flogger.GoogleLogger;
import com.sun.net.httpserver.HttpExchange;
import com.sun.net.httpserver.HttpServer;
import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.net.InetSocketAddress;

public class WebServer {
  private HttpServer httpServer;
  private static final GoogleLogger logger = GoogleLogger.forEnclosingClass();

  public void start(String hostname, int port) throws IOException {
    try {
      httpServer = HttpServer.create(new InetSocketAddress(hostname, port), 0);
      httpServer.setExecutor(null); // sets the executor to null to use the default executor
      httpServer.createContext("/", this::handleRequest); // creates a context with a handler
      httpServer.start();
      logger.atInfo().log("Web server started on %s:%d", hostname, port);
    } catch (IOException e) {
      logger.atSevere().withCause(e).log("IO Exception starting web server");
      throw e;
    } catch (Exception e) {
      logger.atWarning().withCause(e).log("Error starting web server");
      throw e;
    }
  }

  private void handleRequest(HttpExchange exchange) throws IOException {
    String requestMethod = exchange.getRequestMethod();
    logger.atInfo().log("Received %s request", requestMethod);

    if ("GET".equals(requestMethod)) {
      serveModelFile(exchange);
    } else {
      logger.atWarning().log("Unsupported request method: %s", requestMethod);
      exchange.sendResponseHeaders(405, -1); // Method Not Allowed
    }
    exchange.close();
  }

  private void serveModelFile(HttpExchange exchange) throws IOException {
    try (InputStream is = getClass().getClassLoader().getResourceAsStream("model.mar")) {
      if (is == null) {
        logger.atSevere().log("Model file not found");
        exchange.sendResponseHeaders(404, -1); // Not Found
        return;
      }

      byte[] zipContent = is.readAllBytes();
      exchange.getResponseHeaders().add("Content-Type", "application/zip");
      exchange.sendResponseHeaders(200, zipContent.length);

      try (OutputStream os = exchange.getResponseBody()) {
        os.write(zipContent);
      }
    } catch (IOException e) {
      logger.atSevere().withCause(e).log("Error serving model file");
      exchange.sendResponseHeaders(500, -1); // Internal Server Error
    }
  }

  public void stop() {
    if (httpServer != null) {
      httpServer.stop(0);
      logger.atInfo().log("Web server stopped");
    }
  }
}
