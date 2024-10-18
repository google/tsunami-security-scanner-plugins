/*
 * Copyright 2024 Google LLC
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 * http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

package com.google.tsunami.plugins.rce;

import static com.google.tsunami.common.data.NetworkEndpointUtils.forHostnameAndPort;
import static com.google.tsunami.plugins.rce.ExposedFlyteConsoleDetector.*;
import static org.mockito.AdditionalAnswers.delegatesTo;
import static org.mockito.Mockito.anyString;
import static org.mockito.Mockito.doNothing;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.spy;

import com.google.protobuf.util.Timestamps;
import com.google.tsunami.common.time.testing.FakeUtcClock;
import com.google.tsunami.proto.DetectionReport;
import com.google.tsunami.proto.DetectionStatus;
import com.google.tsunami.proto.NetworkEndpoint;
import com.google.tsunami.proto.NetworkService;
import com.google.tsunami.proto.Severity;
import com.google.tsunami.proto.TargetInfo;
import com.google.tsunami.proto.TransportProtocol;
import com.google.tsunami.proto.Vulnerability;
import com.google.tsunami.proto.VulnerabilityId;
import flyteidl.service.AdminServiceGrpc;
import flyteidl.service.AdminServiceGrpc.AdminServiceBlockingStub;
import io.grpc.ClientInterceptors;
import io.grpc.ManagedChannel;
import io.grpc.Metadata;
import io.grpc.Server;
import io.grpc.ServerCall;
import io.grpc.ServerCallHandler;
import io.grpc.ServerInterceptor;
import io.grpc.ServerInterceptors;
import io.grpc.ServerServiceDefinition;
import io.grpc.inprocess.InProcessChannelBuilder;
import io.grpc.inprocess.InProcessServerBuilder;
import io.grpc.testing.GrpcCleanupRule;
import java.io.IOException;
import java.net.URISyntaxException;
import java.time.Instant;
import okhttp3.mockwebserver.MockWebServer;

final class TestHelper {
  private static final GrpcCleanupRule grpcCleanup = new GrpcCleanupRule();
  private static final ServerInterceptor mockServerInterceptor = mock(ServerInterceptor.class,
      delegatesTo(new ServerInterceptor() {
        @Override
        public <ReqT, RespT> ServerCall.Listener<ReqT> interceptCall(ServerCall<ReqT, RespT> call, Metadata headers,
            ServerCallHandler<ReqT, RespT> next) {
          return next.startCall(call, headers);
        }
      }));

  private TestHelper() {
  }

  static NetworkService createFlyteConsole(MockWebServer mockService) {
    return NetworkService.newBuilder()
        .setNetworkEndpoint(forHostnameAndPort(mockService.getHostName(), mockService.getPort()))
        .setTransportProtocol(TransportProtocol.TCP)
        .setServiceName("http")
        .build();
  }

  static TargetInfo buildTargetInfo(NetworkEndpoint networkEndpoint) {
    return TargetInfo.newBuilder().addNetworkEndpoints(networkEndpoint).build();
  }

  static DetectionReport buildValidDetectionReport(
      TargetInfo target, NetworkService service, FakeUtcClock fakeUtcClock) {
    return DetectionReport.newBuilder()
        .setTargetInfo(target)
        .setNetworkService(service)
        .setDetectionTimestamp(Timestamps.fromMillis(Instant.now(fakeUtcClock).toEpochMilli()))
        .setDetectionStatus(DetectionStatus.VULNERABILITY_VERIFIED)
        .setVulnerability(
            Vulnerability.newBuilder()
                .setMainId(
                    VulnerabilityId.newBuilder()
                        .setPublisher(VULNERABILITY_REPORT_PUBLISHER)
                        .setValue(VULNERABILITY_REPORT_ID))
                .setSeverity(Severity.CRITICAL)
                .setTitle(VULNERABILITY_REPORT_TITLE)
                .setDescription(VULN_DESCRIPTION)
                .setRecommendation(RECOMMENDATION))
        .build();
  }

  private static ManagedChannel buildChannel(String serverName) {
    return InProcessChannelBuilder.forName(serverName).directExecutor().build();
  }

  private static Server buildServer(String serverName, ServerServiceDefinition stubService) {
    return InProcessServerBuilder.forName(serverName)
        .directExecutor()
        .addService(stubService)
        .build();
  }

  /**
   * Creates and returns a gRPC AdminServiceBlockingStub using an in-process
   * server for testing purposes.
   *
   * @return A configured AdminServiceBlockingStub instance for testing.
   * @throws IOException If an I/O error occurs during server or channel creation.
   */

  private static AdminServiceBlockingStub getStubService() throws IOException {

    // Generate a unique server name for the in-process server.
    String serverName = InProcessServerBuilder.generateName();

    // Create an instance of the FlyteProtoTestService to be used as the gRPC
    // service.
    FlyteProtoTestService stubService = new FlyteProtoTestService();

    // Intercept the service with a mock server interceptor for testing purposes.
    ServerServiceDefinition interceptedService = ServerInterceptors.intercept(stubService, mockServerInterceptor);

    // Build the in-process gRPC server using the intercepted service.    
    Server build = TestHelper.buildServer(serverName, interceptedService);
    grpcCleanup.register(build.start());


    
    ManagedChannel channel = grpcCleanup.register(TestHelper.buildChannel(serverName));
    AdminServiceGrpc.AdminServiceBlockingStub blockingStub = AdminServiceGrpc.newBlockingStub(
        ClientInterceptors.intercept(channel));
    return blockingStub;
  }

  /**
   * Creates a mock instance of the FlyteProtoClient with a pre-configured gRPC
   * stub service.
   *
   * @return A mock FlyteProtoClient instance with a stub service set.
   * @throws IOException        If an I/O error occurs during the setup.
   * @throws URISyntaxException If there is an error in the URI syntax during the
   *                            setup.
   */

  static FlyteProtoClient getMockFlyteProtoClient() throws IOException, URISyntaxException {

    // Create a spy instance of FlyteProtoClient to enable mocking specific methods.
    FlyteProtoClient client = spy(new FlyteProtoClient());

    // Prevent the buildService method from being executed by mocking it to do
    // nothing.This is done because the stub service is already being passed to the
    // client.
    doNothing().when(client).buildService(anyString());

    client.setStub(TestHelper.getStubService());
    return client;
  }
}