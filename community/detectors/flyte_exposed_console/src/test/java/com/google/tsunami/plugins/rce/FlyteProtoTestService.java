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

import flyteidl.admin.ExecutionOuterClass;
import flyteidl.admin.ProjectOuterClass.ProjectListRequest;
import flyteidl.admin.ProjectOuterClass.ProjectRegisterRequest;
import flyteidl.admin.ProjectOuterClass.ProjectRegisterResponse;
import flyteidl.admin.ProjectOuterClass.Projects;
import flyteidl.admin.TaskOuterClass;
import flyteidl.service.AdminServiceGrpc;
import io.grpc.stub.StreamObserver;

public class FlyteProtoTestService extends AdminServiceGrpc.AdminServiceImplBase {

  @Override
  public void registerProject(ProjectRegisterRequest request,
      StreamObserver<ProjectRegisterResponse> responseObserver) {

    responseObserver.onNext(ProjectRegisterResponse.newBuilder().build());
    responseObserver.onCompleted();
  }

  @Override
  public void listProjects(ProjectListRequest request, StreamObserver<Projects> responseObserver) {
    responseObserver.onNext(Projects.newBuilder().build());
    responseObserver.onCompleted();
  }

  @Override
  public void createTask(
      TaskOuterClass.TaskCreateRequest request,
      StreamObserver<TaskOuterClass.TaskCreateResponse> responseObserver) {
    responseObserver.onNext(TaskOuterClass.TaskCreateResponse.newBuilder().build());
    responseObserver.onCompleted();
  }

  @Override
  public void createExecution(
      ExecutionOuterClass.ExecutionCreateRequest request,
      StreamObserver<ExecutionOuterClass.ExecutionCreateResponse> responseObserver) {
    responseObserver.onNext(ExecutionOuterClass.ExecutionCreateResponse.newBuilder().build());
    responseObserver.onCompleted();
  }

 
}
