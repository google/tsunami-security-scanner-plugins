#!/usr/bin/env bash

# Copyright 2024 Google LLC
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#     https://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.

set -e

source ../../common.sh

SCRIPT_PATH="$(cd -- "$(dirname "$0")" >/dev/null 2>&1 ; pwd -P)"
PROJECT_ROOT="$(cd -- "${SCRIPT_PATH}/../../../.." >/dev/null 2>&1 ; pwd -P)"
APP_PATH="${SCRIPT_PATH}/app"
TMP_DATA="/tmp/kubeflow_fingerprints"
GIT_REPO="${TMP_DATA}/repo"
FINGERPRINTS_PATH="${TMP_DATA}/fingerprints"
JSON_DATA="${FINGERPRINTS_PATH}/fingerprint.json"
BIN_DATA="${FINGERPRINTS_PATH}/fingerprint.binproto"
BINPROTO="${PROJECT_ROOT}/src/main/resources/fingerprinters/web/data/community/kubeflow.binproto"

mkdir -p "${FINGERPRINTS_PATH}"


removeCluster(){
  docker rmi -f kind_cluster:latest
}
buildCluster() {
  pushd "${APP_PATH}" >/dev/null
  docker build -t kind_cluster:latest -f Dockerfile.kind .
  popd >/dev/null
}

buildKubeFlowImage(){
  local version="$1"
  pushd "${GIT_REPO}" >/dev/null
  docker build -t kubeflow-models-ui:${version} -f Dockerfile .
  popd >/dev/null
}

removeKubeFlowImage(){
  local version="$1"
  docker rmi -f kubeflow-models-ui:${version}
}

startKubeflow(){
  local version="$1"
  pushd "${APP_PATH}" >/dev/null
  MODELS_WEB_APP_TAG="${version}" docker-compose up -d
  popd >/dev/null
}

stopContainer(){
  local name="$1"

  CONTAINER_ID=$(docker ps | grep "${name}" | cut -d " " -f1)
  if [ -n "$KUBEFLOW_CONTAINER" ]; then
    docker stop $CONTAINER_ID
  fi

}

stopKubeFlow(){
  local version="$1"
  pushd "${APP_PATH}" >/dev/null
  MODELS_WEB_APP_TAG="${version}" docker-compose down
  stopContainer "kindest/node"
  stopContainer "kubeflow-models-ui:${version}"
  stopContainer "kind_cluster"

  popd >/dev/null
}

waitForServer() {
  local url="http://localhost:8080"
  local wait_time="${2:-5}"

  echo "Waiting for server at $url to be available..."

  while true; do
    http_response=$(curl --write-out "%{http_code}" --silent --output /dev/null "$url" || echo "failed")
    if [ "$http_response" -eq 200 ]; then
      echo "Server is up and running at $url!"
      break
    elif [ "$http_response" = "failed" ]; then
      echo "Curl command failed. Waiting for $wait_time seconds before retrying..."
    else
      echo "Server not yet available (HTTP status: $http_response). Waiting for $wait_time seconds..."
    fi
    sleep "$wait_time"
  done
}


#Build kuberentes cluster
buildCluster

# Convert existing data file to a human-readable JSON file
convertFingerprint "${BINPROTO}" "${JSON_DATA}"

# Clone Kubeflow Models UI repository if not already present
if [[ ! -d "${GIT_REPO}" ]]; then
  git clone https://github.com/kserve/models-web-app.git "${GIT_REPO}"
fi


# Read all versions to be fingerprinted
readarray -t ALL_VERSIONS < "${SCRIPT_PATH}/versions.txt"

# Update fingerprints for all listed versions
for app_version in "${ALL_VERSIONS[@]}"; do
  echo "Fingerprinting Kubeflow Models UI version ${app_version} ..."

  # Checkout the repository to the correct tag
  checkOutRepo "${GIT_REPO}" "v${app_version}"

  # Build and run the container
  buildKubeFlowImage "${app_version}"

  # Start the cluser and kubeflow
  startKubeflow "${app_version}"

  echo "Waiting for Kubeflow ${app_version} to be ready ..."
  sleep 60

  # Wait for the container to be fully up
  waitForServer

  echo "Application is up, updating fingerprint."

  # Capture the fingerprints
  updateFingerprint \
    "kubeflow" \
    "${app_version}" \
    "${FINGERPRINTS_PATH}" \
    "${GIT_REPO}" \
    "http://localhost:8080"

  # Stop and remove the container
  stopKubeFlow "${app_version}"

  removeKubeFlowImage "${app_version}"

done

removeCluster

# Convert the updated JSON data to binary proto format
convertFingerprint "${JSON_DATA}" "${BIN_DATA}"

echo "Fingerprint updated for Kubeflow Models UI. Please commit the following file:"
echo "  ${BIN_DATA}"
echo "to"
echo "  ${BINPROTO}"
