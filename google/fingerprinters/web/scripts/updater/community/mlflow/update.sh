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
# Root path to the web fingerprinter plugin.
PROJECT_ROOT="$(cd -- "${SCRIPT_PATH}/../../../.." >/dev/null 2>&1 ; pwd -P)"
# Path to the configurations for starting a live instance of MLflow.
APP_PATH="${SCRIPT_PATH}/app"
# Path to the temporary data holder.
TMP_DATA="/tmp/mlflow_fingerprints"
# Path to the local git repository for MLflow codebase.
GIT_REPO="${TMP_DATA}/repo"
# Path to the directory of all the updated fingerprints data.
FINGERPRINTS_PATH="${TMP_DATA}/fingerprints"
# Json data of the final result.
JSON_DATA="${FINGERPRINTS_PATH}/fingerprint.json"
# Binary proto data of the final result.
BIN_DATA="${FINGERPRINTS_PATH}/fingerprint.binproto"
# Read all the versions to be fingerprinted.
readarray -t ALL_VERSIONS < "${SCRIPT_PATH}/versions.txt"

mkdir -p "${FINGERPRINTS_PATH}"

BINPROTO="${PROJECT_ROOT}/src/main/resources/fingerprinters/web/data/community/mlflow.binproto"

StartMLflow() {
  local version="$1"
  pushd "${APP_PATH}" >/dev/null
    MLFLOW_VERSION="${version}" docker-compose up -d
  popd >/dev/null
}

StopMLflow() {
  local version="$1"
  pushd "${APP_PATH}" >/dev/null
    MLFLOW_VERSION="${version}" docker-compose down --volumes --remove-orphans
  popd >/dev/null
}

CreateFingerprintForMLflow() {
  local mlflowVersion="$1"

  echo "Fingerprinting MLflow version ${mlflowVersion} ..."
  # Start a live instance of MLflow.
  StartMLflow "${mlflowVersion}"

  # Arbitrarily chosen so that MLflow is up and running.
  echo "Waiting for MLflow ${mlflowVersion} to be ready ..."
  sleep 20

  # Checkout the repository to the correct tag.
  checkOutRepo "${GIT_REPO}" "${mlflowVersion}"

  updateFingerprint \
    "mlflow" \
    "${mlflowVersion}" \
    "${FINGERPRINTS_PATH}" \
    "${GIT_REPO}/mlflow" \
    "http://localhost:5000"

  # Stop the live instance of MLflow.
  StopMLflow "${mlflowVersion}"
}

# Fetch MLflow codebase.
if [[ ! -d "${GIT_REPO}" ]] ; then
  git clone https://github.com/mlflow/mlflow "${GIT_REPO}"
fi

# Get versions
for mlflow_version in "${ALL_VERSIONS[@]}"; do
  CreateFingerprintForMLflow "${mlflow_version}"
done

convertFingerprint "${JSON_DATA}" "${BIN_DATA}"

echo "Fingerprint updated for MLflow. Please commit the following file:"
echo "  ${BIN_DATA}"
echo "to"
echo "  ${BINPROTO}"
