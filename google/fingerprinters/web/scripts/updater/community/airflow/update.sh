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
# Path to the configurations for starting a live instance of Airflow.
APP_PATH="${SCRIPT_PATH}/app"
# Path to the temporary data holder.
TMP_DATA="/tmp/airflow_fingerprints"
# Path to the local git repository for Airflow codebase.
GIT_REPO="${TMP_DATA}/repo"
# Path to the directory of all the updated fingerprints data.
FINGERPRINTS_PATH="${TMP_DATA}/fingerprints"
# Json data of the final result.
JSON_DATA="${FINGERPRINTS_PATH}/fingerprint.json"
# Binary proto data of the final result.
BIN_DATA="${FINGERPRINTS_PATH}/airflow.binproto"
# Read all the versions to be fingerprinted.
readarray -t ALL_VERSIONS < "${SCRIPT_PATH}/versions.txt"
mkdir -p "${FINGERPRINTS_PATH}"

startAirflow() {
  local version="$1"
  pushd "${APP_PATH}" >/dev/null
    COMPOSE_HTTP_TIMEOUT=200 AIRFLOW_UID=65535 docker-compose -f airflow-${version}.yaml up -d
  popd >/dev/null
}

stopAirflow() {
  local version="$1"
  pushd "${APP_PATH}" >/dev/null
    COMPOSE_HTTP_TIMEOUT=200 AIRFLOW_UID=65535 docker-compose -f airflow-${version}.yaml down --volumes --remove-orphans
  popd >/dev/null
}

# Convert the existing data file to a human-readable json file.
convertFingerprint \
  "${PROJECT_ROOT}/src/main/resources/fingerprinters/web/data/community/airflow.binproto" \
  "${JSON_DATA}"

# Fetch Airflow codebase.
if [[ ! -d "${GIT_REPO}" ]] ; then
  git clone https://github.com/apache/airflow.git "${GIT_REPO}"
fi

# Update for all the versions listed in versions.txt file.
for version in "${ALL_VERSIONS[@]}"; do
  echo "Fingerprinting Airflow version ${version} ..."
  # Download docker-compose.yaml of each version.
  curl -L https://airflow.apache.org/docs/apache-airflow/${version}/docker-compose.yaml -o $APP_PATH/airflow-${version}.yaml
  # Start a live instance of Airflow.
  startAirflow "${version}"
  # Arbitrarily chosen so that Airflow is up and running.
  echo "Waiting for Airflow ${version} to be ready ..."
  sleep 60
  # No need to do other installation process for Airflow.
  touch ${FINGERPRINTS_PATH}/fingerprint.${version}.json

  # Checkout the repository to the correct tag.
  checkOutRepo "${GIT_REPO}" "${version}"

  updateFingerprint \
    "airflow" \
    "${version}" \
    "${FINGERPRINTS_PATH}" \
    "${GIT_REPO}" \
    "http://localhost:8080"

  # Stop the live instance of Airflow.
  stopAirflow "${version}"
done

convertFingerprint "${JSON_DATA}" "${BIN_DATA}"

echo "Fingerprint updated for Airflow. Please commit the following file:"
echo "  ${BIN_DATA}"
