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
# Path to the configurations for starting a live instance of the service.
APP_PATH="${SCRIPT_PATH}/app"
# Path to the temporary data holder.
TMP_DATA="/root/teamcity_fingerprints"
# Path to the local code repository.
CODE_REPO="${TMP_DATA}/repo"
# Path to the directory of all the updated fingerprints data.
FINGERPRINTS_PATH="${TMP_DATA}/fingerprints"
# Json data of the final result.
JSON_DATA="${FINGERPRINTS_PATH}/fingerprint.json"
# Binary proto data of the final result.
BIN_DATA="${FINGERPRINTS_PATH}/fingerprint.binproto"
# Read all the versions to be fingerprinted.
readarray -t ALL_VERSIONS < "${SCRIPT_PATH}/versions.txt"
mkdir -p "${CODE_REPO}"
mkdir -p "${FINGERPRINTS_PATH}"

startService() {
  local version="$1"
  pushd "${APP_PATH}" >/dev/null
    # set COMPOSE_HTTP_TIMEOUT to avoid timeout errors with docker-compose operations
    APP_VERSION="${version}" COMPOSE_HTTP_TIMEOUT=200 docker-compose up -d
  popd >/dev/null
}

stopService() {
  local version="$1"
  pushd "${APP_PATH}" >/dev/null
    APP_VERSION="${version}" COMPOSE_HTTP_TIMEOUT=200 docker-compose down --volumes --remove-orphans
  popd >/dev/null
}

downloadCode() {
  local code_repo="$1"
  local version="$2"
  pushd "${code_repo}" >/dev/null
    mkdir -p "${version}"
    pushd "${version}" >/dev/null
      curl "https://download.jetbrains.com/teamcity/TeamCity-${version}.tar.gz" -L -o - | tar -xzf -
    popd >/dev/null
  popd >/dev/null
}

# Convert the existing data file to a human-readable json file.
convertFingerprint \
  "${PROJECT_ROOT}/src/main/resources/fingerprinters/web/data/community/teamcity.binproto" \
  "${JSON_DATA}"

# Update for all the versions listed in versions.txt file.
for APP_VERSION in "${ALL_VERSIONS[@]}"; do
  echo "Fingerprinting TeamCity version ${APP_VERSION} ..."
  # Start a live instance of TeamCity.
  startService "${APP_VERSION}"

  # Checkout the repository to the correct tag.
  downloadCode "${CODE_REPO}" "${APP_VERSION}"
  RESOURCES_PATH="${CODE_REPO}/${APP_VERSION}/TeamCity/webapps/ROOT"

  # Arbitrarily chosen so that TeamCity is up and running.
  echo "Waiting for TeamCity ${APP_VERSION} to be ready ..."
  sleep 90
  # Finish the installation process.

  updateFingerprint \
    "teamcity" \
    "${APP_VERSION}" \
    "${FINGERPRINTS_PATH}" \
    "${RESOURCES_PATH}" \
    "http://localhost:8080"

  # Stop the live instance of TeamCity.
  stopService "${APP_VERSION}"
done

convertFingerprint "${JSON_DATA}" "${BIN_DATA}"

echo "Fingerprint updated for TeamCity. Please commit the following file:"
echo "  ${BIN_DATA}"
