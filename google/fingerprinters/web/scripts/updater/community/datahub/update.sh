#!/usr/bin/env bash

# Copyright 2022 Google LLC
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
# Path to the configurations for starting a live instance of DataHub.
DATAHUB_APP_PATH="${SCRIPT_PATH}/app"
# Path to the temporary data holder.
TMP_DATA="/tmp/datahub_fingerprints"
# Path to the local git repository for DataHub codebase.
GIT_REPO="${TMP_DATA}/repo"
# Path to the directory of all the updated fingerprints data.
FINGERPRINTS_PATH="${TMP_DATA}/fingerprints"
# Json data of the final result.
JSON_DATA="${FINGERPRINTS_PATH}/fingerprint.json"
# Binary proto data of the final result.
BIN_DATA="${FINGERPRINTS_PATH}/fingerprint.binproto"
# Read all the versions of the new react frontend to be fingerprinted.
readarray -t ALL_VERSIONS < "${SCRIPT_PATH}/versions.txt"
BIN_DATA="${FINGERPRINTS_PATH}/fingerprint.binproto"
# Read all the versions  of the old frontend to be fingerprinted.
readarray -t ALL_VERSIONS_OLD_FRONTEND < "${SCRIPT_PATH}/versions_old_frontend.txt"
mkdir -p "${FINGERPRINTS_PATH}"

startDataHub() {
  local version="$1"
  local frontend_type="$2"
  pushd "${DATAHUB_APP_PATH}" >/dev/null
    DATAHUB_VERSION="${version}" DATAHUB_FRONTEND_TYPE="${frontend_type}" docker-compose up -d
  popd >/dev/null
}

stopDataHub() {
  local version="$1"
  local frontend_type="$2"
  pushd "${DATAHUB_APP_PATH}" >/dev/null
    DATAHUB_VERSION="${version}" DATAHUB_FRONTEND_TYPE="${frontend_type}" docker-compose down --volumes --remove-orphans
  popd >/dev/null
}

# Create the fingerprint for a frontend.
# First argument expects the datahub version
# Second argument expects which kind of frontend we want:
## The new one: datahub-frontend-react
## The old one: datahub-frontend
createFingerprintForFrontend() {
  local datahub_version="$1"
  local datahub_frontend_type="$2"

  echo "Fingerprinting Datahub version ${datahub_version} ..."

  # Start a live instance of DataHub.
  startDataHub "${datahub_version}" "${datahub_frontend_type}"
  # Arbitrarily chosen so that DataHub is up and running.
  echo "Waiting for DataHub ${datahub_version} to be ready ..."
  sleep 30

  # Checkout the repository to the correct tag.
  checkOutRepo "${GIT_REPO}" "${datahub_version}"

  updateFingerprint \
    "datahub" \
    "${datahub_version}" \
    "${FINGERPRINTS_PATH}" \
    "${GIT_REPO}" \
    "http://localhost:9002"

  # Stop the live instance of DataHub.
  stopDataHub "${datahub_version}" "${datahub_frontend_type}"
}

# Convert the existing data file to a human-readable json file.
convertFingerprint \
  "${PROJECT_ROOT}/src/main/resources/fingerprinters/web/data/community/datahub.binproto" \
  "${JSON_DATA}"

# Fetch DataHub codebase.
if [[ ! -d "${GIT_REPO}" ]] ; then
  git clone https://github.com/datahub-project/datahub.git "${GIT_REPO}"
fi

# Update for all the versions listed in versions.txt file.
# Newer datahub versions use a react frontend. This is fingerprinted here:
for datahub_version in "${ALL_VERSIONS[@]}"; do
  createFingerprintForFrontend "${datahub_version}" "datahub-frontend-react"
done

# Update for all the versions listed in versions_old_frontend.txt file.
# Here the fingerprints for the old frontend are created
for datahub_version in "${ALL_VERSIONS_OLD_FRONTEND[@]}"; do
  createFingerprintForFrontend "${datahub_version}" "datahub-frontend"
done

convertFingerprint "${JSON_DATA}" "${BIN_DATA}"

echo "Fingerprint updated for DataHub. Please commit the following file:"
echo "  ${BIN_DATA}"
