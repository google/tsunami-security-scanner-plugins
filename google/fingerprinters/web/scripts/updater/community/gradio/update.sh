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
# Path to the configurations for starting a live instance of Gradio.
GRADIO_APP_PATH="${SCRIPT_PATH}/app"
# Path to the temporary data holder.
TMP_DATA="/tmp/gradio_fingerprints"
# Path to the local git repository for Gradio codebase.
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

startGradio() {
  local version="$1"
  pushd "${GRADIO_APP_PATH}" >/dev/null
    GRADIO_VERSION="${version}" docker-compose up --build -d
  popd >/dev/null
}

stopGradio() {
  local version="$1"
  pushd "${GRADIO_APP_PATH}" >/dev/null
    GRADIO_VERSION="${version}" docker-compose down --volumes --remove-orphans
  popd >/dev/null
}

# Convert the existing data file to a human-readable json file.
convertFingerprint \
  "${PROJECT_ROOT}/src/main/resources/fingerprinters/web/data/community/gradio.binproto" \
  "${JSON_DATA}"

# Fetch Gradio codebase.
if [[ ! -d "${GIT_REPO}" ]] ; then
  git clone https://github.com/gradio-app/gradio.git "${GIT_REPO}"
fi

# Update for all the versions listed in versions.txt file.
for gradio_version in "${ALL_VERSIONS[@]}"; do
  echo "Fingerprinting Gradio version ${gradio_version} ..."
  # Start a live instance of Gradio.
  startGradio "${gradio_version}"
  # Arbitrarily chosen so that Gradio is up and running.
  echo "Waiting for Gradio ${gradio_version} to be ready ..."
  sleep 30

  # Checkout the repository to the correct tag.
  checkOutRepo "${GIT_REPO}" "gradio@${gradio_version}"

  updateFingerprint \
    "gradio" \
    "${gradio_version}" \
    "${FINGERPRINTS_PATH}" \
    "${GIT_REPO}/js/app/public/" \
    "http://localhost:8000"

  # Stop the live instance of Gradio.
  stopGradio "${gradio_version}"
done

convertFingerprint "${JSON_DATA}" "${BIN_DATA}"

echo "Fingerprint updated for Gradio. Please commit the following file:"
echo "  ${BIN_DATA}"
