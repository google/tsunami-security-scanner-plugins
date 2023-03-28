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
# Path to the configurations
APP_PATH="${SCRIPT_PATH}/app"
# Path to the temporary data holder.
TMP_DATA="/tmp/adminer_fingerprints"
# Path to the local git repository for adminer codebase.
GIT_REPO="${TMP_DATA}/repo"
# Path to the directory of all the updated fingerprints data.
FINGERPRINTS_PATH="${TMP_DATA}/fingerprints"
# Json data of the final result.
JSON_DATA="${FINGERPRINTS_PATH}/fingerprint.json"
# Binary proto data of the final result.
BIN_DATA="${FINGERPRINTS_PATH}/fingerprint.binproto"

mkdir -p "${FINGERPRINTS_PATH}"

BINPROTO="${PROJECT_ROOT}/src/main/resources/fingerprinters/web/data/community/adminer.binproto"

# Convert the existing data file to a human-readable json file.
convertFingerprint "${BINPROTO}"  "${JSON_DATA}"


# Fetch Adminer codebase.
if [[ ! -d "${GIT_REPO}" ]] ; then
  git clone https://github.com/vrana/adminer/ "${GIT_REPO}"
fi

# Read all the versions to be fingerprinted.
readarray -t ALL_VERSIONS < "${SCRIPT_PATH}/versions.txt"

# Update for all the versions listed in versions.txt file.
for app_version in "${ALL_VERSIONS[@]}"; do
  echo "Fingerprinting Adminer version ${app_version} ..."
  docker run --rm -d --name adminer_${app_version} -p 8080:8080 adminer:${app_version}

  # Start docker container
  echo "Waiting for Adminer ${app_version} to be ready ..."

  until [[ $(docker ps -q -f name=adminer_${app_version}) ]]
  do
    echo -n "."
    sleep 5
  done

  # Checkout the repository to the correct tag.
  checkOutRepo "${GIT_REPO}" "v${app_version}"

  updateFingerprint \
    "adminer" \
    "${app_version}" \
    "${FINGERPRINTS_PATH}" \
    "${GIT_REPO}" \
    "http://localhost:8080"

  # Stop the live instance
  docker stop adminer_${app_version}

done

convertFingerprint "${JSON_DATA}" "${BIN_DATA}"

echo "Fingerprint updated for Adminer. Please commit the following file:"
echo "  ${BIN_DATA}"
echo "to"
echo "  ${BINPROTO}"
