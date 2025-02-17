#!/usr/bin/env bash

# Copyright 2024 Google LLC
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
# http://www.apache.org/licenses/LICENSE-2.0
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
TMP_DATA="/tmp/craftcms_fingerprints"
# Path to CraftCMS Releases files
TMP_RELEASE_FILES="${TMP_DATA}/craftcms_instance"
# Path to the local git repository for Craft CMS codebase.
GIT_REPO="${TMP_DATA}/repo"
# Path to the directory of all the updated fingerprints data.
FINGERPRINTS_PATH="${TMP_DATA}/fingerprints"
# Json data of the final result.
JSON_DATA="${FINGERPRINTS_PATH}/fingerprint.json"
# Binary proto data of the final result.
BIN_DATA="${FINGERPRINTS_PATH}/fingerprint.binproto"

mkdir -p "${FINGERPRINTS_PATH}"
mkdir -p "${TMP_RELEASE_FILES}"

BINPROTO="${PROJECT_ROOT}/src/main/resources/fingerprinters/web/data/community/craftcms.binproto"

StartCraftCMS() {
  local version="$1"
  pushd "${APP_PATH}" >/dev/null
    CRAFT_VERSION="$version" docker compose up --build --wait -d
    docker exec -it craftcms-web-1 php craft install/craft --email test@test.com --username admin --password tsunami --site-name local --site-url http://localhost:8080 --language en-us
  popd >/dev/null
}

StopCraftCMS() {
  pushd "${APP_PATH}" >/dev/null
    docker compose down --volumes --remove-orphans
  popd >/dev/null
}

CreateFingerprintForCraftCMS(){
  local version="$1"
  StartCraftCMS "$version"
  checkOutRepo "${GIT_REPO}" "${version}"
  RESOURCES_PATH="${GIT_REPO}"
  updateFingerprint \
    "craftcms" \
    "${version}" \
    "${FINGERPRINTS_PATH}" \
    "${RESOURCES_PATH}" \
    "http://localhost:8080"
  StopCraftCMS
}

# Convert the existing data file to a human-readable json file.
convertFingerprint "${BINPROTO}"  "${JSON_DATA}"

# Fetch Craftcms codebase.
if [[ ! -d "${GIT_REPO}" ]] ; then
  git clone https://github.com/craftcms/cms "${GIT_REPO}"
fi

# Read all released CraftCMS versions to be fingerprinted.
readarray -t ALL_VERSIONS < "${SCRIPT_PATH}/versions.txt"

for craftcms_version in "${ALL_VERSIONS[@]}"; do
  CreateFingerprintForCraftCMS "${craftcms_version}" "env"
done

convertFingerprint "${JSON_DATA}" "${BIN_DATA}"

echo "Fingerprint updated for Craft CMS. Please commit the following file:"
echo "  ${BIN_DATA}"
echo "to"
echo "  ${BINPROTO}"
