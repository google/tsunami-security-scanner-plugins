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
  pushd "${TMP_RELEASE_FILES}" >/dev/null
    docker-compose up -d
    docker exec -it craftcms_instance_web_1 php craft install/craft --email test@test.com --username admin --password tsunami --site-name local --site-url http://localhost:8080 --language en-us
  popd >/dev/null
}

StopCraftCMS() {
  pushd "${TMP_RELEASE_FILES}" >/dev/null
    docker-compose down --volumes --remove-orphans
    rm -rf {,.[!.],..?}*
  popd >/dev/null
}

CreateFingerprintForCraftCMS(){
  local version="$1"
  local envFile="$2"
  echo https://github.com/craftcms/cms/releases/download/"${version}"/CraftCMS-"${version}".zip
  curl -L https://github.com/craftcms/cms/releases/download/"${version}"/CraftCMS-"${version}".zip --output "${TMP_RELEASE_FILES}"/CraftCMS.zip
  unzip -o "${TMP_RELEASE_FILES}"/CraftCMS.zip -d "${TMP_RELEASE_FILES}"
  cp "${APP_PATH}"/"${envFile}" "${TMP_RELEASE_FILES}"/.env
  cp "${APP_PATH}"/docker-compose.yml "${TMP_RELEASE_FILES}"/docker-compose.yml
  chown -R 82:82 "${TMP_RELEASE_FILES}"
  StartCraftCMS
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

# Read all released CraftCMS 3 versions to be fingerprinted.
readarray -t ALL_VERSIONS_3 < "${SCRIPT_PATH}/versions3.txt"

# Read all released CraftCMS 4 versions to be fingerprinted.
readarray -t ALL_VERSIONS_4 < "${SCRIPT_PATH}/versions4.txt"

# Version 3 uses different .env file format.
for craftcms_version in "${ALL_VERSIONS_3[@]}"; do
  CreateFingerprintForCraftCMS "${craftcms_version}" ".env_3"
done

# Version 4 uses different .env file format.
for craftcms_version in "${ALL_VERSIONS_4[@]}"; do
  CreateFingerprintForCraftCMS "${craftcms_version}" ".env_4"
done

convertFingerprint "${JSON_DATA}" "${BIN_DATA}"

echo "Fingerprint updated for Craft CMS. Please commit the following file:"
echo "  ${BIN_DATA}"
echo "to"
echo "  ${BINPROTO}"
