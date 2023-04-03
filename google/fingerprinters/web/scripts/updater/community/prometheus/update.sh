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

# set -e

source ../../common.sh

SCRIPT_PATH="$(cd -- "$(dirname "$0")" >/dev/null 2>&1 ; pwd -P)"
# Root path to the web fingerprinter plugin.
PROJECT_ROOT="$(cd -- "${SCRIPT_PATH}/../../../.." >/dev/null 2>&1 ; pwd -P)"
# App name
APP="prometheus"
# docker hub image name
DOCKER_IMAGE="prom/prometheus"
# GIT repository URL
GIT_URL="https://github.com/prometheus/prometheus"
# Path to the temporary data holder.
TMP_DATA="/tmp/${APP}_fingerprints"
# Path to the local git repository.
GIT_REPO="${TMP_DATA}/repo"
# Path to the directory of all the updated fingerprints data.
FINGERPRINTS_PATH="${TMP_DATA}/fingerprints"
# Json data of the final result.
JSON_DATA="${FINGERPRINTS_PATH}/fingerprint.json"
# Binary proto data of the final result.
BIN_DATA="${FINGERPRINTS_PATH}/fingerprint.binproto"
# Binary proto path to copy the final result.
BINPROTO="${PROJECT_ROOT}/src/main/resources/fingerprinters/web/data/community/${APP}.binproto"

mkdir -p "${FINGERPRINTS_PATH}"

updateFingerprint() {
  local app_name="$1"
  local app_version="$2"
  local fingerprint_path="$3"
  local git_repo="$4"
  local remote_url="$5"

  local fingerprint_input="${fingerprint_path}/fingerprint.json"
  local fingerprint_versioned_output="${fingerprint_path}/fingerprint.${app_version}.json"

  echo "Updating fingerprint ..."
  args=(
    --software-name="${app_name}"
    --fingerprint-data-path="${fingerprint_input}"
    --local-repo-path="${git_repo}"
    --remote-url="${remote_url}"
    --version="${app_version}"
    --crawl-seed-path=/
  )

  pushd "${PROJECT_ROOT}" >/dev/null || exit
  echo ./gradlew :runFingerprintUpdater --args="${args[*]}"
    ./gradlew :runFingerprintUpdater --args="${args[*]}"
  popd >/dev/null || exit

  if grep -Fq "\"${app_version}\"" "${fingerprint_versioned_output}"; then
    echo "Fingerprint updated successfully"
    cp "${fingerprint_versioned_output}" "${fingerprint_input}"
  else
    echo "fingerprint updating failed"
    exit 1
  fi
}


startApp() {
  local version="$1"
  # Start docker container
  docker run --rm -d --name "${APP}_${version}" -p 9090:9090 "${DOCKER_IMAGE}:v${version}" || exit

  echo "Waiting for ${APP} ${version} to be ready ..."

  until [[ $(docker ps -q -f name="${APP}_${version}") ]]
  do
    echo -n "."
    sleep 5
  done

}

stopApp() {
  local version="$1"
  docker stop "${APP}_${version}" || exit
}

convertFingerprint "${BINPROTO}" "${JSON_DATA}"

# Fetch codebase
if [[ ! -d "${GIT_REPO}" ]] ; then
  git clone "${GIT_URL}" "${GIT_REPO}"
fi

cd "${GIT_REPO}" || exit

# Read all the versions to be fingerprinted.
readarray -t ALL_VERSIONS < "${SCRIPT_PATH}/versions.txt"

# Update for all the versions listed in versions.txt file.
for app_version in "${ALL_VERSIONS[@]}"; do

  echo "Fingerprinting ${APP} version ${app_version} ..."

  # Starting app
  startApp "${app_version}"

  # Checkout the repository to the correct tag.
  checkOutRepo "${GIT_REPO}" "v${app_version}"
  cd "${GIT_REPO}" || exit

  # Download buildinfo information to repo directory
  mkdir -p api/v1/status/
  curl http://localhost:9090/api/v1/status/buildinfo -o api/v1/status/buildinfo

  updateFingerprint \
    "${APP}" \
    "${app_version}" \
    "${FINGERPRINTS_PATH}" \
    "${GIT_REPO}" \
    "http://localhost:9090"

  # Stop the live instance of application.
  stopApp "${app_version}"
  
  rm -rf api

done

convertFingerprint "${JSON_DATA}" "${BIN_DATA}"

echo "Fingerprint updated for ${APP}. Please commit the following file:"
echo "  ${BIN_DATA}"
echo "to"
echo "  ${BINPROTO}"