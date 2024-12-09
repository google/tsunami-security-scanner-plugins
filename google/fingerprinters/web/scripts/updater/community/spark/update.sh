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
# Path to the configurations for starting a live instance of Spark.
SPARK_APP_PATH="${SCRIPT_PATH}/app"
# Path to the temporary data holder.
TMP_DATA="/tmp/SPARK_fingerprints"
# Path to the local git repository for Spark codebase.
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

startSpark() {
  local version="$1"
  pushd "${SPARK_APP_PATH}" >/dev/null
    # if version-python3 exists then we have a spark container with python3
    # otherwise we must install python3
    $(SPARK_VERSION="${version}-python3" docker compose up -d &&
        sleep 10) || \
      (
        echo -e "\nInstalling python3 into worker container"
        SPARK_VERSION="${version}" docker compose up -d
        sleep 10
        installPython3InSpark "${version}"
      )
  popd >/dev/null
}

installPython3InSpark() {
  local version="$1"
  pushd "${SPARK_APP_PATH}" >/dev/null
    docker exec  -it -u 0 spark-master apt update >/dev/null
    docker exec  -it -u 0 spark-master apt install python3 python3-pip -y >/dev/null
    docker exec  -it -u 0 spark-master pip3 install pyspark=="${version}" >/dev/null
  popd >/dev/null
}

stopSpark() {
  local version="$1"
  pushd "${SPARK_APP_PATH}" >/dev/null
    SPARK_VERSION="${version}" docker compose down --volumes --remove-orphans
    # or stop the python3 contained version
    SPARK_VERSION="${version}-python3" docker compose down --volumes --remove-orphans
  popd >/dev/null
}

createFingerprintForWebUI() {
  local spark_version="$1"

  echo "Fingerprinting Spark version ${spark_version} ..."
  # Start a live instance of Spark.
  startSpark "${spark_version}"

  # Checkout the repository to the correct tag.
  if [[ ${spark_version:0:1} == "v" ]]; then
    checkOutRepo "${GIT_REPO}" "${spark_version}"
  else
    checkOutRepo "${GIT_REPO}" "v${spark_version}"
  fi

  # Fingerprint of Master UI
  updateFingerprint \
    "spark" \
    "${spark_version}" \
    "${FINGERPRINTS_PATH}" \
    "${GIT_REPO}/core/src/main/resources/org/apache/spark/ui/static" \
    "http://localhost:8080/"

  # Fingerprint of Worker UI
  updateFingerprint \
    "spark" \
    "${spark_version}" \
    "${FINGERPRINTS_PATH}" \
    "${GIT_REPO}/core/src/main/resources/org/apache/spark/ui/static" \
    "http://localhost:8081/"

  docker exec -d spark-master /opt/spark/bin/spark-submit --master spark://spark-master:7077 /opt/spark/examples/src/main/python/fib.py
  sleep 10

  # Fingerprint of Web Interface
  updateFingerprint \
    "spark" \
    "${spark_version}" \
    "${FINGERPRINTS_PATH}" \
    "${GIT_REPO}/core/src/main/resources/org/apache/spark/ui/static" \
    "http://localhost:4040/"


  # Stop the live instance of Spark.
  stopSpark "${spark_version}"
}


# Convert the existing data file to a human-readable json file.
convertFingerprint \
  "${PROJECT_ROOT}/src/main/resources/fingerprinters/web/data/community/spark.binproto" \
  "${JSON_DATA}"

# Fetch Spark codebase.
if [[ ! -d "${GIT_REPO}" ]] ; then
  git clone https://github.com/apache/spark.git "${GIT_REPO}"
fi

# Update for all the versions listed in versions.txt file.
for spark_version in "${ALL_VERSIONS[@]}"; do
  createFingerprintForWebUI "${spark_version}"
done

convertFingerprint "${JSON_DATA}" "${BIN_DATA}"

echo "Fingerprint updated for Spark. Please commit the following file:"
echo "  ${BIN_DATA}"
