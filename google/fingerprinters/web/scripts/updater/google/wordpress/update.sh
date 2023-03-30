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
# Path to the configurations for starting a live instance of WordPress.
WP_APP_PATH="${SCRIPT_PATH}/app"
# Path to the temporary data holder.
TMP_DATA="/tmp/wp_fingerprints"
# Path to the local git repository for WordPress codebase.
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

startWordPress() {
  local version="$1"
  pushd "${WP_APP_PATH}" >/dev/null
    WP_VERSION="${version}" docker-compose up -d
  popd >/dev/null
}

stopWordPress() {
  local version="$1"
  pushd "${WP_APP_PATH}" >/dev/null
    WP_VERSION="${version}" docker-compose down --volumes --remove-orphans
  popd >/dev/null
}

# Convert the existing data file to a human-readable json file.
convertFingerprint \
  "${PROJECT_ROOT}/src/main/resources/fingerprinters/web/data/google/wordpress.binproto" \
  "${JSON_DATA}"

# Fetch WordPress codebase.
if [[ ! -d "${GIT_REPO}" ]] ; then
  git clone https://github.com/WordPress/WordPress.git "${GIT_REPO}"
fi

# Update for all the versions listed in versions.txt file.
for wp_version in "${ALL_VERSIONS[@]}"; do
  echo "Fingerprinting WordPress version ${wp_version} ..."
  # Start a live instance of WordPress.
  startWordPress "${wp_version}"
  # Arbitrarily chosen so that WordPress is up and running.
  echo "Waiting for WordPress ${wp_version} to be ready ..."
  sleep 30
  # Finish the WordPress installation process.
  curl \
    -X POST \
    -H "Content-Type: application/x-www-form-urlencoded" \
    -d "weblog_title=test&user_name=test&admin_password=test&pass1-text=test&admin_password2=test&pw_weak=on&admin_email=test@test.com&blog_public=0&Submit=Install Wordpress" \
    'http://localhost:8080/wp-admin/install.php?step=2'

  # Checkout the repository to the correct tag.
  checkOutRepo "${GIT_REPO}" "${wp_version}"

  updateFingerprint \
    "wordpress" \
    "${wp_version}" \
    "${FINGERPRINTS_PATH}" \
    "${GIT_REPO}" \
    "http://localhost:8080"

  # Stop the live instance of WordPress.
  stopWordPress "${wp_version}"
done

convertFingerprint "${JSON_DATA}" "${BIN_DATA}"

echo "Fingerprint updated for WordPress. Please commit the following file:"
echo "  ${BIN_DATA}"
