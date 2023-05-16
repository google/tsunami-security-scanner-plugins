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
TMP_DATA="/tmp/drupal_fingerprints"
# Path to the local git repository for adminer codebase.
GIT_REPO="${TMP_DATA}/repo"
# Path to the directory of all the updated fingerprints data.
FINGERPRINTS_PATH="${TMP_DATA}/fingerprints"
# Json data of the final result.
JSON_DATA="${FINGERPRINTS_PATH}/fingerprint.json"
# Binary proto data of the final result.
BIN_DATA="${FINGERPRINTS_PATH}/fingerprint.binproto"

mkdir -p "${FINGERPRINTS_PATH}"

BINPROTO="${PROJECT_ROOT}/src/main/resources/fingerprinters/web/data/google/drupal.binproto"

# Convert the existing data file to a human-readable json file.
convertFingerprint "${BINPROTO}"  "${JSON_DATA}"

# Fetch Drupal codebase.
if [[ ! -d "${GIT_REPO}" ]] ; then
  git clone https://git.drupalcode.org/project/drupal.git "${GIT_REPO}"
fi

# Read all the versions to be fingerprinted.
readarray -t ALL_VERSIONS < "${SCRIPT_PATH}/versions.txt"

app_files="sites/default/files"
app_db=".sqlite"
# Update for all the versions listed in versions.txt file.
for app_version in "${ALL_VERSIONS[@]}"; do
  echo "Fingerprinting Drupal version ${app_version} ..."
  docker run --rm -d --name drupal_${app_version} -p 8080:80 drupal:${app_version}
  if [[ $app_version == 7* ]];
  then
    docker exec -it drupal_${app_version} /bin/bash -c \
      "curl -sS https://getcomposer.org/installer | php
      mv composer.phar /usr/bin/composer
      COMPOSER_MEMORY_LIMIT=-1 composer require drush/drush:8.*
      vendor/drush/drush/drush site-install standard --db-url=sqlite://$app_files/$app_db -y
      chown www-data:www-data $app_files $app_files/$app_db"
  else
    docker exec -it drupal_${app_version} /bin/bash -c \
      "cd web
      php core/scripts/drupal install standard
      chown www-data:www-data $app_files $app_files/$app_db"
  fi

# Checkout the repository to the correct tag.
  checkOutRepo "${GIT_REPO}" "${app_version}"

  updateFingerprint \
    "drupal" \
    "${app_version}" \
    "${FINGERPRINTS_PATH}" \
    "${GIT_REPO}" \
    "http://localhost:8080"

  # Stop the live instance
  docker stop drupal_${app_version}
done

convertFingerprint "${JSON_DATA}" "${BIN_DATA}"

echo "Fingerprint updated for Drupal. Please commit the following file:"
echo "  ${BIN_DATA}"
echo "to"
echo "  ${BINPROTO}"
