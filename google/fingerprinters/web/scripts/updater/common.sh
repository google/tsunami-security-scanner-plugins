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

# Absolute path to this common.sh file. This file is supposed to used by sourcing.
SCRIPT_PATH="$(cd -- "$(dirname "$BASH_SOURCE")" >/dev/null 2>&1 ; pwd -P)"
# Root path to the web fingerprinter plugin.
PROJECT_ROOT="$(cd -- "${SCRIPT_PATH}/../.." >/dev/null 2>&1 ; pwd -P)"

convertFingerprint() {
  local input="$1"
  local output="$2"

  args=(
    --input="${input}"
    --output="${output}"
  )

  pushd "${PROJECT_ROOT}" >/dev/null
    ./gradlew :runFingerprintFileConverter --args="${args[*]}"
  popd >/dev/null
}

checkOutRepo() {
  local repo="$1"
  local tag="$2"
  pushd "${repo}" >/dev/null
    git checkout "${tag}"
  popd >/dev/null
}

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
  )

  pushd "${PROJECT_ROOT}" >/dev/null
    ./gradlew :runFingerprintUpdater --args="${args[*]}"
  popd >/dev/null

  if grep -Fq "\"${app_version}\"" "${fingerprint_versioned_output}"; then
    echo "Fingerprint updated successfully"
    cp "${fingerprint_versioned_output}" "${fingerprint_input}"
  else
    echo "fingerprint updating failed"
    exit 1
  fi
}
