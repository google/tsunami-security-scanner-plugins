#!/bin/bash
# Copyright 2020 Google LLC
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

set -eu

SCRIPT_PATH="$( cd "$(dirname "$0")" >/dev/null 2>&1 ; pwd -P )"
GENERATED_PLUGINS_PATH="${SCRIPT_PATH}/build/plugins"
mkdir -p "${GENERATED_PLUGINS_PATH}"

# For each Google plugin, build the jar file and copy it to build/plugins
# folder.
for plugin_dir in $(find "${SCRIPT_PATH}" -name 'gradlew' -print0 | xargs -0 -n1 dirname | sort --unique) ; do
  plugin_name="${plugin_dir##*"${SCRIPT_PATH}/"}"
  printf "\nBuilding ${plugin_name} ...\n"

  pushd "${plugin_dir}" >/dev/null

  ./gradlew build
  cp ./build/libs/*.jar "${GENERATED_PLUGINS_PATH}"

  popd >/dev/null
done

