# Stage 1: Build phase

FROM ghcr.io/google/tsunami-scanner-devel:latest AS build

ARG TSUNAMI_PLUGIN_FOLDER

## Compile the plugins
WORKDIR /usr/repos/plugins
COPY ${TSUNAMI_PLUGIN_FOLDER} /usr/repos/plugins/${TSUNAMI_PLUGIN_FOLDER}
RUN mkdir -p /usr/tsunami/plugins

WORKDIR /usr/repos/plugins/
RUN bash <<EOF
set -eu
for plugins in \$(find . -name 'build.gradle'); do
  pushd \$(dirname \${plugins}) >/dev/null
  echo "Building in directory: \${PWD}"
  gradle build
  cp ./build/libs/*.jar /usr/tsunami/plugins/
  popd >/dev/null
done
EOF

# Stage 2: Release
#
# IMPORTANT NOTE: These images cannot be used as is. They are expected to be
# used as a layer to compose the final Tsunami image.
#
FROM scratch AS release

## Copy the plugins
COPY --from=build /usr/tsunami/plugins /usr/tsunami/plugins
