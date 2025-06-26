# Stage 1: Build phase

FROM ghcr.io/google/tsunami-scanner-devel:latest AS build

ARG TSUNAMI_PLUGIN_BOOTSTRAP
ARG TSUNAMI_PLUGIN_FOLDER

## Compile the plugins
WORKDIR /usr/repos/tsunami-security-scanner-plugins
COPY . /usr/repos/tsunami-security-scanner-plugins/

WORKDIR /usr/repos/tsunami-security-scanner-plugins/${TSUNAMI_PLUGIN_FOLDER}
RUN mkdir -p /usr/tsunami/plugins \
    && ${TSUNAMI_PLUGIN_BOOTSTRAP}

## Copy the built files
WORKDIR /usr/repos/tsunami-security-scanner-plugins/${TSUNAMI_PLUGIN_FOLDER}
RUN cp build/libs/*.jar /usr/tsunami/plugins

# Stage 2: Release
#
# IMPORTANT NOTE: These images cannot be used as is. They are expected to be
# used as a layer to compose the final Tsunami image.
#
FROM scratch AS release

## Copy the plugins
COPY --from=build /usr/tsunami/plugins /usr/tsunami/plugins
