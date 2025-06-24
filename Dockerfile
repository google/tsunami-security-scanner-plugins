# Stage 1: Build phase

FROM ubuntu:latest AS build

ARG TSUNAMI_PLUGIN_BOOTSTRAP
ARG TSUNAMI_PLUGIN_FOLDER

## Dependencies
RUN apt-get update \
 && apt-get install -y --no-install-recommends ca-certificates wget unzip openjdk-21-jdk \
 && rm -rf /var/lib/apt/lists/* \
 && rm -rf /usr/share/doc && rm -rf /usr/share/man \
 && apt-get clean

## Install a specific version of protoc for the templated plugins
WORKDIR /usr/tsunami/deps
RUN mkdir /usr/tsunami/deps/protoc \
    && wget https://github.com/protocolbuffers/protobuf/releases/download/v25.5/protoc-25.5-linux-x86_64.zip -O /usr/tsunami/deps/protoc.zip \
    && unzip /usr/tsunami/deps/protoc.zip -d /usr/tsunami/deps/protoc/
ENV PATH="${PATH}:/usr/tsunami/deps/protoc/bin"

## Compile the plugins
WORKDIR /usr/repos/tsunami-security-scanner-plugins
COPY . /usr/repos/tsunami-security-scanner-plugins/

WORKDIR /usr/repos/tsunami-security-scanner-plugins/${TSUNAMI_PLUGIN_FOLDER}
RUN mkdir /usr/tsunami/plugins \
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
