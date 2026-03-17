# Stage 1: Build phase

FROM ghcr.io/google/tsunami-scanner-devel:latest AS build

ARG TSUNAMI_PLUGIN_FOLDER

ENV GITREPO_TSUNAMI_CORE="https://github.com/google/tsunami-security-scanner.git"
ENV GITBRANCH_TSUNAMI_CORE="stable"

ENV GITREPO_TSUNAMI_TCS="https://github.com/google/tsunami-security-scanner-callback-server.git"
ENV GITBRANCH_TSUNAMI_TCS="stable"

## Compile the plugins
WORKDIR /usr/repos/plugins
COPY ${TSUNAMI_PLUGIN_FOLDER} /usr/repos/plugins/${TSUNAMI_PLUGIN_FOLDER}
RUN mkdir -p /usr/tsunami/plugins

## Note: There can be two situations here:
##
##    - Either we are directly building one plugin, in this case it will have
##      a build.gradle file that we can use to build.
##
##    - Or we are building a group of plugins, in that case there will be no
##      build.gradle file at the root. We then generate a composite build.gradle
##      so that we can optimize the build.
WORKDIR /usr/repos/plugins/${TSUNAMI_PLUGIN_FOLDER}
RUN bash <<EOF
set -eu

### if there is no build.gradle at the root, we create a composite one.
if [[ ! -f build.gradle ]]; then
  echo "No build.gradle file found, creating a composite one."
  for plugins in \$(find . -name 'build.gradle'); do
    echo "includeBuild \"\$(dirname \${plugins})\"" >> settings.gradle
  done

  ### The default available memory is not enough to build all plugins. Because
  ### each plugin is independant, we can also make the best use of parallelism.
  echo "org.gradle.parallel=true" >> gradle.properties
  echo "org.gradle.caching=true" >> gradle.properties
  echo "org.gradle.jvmargs=-Xmx1024m" >> gradle.properties

  echo "task build { dependsOn gradle.includedBuilds*.task(':build') }" > build.gradle
fi
EOF

RUN gradle build
RUN find . -type f \( -name '*.jar' -a ! -path './.gradle/**' \) -exec cp {} /usr/tsunami/plugins/ \;

# Stage 2: Release
#
# IMPORTANT NOTE: These images cannot be used as is. They are expected to be
# used as a layer to compose the final Tsunami image.
#
FROM scratch AS release

## Copy the plugins
COPY --from=build /usr/tsunami/plugins /usr/tsunami/plugins
