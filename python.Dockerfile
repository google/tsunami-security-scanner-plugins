# IMPORTANT NOTE: These images cannot be used as is. They are expected to be
# used as a layer to compose the final Tsunami image.
#
FROM scratch AS release

## Copy the plugins
WORKDIR /usr/tsunami/plugins/
COPY py_plugins /usr/tsunami/py_plugins
