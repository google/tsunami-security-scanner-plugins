# Tsunami Remote Payloads

If a Tsunami plugin require payloads to be served remotely, you can add them in
this folder.

When adding a new payload, please make sure:

1. Add a dedicated folder for the payload
2. Include the source code for the binary payload for debuggability in the future.

The long-term plan is to serve these payloads on the Tsunami callback server, so
that we can do callback verification on top of triggering exploits and keep the
serving url short.
