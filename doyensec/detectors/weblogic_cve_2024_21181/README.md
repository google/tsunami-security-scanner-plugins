# Weblogic T3/IIOP Deserialization (CVE-2024-21181)

## Description

CVE-2024-21181 is a critical vulnerability in Oracle WebLogic Server. The vulnerability lies in the way it
handles T3/IIOP requests. When performing the lookup for a Reference object the unsafe deserialization is triggered.

### Detector's implementation

This detector only exploits the deserialization vulnerability to perform a simple DNS callback. 
Even though this doesn't leak any sensitive data, it hints that a more complex gadget chain is possible.
Implementing a gadget-chain that leverages the deserialization vulnerability to achieve a complete RCE
it's outside the scope of the scanner.

**The detector needs the Tsunami Callback Server with the DNS mode enabled.**

## Affected Versions

-  v12.2.1.4.0
-  v14.1.1.0.0

## Build the plugin

### Oracle Library

The plugin needs the `wlclient.jar` library from Oracle WebLogic to communicate with the Oracle WebLogic server, but since it's proprietary software we can't include it in the repo.

However, the library can be recovered from a WebLogic v12.2.1.40 installation, here's a guide that uses the WebLogic Docker image to do so:
1. Create an Oracle account if you don't have one
2. Log into the Oracle Container Registry website: https://container-registry.oracle.com/
3. Click on your username on the top right of the page and click on "Auth Token"
4. Click on Generate Secret Key and copy the generated key
5. Run the following command and login using your email as the username and the generated key as the password:
```sh
docker login container-registry.oracle.com
```
6. Extract the library from the image:
```sh
# Pull the image
docker pull container-registry.oracle.com/middleware/weblogic:12.2.1.4

# Create a temporary container
docker create --name weblogic-temp image-name

# Pull the library
docker cp weblogic-temp:/u01/oracle/wlserver/server/lib/wlclient.jar .

# Remove the container
docker rm weblogic-temp
```
7. Put the library in the `libs/` folder

### Build 

```shell
./gradlew shadowJar
```

This will create a "fat-jar" which includes the contents of `wlclient.jar`, needed for the detector to work.

The Tsunami identifiable jar file is located in the `build/libs` directory, the shadow JAR will have a `-all` suffix before the extension.

## Notes
### T3 Protocol
This detector uses the IIOP protocol to trigger the deserialization bug. It should theoretically be possible to use the T3 protocol, but during testing we found that using T3 seem to actually trigger the bug on the client side – i.e. on our own detector – instead that on the server.

### Internal IPs Issues
It seems that the detector fails to connect to the server and the connection hangs in some situations, specifically when the WebLogic server has an internal IP that is not directly accessible from the detector – for example if the server is behind a NAT or in an EC2 instance where the interface address is not the same as the instance public IPv4 – and the server doesn't have its public IP specified in the WebLogic configuration.

This happens because, after the initial connection, the server will send its local IP (instead of the public one) to the client, and the client will try and establish a new connection to this IP, even though the initial connection worked fine. We could not find any clear way to work around this issue.