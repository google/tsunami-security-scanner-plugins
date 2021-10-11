# Apache AirFlow CVE_2021_38540 Vulnerability Detector

apache-airflow is a platform to programmatically author, schedule, and monitor workflows.
Affected versions of this package are vulnerable to Improper Authentication due to 
missing authentication in the variable import endpoint. 
This allowed unauthenticated users to add/modify Airflow variables used in DAGs,
potentially resulting in a denial of service, information disclosure or remote code execution.

The plugin is used to detect the above mentioned vulnerability.

## Build jar file for this plugin

Using `gradlew`:

```shell
./gradlew jar
```

Tsunami identifiable jar file is located at `build/libs` directory.


## Python Dependency 

This plugin does'nt include python binary, In order to run this plugin, Please
add below lines in the **Tsunami Scanner** Dockerfile.


```shell

#Build Community Plugins 

WORKDIR /usr/tsunami/repos/tsunami-security-scanner-plugins/community
RUN chmod +x build_all.sh \
    && ./build_all.sh

RUN cp build/plugins/*.jar /usr/tsunami/plugins
RUN cp -a build/python/. /usr/tsunami/python 2>/dev/null || :

# Compile the Tsunami scanner
...

RUN apt-get install python3 python3-pip
RUN pip3 install requests

```

## Vulnerability Detected with Tsunami Scanner

![Output](https://i.imgur.com/j3vUWjC.png)