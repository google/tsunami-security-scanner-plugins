# Jenkins CLI Deserialization RCE Detector

This detector checks for Jenkins services with a remoting-based CLI endpoint,
which allows remote code execution by transferring a malicious serialized Java
SignedObject object. See https://ssd-disclosure.com/ssd-advisory-cloudbees-jenkins-unauthenticated-code-execution/
for a detailed description.

## Build jar file for this plugin

Using `gradlew`:

```shell
./gradlew jar
```

Tsunami identifiable jar file is located at `build/libs` directory.

## Build payloads

This detector includes two payloads by default: one to append a specific string
to `$JENKINS_HOME/war/robots.txt` and one to remove the appended string. The
payloads can be built using instructions from https://github.com/vulhub/CVE-2017-1000353.

The payloads contain the following commands:

*  append.ser: `printf "\n# 790j6UFi7ClZyPlMAa9g" >> $JENKINS_HOME/war/robots.txt`
*  remove.ser: `sed -i '$ d' $JENKINS_HOME/war/robots.txt` (removes the last line of robots.txt)

which are base64-encoded to these commands before being encoded to the payload:

*  `bash -c {echo,cHJpbnRmICJcbiMgNzkwajZVRmk3Q2xaeVBsTUFhOWciID4+ICRKRU5LSU5TX0hPTUUvd2FyL3JvYm90cy50eHQ=}|{base64,-d}|{bash,-i}`
*  `bash -c {echo,c2VkIC1pICckIGQnICRKRU5LSU5TX0hPTUUvd2FyL3JvYm90cy50eHQ=}|{base64,-d}|{bash,-i}`
