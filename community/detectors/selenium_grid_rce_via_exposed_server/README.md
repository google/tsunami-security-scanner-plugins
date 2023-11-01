# Selenium Grid - Remote Code Execution via Chrome webdriver

This plugin detects RCE in an exposed Selenium Grid service via Chrome webdriver.

It makes use --renderer-cmd-prefix parameter of Chrome browser to execute a command.

The command provided within this parameter is added before the path to Chrome 
binary and its parameters when a new Chrome instance is launched. 
Because of this, some commands may not execute properly when the Chrome path/parameters 
are appended to the injected command. 
The plugin uses curl command with '--' at the end, to make curl treat the remaining 
parameters as URLs/hostnames rather than parameters to prevent curl exiting with errors.


This plugin uses two methods to confirm that an injected command has executed:

1. If available, it uses  [Tsunami Callback Server](https://github.com/google/tsunami-security-scanner-callback-server),
which helps further validate findings. It executes a payload similar to:

`curl CALLBACK_URL -- `


2. If the callback server is disabled. The plugin creates a test file on the target
by using --trace option with a uniq test string provided as a hostname such as:

`curl --trace /tmp/tsunami-selenium-rce tsunami-selenium-rce-3fd7b7962a51eee2 --`

Curl will fail to resolve the hostname and write it into the trace log similar to:

```
== Info: Closing connection 23
== Info: Could not resolve host: tsunami-selenium-rce-3fd7b7962a51eee2
== Info: Closing connection 0
```

The RCE test file is then read by requesting the file with browser file:/// schema such as:

`file:///tmp/tsunami-selenium-rce`

The file is then checked for the previously injected detection string, e.g.:

`tsunami-selenium-rce-3fd7b7962a51eee2`

to determine if the curl --trace command executed.

## References

[Chrome command line switches](https://peter.sh/experiments/chromium-command-line-switches/)
[Tsunami Callback Server](https://github.com/google/tsunami-security-scanner-callback-server)


## Build jar file for this plugin

Using `gradlew`:

```shell
./gradlew jar
```

Tsunami identifiable jar file is located at `build/libs` directory.
