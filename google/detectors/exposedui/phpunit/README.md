# PHPUnit Exposed Vulnerable eval-stdin.php Detector

This detector checks for [CVE-2017-9841](https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2017-9841) RCE vulnerability in PHPUnit. For vulnerable versions of phpunit, its eval-stdin.php script allows RCE via a POST request payload.

## Build jar file for this plugin

Using `gradlew`:

```shell
./gradlew jar
```

Tsunami identifiable jar file is located at `build/libs` directory.

## Exported config values

Config properties prefix: `plugins.google.detector.exposed_ui.phpunit`.

Config values:

*   `mode`: specifies the run mode for this plugin. When set to `DEFAULT` or unset, it scans for the exact path reported in cve-2017-9841. When set to `CUSTOM`, it scans all the paths from the `script_paths_file` field. When set to `FULL`, it scans for all the paths defined in data/phpunit_path_list.txt which is a modified copy of [bruteforce-lists/phpunit.txt](https://github.com/random-robbie/bruteforce-lists/blob/master/phpunit.txt).
*   `script_paths_file`: specifies the path to the file that contains a list of possible paths to eval-stdin.php, newline separated.

Example YAML config for the CUSTOM mode:

```yaml
plugins:
  google:
    detector:
      exposed_ui:
        phpunit:
          mode: "CUSTOM"
          script_paths_file: "/home/foo/path_list.txt"
```
Example YAML config for the FULL mode:
```yaml
plugins:
  google:
    detector:
      exposed_ui:
        phpunit:
          mode: "FULL"
```
