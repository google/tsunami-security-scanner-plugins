# Web Service Fingerprinter

This plugin tries to identify the name and version of the web application
running behind a web service.

# Supported Web Applications

Application                                                                                  | Fingerprint File                                                                                                                                                                                   | Supported Version Ranges
-------------------------------------------------------------------------------------------- | -------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- | ------------------------
[Adminer](https://www.adminer.org/)                                                          | [adminer.binproto](https://github.com/google/tsunami-security-scanner-plugins/blob/master/google/fingerprinters/web/src/main/resources/fingerprinters/web/data/adminer.binproto)                   | 4.2.5 - 4.7.8
[Apache Zeppelin](https://zeppelin.apache.org/)                                              | [apache_zeppelin.binproto](https://github.com/google/tsunami-security-scanner-plugins/blob/master/google/fingerprinters/web/src/main/resources/fingerprinters/web/data/apache_zeppelin.binproto)   | 0.7.2 - 0.9.0
[Argo Workflows](https://argoproj.github.io/projects/argo)                                   | [argo-workflows.binproto](https://github.com/google/tsunami-security-scanner-plugins/blob/master/google/fingerprinters/web/src/main/resources/fingerprinters/web/data/argo-workflows.binproto)     | 2.6.0 - 2.11.8
[Drupal](https://www.drupal.org/)                                                            | [drupal.binproto](https://github.com/google/tsunami-security-scanner-plugins/blob/master/google/fingerprinters/web/src/main/resources/fingerprinters/web/data/drupal.binproto)                     | 7.36 - 9.0.6
[Gitlab](https://gitlab.com/gitlab-org/gitlab)                                               | [gitlab.binproto](https://github.com/google/tsunami-security-scanner-plugins/blob/master/google/fingerprinters/web/src/main/resources/fingerprinters/web/data/gitlab.binproto)                     | 10.0.0 - 13.4.1
[GoCD](https://www.gocd.org/)                                                                | [gocd.binproto](https://github.com/google/tsunami-security-scanner-plugins/blob/master/google/fingerprinters/web/src/main/resources/fingerprinters/web/data/gocd.binproto)                         | 17.3.0 - 21.1.0
[Grafana](https://grafana.com/)                                                              | [grafana.binproto](https://github.com/google/tsunami-security-scanner-plugins/blob/master/google/fingerprinters/web/src/main/resources/fingerprinters/web/data/grafana.binproto)                   | 5.0.0 - 7.3.4
[GravCMS](https://getgrav.org/)                                                              | [gravcms.binproto](https://github.com/google/tsunami-security-scanner-plugins/blob/master/google/fingerprinters/web/src/main/resources/fingerprinters/web/data/gravcms.binproto)                   | 1.2.0 - 1.7.5
[Hadoop Yarn](https://hadoop.apache.org/docs/current/hadoop-yarn/hadoop-yarn-site/YARN.html) | [hadoop_yarn.binproto](https://github.com/google/tsunami-security-scanner-plugins/blob/master/google/fingerprinters/web/src/main/resources/fingerprinters/web/data/hadoop_yarn.binproto)           | 2.0.0 - 3.3.0
[Jenkins](https://www.jenkins.io/)                                                           | [jenkins.binproto](https://github.com/google/tsunami-security-scanner-plugins/blob/master/google/fingerprinters/web/src/main/resources/fingerprinters/web/data/jenkins.binproto)                   | 1.359 - 2.251
[Joomla](https://www.joomla.org/)                                                            | [joomla.binproto](https://github.com/google/tsunami-security-scanner-plugins/blob/master/google/fingerprinters/web/src/main/resources/fingerprinters/web/data/joomla.binproto)                     | 3.4.3 - 3.9.21
[Jupyter Notebook](https://jupyter.org/)                                                     | [jupyter_notebook.binproto](https://github.com/google/tsunami-security-scanner-plugins/blob/master/google/fingerprinters/web/src/main/resources/fingerprinters/web/data/jupyter_notebook.binproto) | 4.0.0 - 6.1.4
[Kiali](https://kiali.io/)                                                                   | [kiali.binproto](https://github.com/google/tsunami-security-scanner-plugins/blob/master/google/fingerprinters/web/src/main/resources/fingerprinters/web/data/kiali.binproto)                       | 0.18.0 - 1.26.1
[Locust](https://locust.io/)                                                                 | [locust.binproto](https://github.com/google/tsunami-security-scanner-plugins/blob/master/google/fingerprinters/web/src/main/resources/fingerprinters/web/data/locust.binproto)                     | 0.12.1 - 1.4.1
[Magento](https://magento.com/)                                                              | [magento.binproto](https://github.com/google/tsunami-security-scanner-plugins/blob/master/google/fingerprinters/web/src/main/resources/fingerprinters/web/data/magento.binproto)                   | 2.0.0 - 2.3.5
[MantisBT](https://www.mantisbt.org/)                                                        | [mantisbt.binproto](https://github.com/google/tsunami-security-scanner-plugins/blob/master/google/fingerprinters/web/src/main/resources/fingerprinters/web/data/mantisbt.binproto)                 | 1.0.0 - 2.24.3
[Moodle](https://moodle.org/)                                                                | [moodle.binproto](https://github.com/google/tsunami-security-scanner-plugins/blob/master/google/fingerprinters/web/src/main/resources/fingerprinters/web/data/moodle.binproto)                     | 3.0.0 - 3.9.2
[OpenCart](https://www.opencart.com/)                                                        | [opencart.binproto](https://github.com/google/tsunami-security-scanner-plugins/blob/master/google/fingerprinters/web/src/main/resources/fingerprinters/web/data/opencart.binproto)                 | 1.5.5.1 - 3.0.3.6
[phpMyAdmin](https://www.phpmyadmin.net/)                                                    | [php_my_admin.binproto](https://github.com/google/tsunami-security-scanner-plugins/blob/master/google/fingerprinters/web/src/main/resources/fingerprinters/web/data/php_my_admin.binproto)         | 4.5.3.1 - 5.0.4
[Polynote](https://polynote.org/)                                                            | [polynote.binproto](https://github.com/google/tsunami-security-scanner-plugins/blob/master/google/fingerprinters/web/src/main/resources/fingerprinters/web/data/polynote.binproto)                 | 0.2.11 - 0.3.12
[Redmine](https://www.redmine.org/)                                                          | [redmine.binproto](https://github.com/google/tsunami-security-scanner-plugins/blob/master/google/fingerprinters/web/src/main/resources/fingerprinters/web/data/redmine.binproto)                   | 3.0.0 - 4.1.1
[WordPress](https://wordpress.com/)                                                          | [wordpress.binproto](https://github.com/google/tsunami-security-scanner-plugins/blob/master/google/fingerprinters/web/src/main/resources/fingerprinters/web/data/wordpress.binproto)               | 1.2 - 5.5
[Zabbix](https://www.zabbix.com/)                                                            | [zabbix.binproto](https://github.com/google/tsunami-security-scanner-plugins/blob/master/google/fingerprinters/web/src/main/resources/fingerprinters/web/data/community/zabbix.binproto).          | 4.0.0 - 6.4.0

# How to Contribute

Add **updater script** for fingerprints to https://github.com/google/tsunami-security-scanner-plugins/tree/master/google/fingerprinters/web/scripts/updater/community.

Add **generated fingerprint binary proto** to https://github.com/google/tsunami-security-scanner-plugins/tree/master/google/fingerprinters/web/src/main/resources/fingerprinters/web/data/community

# How to Collect Fingerprints for a Web Application

1.  Create parameterized docker compose file to turn up different versions of
    the web application

    [WordPress Example](https://github.com/google/tsunami-security-scanner-plugins/blob/master/google/fingerprinters/web/scripts/updater/google/wordpress/app/docker-compose.yaml#L16)

1.  Locate the open source repo of the web application

    For instance, wordpress is located at
    https://github.com/WordPress/WordPress, and a list of wordpress versions can
    be extracted based on its git
    [**Tags**](https://git-scm.com/book/en/v2/Git-Basics-Tagging).

    Furthermore, note down where the static/public resources are located in the
    repository. It could be the top level directory like
    `https://github.com/WordPress/WordPress`, or a UI/frontend specific
    directory like `https://github.com/zabbix/zabbix/tree/4.0.0/frontends/php`.
    The
    [updater tool](https://github.com/google/tsunami-security-scanner-plugins/blob/master/google/fingerprinters/web/src/main/java/com/google/tsunami/plugins/fingerprinters/web/tools/FingerprintUpdater.java)
    would try query potential static files identified in the specified repo
    direction against the live instance of the application you spin up locally.

1.  Initialize/Seed the fingerprint file

    Using Zabbix as an example:

    ```
    # Change into the fingerprinter directory
    cd google/fingerprinters/web/

    # Run the fingerprinter to create a new fingerprint file
    ./gradlew :runFingerprintUpdater --args="\
    --software-name=zabbix \
    --fingerprint-data-path=/tmp/zabbix_fingerprints/fingerprints/fingerprint.json \
    --local-repo-path=/tmp/zabbix_fingerprints/repo/frontends/php \
    --remote-url=http://localhost:280 \
    --version=4.0.0 \
    --init"

    # Create a binproto file from your newly generated fingerprint.json file
    source common.sh
    convertFingerprint /tmp/zabbix_fingerprints/fingerprints/fingerprint.json /tmp/zabbix_fingerprints/fingerprints/fingerprint.binproto
    # Move your binproto file into the same directory as specified in your update.sh BIN_DATA directory
    mv /tmp/zabbix_fingerprints/fingerprints/fingerprint.binproto ./google/fingerprinters/web/src/main/resources/fingerprinters/web/data/google/zabbix.binproto
    ```

    `--local-repo-path` is the location where you git clone the application git
    repo; `--remote-url` points to the live instance of the application you are
    running locally; `--init` initializes the
    `/tmp/zabbix_fingerprints/fingerprints/fingerprint.json`.

1.  Create the fingerprint generation script

    Existing examples:

    *   [WordPress updater script](https://github.com/google/tsunami-security-scanner-plugins/blob/master/google/fingerprinters/web/scripts/updater/google/wordpress/update.sh)
    *   [Zabbix updater script](https://github.com/google/tsunami-security-scanner-plugins/blob/master/google/fingerprinters/web/scripts/updater/community/zabbix/update.sh)

    Note:
    [updater/common.sh](https://github.com/google/tsunami-security-scanner-plugins/blob/master/google/fingerprinters/web/scripts/updater/common.sh)
    contains a lot of utils you can reuse in your updater script.

1.  Validate the correctness of the fingerprints

    Once the generated \<software\>.binproto is added to
    https://github.com/google/tsunami-security-scanner-plugins/tree/master/google/fingerprinters/web/src/main/resources/fingerprinters/web/data/community
    you can run Tsunami scanner locally against the application, the scanner
    should report correct software name as well as the version or set of
    versions. For example:

    ```
    INFO: WebServiceFingerprinter discovered 1 potential applications for 'http://127.0.0.1:18080/': [zabbix].
    Mar 27, 2023 8:43:43 PM com.google.tsunami.plugins.fingerprinters.web.detection.VersionDetector detectVersions
    INFO: Possible versions for software zabbix from file hashes are: [4.0.21, 4.0.22, 4.0.24, 4.0.25, 4.0.26, 4.0.27]
    Mar 27, 2023 8:43:43 PM com.google.tsunami.plugins.fingerprinters.web.detection.VersionDetector detectVersions
    INFO: Possible versions for software zabbix after file path sifting: [4.0.21, 4.0.22, 4.0.24, 4.0.25, 4.0.26, 4.0.27]
    ```

## Common Issues

1. [Docker] ERROR: could not find an available, non-overlapping IPv4 address pool among the defaults to assign to the network.

  `docker network prune`

2. [Docker] Stop all the running docker containers and remove them permanently.

  `docker stop $(docker ps -q); docker rm $(docker ps --filter status=exited -q);`

3. [[FingerprintUpdater.java](https://github.com/google/tsunami-security-scanner-plugins/blob/master/google/fingerprinters/web/src/main/java/com/google/tsunami/plugins/fingerprinters/web/tools/FingerprintUpdater.java)] Reports `No new fingerprints found` and exits with error.

  Check if the application is running at the expected `--remote-url`. This error could be triggered if there's no service running at the expected url.
