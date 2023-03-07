# Redis CVE-2022-0543 Vulnerability Detector

Redis is an open source (BSD licensed), in-memory data structure store, used as a database, cache, and message broker.

Reginaldo Silva discovered that due to a packaging issue on Debian/Ubuntu, a remote attacker with the ability to execute arbitrary Lua scripts could possibly escape the Lua sandbox and execute arbitrary code on the host.

References:

- <https://www.ubercomp.com/posts/2022-01-20_redis_on_debian_rce>
- <https://bugs.debian.org/cgi-bin/bugreport.cgi?bug=1005787>

This detector connects to a remote Redis server using the [Jedis](https://github.com/redis/jedis) library and sends the payload specified in https://github.com/vulhub/vulhub/tree/master/redis/CVE-2022-0543. It also utilizes Tsunami's payload generation framework to generated the Linux shell command.

## Build jar file for this plugin

Using `gradlew`:

```shell
./gradlew jar
```

Tsunami identifiable jar file is located at `build/libs` directory.
