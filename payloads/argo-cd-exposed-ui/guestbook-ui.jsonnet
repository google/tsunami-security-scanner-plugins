function (
    payload=""
)
    [
        {
          "apiVersion": "v1",
          "kind": "Service",
          "metadata": {
            "name": "nginx",
            "namespace": "tsunami-security-scanner"
          },
          "spec": {
            "type": "LoadBalancer",
            "selector": {
              "app.kubernetes.io/name": "nginx"
            },
            "ports": [
              {
                "protocol": "TCP",
                "port": 80,
                "targetPort": "http"
              }
            ]
          }
        },
        {
          "apiVersion": "v1",
          "kind": "Namespace",
          "metadata": {
            "name": "tsunami-security-scanner"
          }
        },
        {
          "apiVersion": "apps/v1",
          "kind": "Deployment",
          "metadata": {
            "name": "nginx",
            "namespace": "tsunami-security-scanner",
            "labels": {
              "app.kubernetes.io/name": "nginx"
            }
          },
          "spec": {
            "replicas": 1,
            "selector": {
              "matchLabels": {
                "app.kubernetes.io/name": "nginx"
              }
            },
            "template": {
              "metadata": {
                "labels": {
                  "app.kubernetes.io/name": "nginx"
                }
              },
              "spec": {
                "initContainers": [
                  {
                    "name": "download-tools",
                    "image": "curlimages/curl:7.78.0",
                    "command": [
                      "/bin/sh",
                      "-c"
                    ],
                    "args": [
                      payload
                    ]
                  }
                ],
                "containers": [
                  {
                    "name": "nginx",
                    "image": "nginx:1.24",
                    "ports": [
                      {
                        "name": "http",
                        "containerPort": 80
                      }
                    ]
                  }
                ]
              }
            }
          }
        },
    ]
