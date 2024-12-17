#!/bin/sh

export DOCKER_GATEWAY_IP=$(docker network inspect bridge --format '{{range .IPAM.Config}}{{.Gateway}}{{end}}')
export KUBE_PROXY_PORT=58080
export KUBECTL_INSECURE_SKIP_TLS_VERIFY=true


kubectl_proxy_on() {
    kubectl config set-cluster proxy-cluster --server="http://${DOCKER_GATEWAY_IP}:${KUBE_PROXY_PORT}"
    kubectl config set-context proxy-context --cluster=proxy-cluster --user=$(kubectl config view -o jsonpath='{.contexts[?(@.name == "'"$(kubectl config current-context)"'")].context.user}')
    kubectl config use-context proxy-context
    echo "Switched to use kubectl proxy"
}

start_kubernetes_cluster() {
    #delete if exists
    kind delete cluster --name my-cluster

    #create cluster
cat <<EOF | kind create cluster --name my-cluster  --config=-
kind: Cluster
apiVersion: kind.x-k8s.io/v1alpha4
networking:
  apiServerAddress: "0.0.0.0"
EOF

    #wait for the cluster
    sleep 5

    #update the gateway IP
    sed -i "s/0.0.0.0/$DOCKER_GATEWAY_IP/g" /root/.kube/config

}
start_proxy(){
    kubectl --insecure-skip-tls-verify proxy --address='0.0.0.0' --accept-hosts='^.*$'  --port=${KUBE_PROXY_PORT} &
    sleep 5
}

configure_cluster(){
    kubectl create namespace kubeflow
    kubectl apply -f https://raw.githubusercontent.com/kserve/kserve/master/install/v$MODELS_WEB_APP_TAG/kserve_kubeflow.yaml
}

start_kubernetes_cluster
start_proxy
kubectl_proxy_on
configure_cluster

sleep 2
touch /lockconfig/lock
tail -f /dev/null
