# k8slimiter

Rate Limits through Validating Webhooks in Kubernetes

For context, please refer to: [Rate limiting Kubernetes pod creation with dynamic admission control](https://www.artur-rodrigues.com/tech/2023/10/22/rate-limiting-kubernetes-pod-creation.html)

## Local Development

Generate local certs:

```
$ mkcert -cert-file ./certs/tls.crt -key-file ./certs/tls.key localhost
```

Run the server:

```
$ TLS_ENABLED=true go run main.go
```

Test the server:

```
$ xh https://localhost:8443/healthz
HTTP/2.0 200 OK
content-length: 15
content-type: application/json; charset=utf-8
date: Sun, 22 Oct 2023 09:05:35 GMT

{
    "status": "ok"
}
```

## Testing Locally with Kind

### Setup

Create a cluster:

```
$ kind create cluster
```

Build the image:

```
$ docker build -t k8slimiter:0.1.0 .
```

Load the image into the cluster:

```
$ kind load docker-image k8slimiter:0.1.0
```

Install cert-manager in the cluster:

```
$ kubectl apply -f https://github.com/cert-manager/cert-manager/releases/download/v1.15.1/cert-manager.yaml
```

Finally, install k8slimiter:

```
$ kubectl apply -f manifests/k8slimiter.yaml
```

Port-forward the service locally:

```
$ kubectl -n k8slimiter port-forward service/k8slimiter-service 8443:https
```

Test the server (note the `--verify=no` flag, since we don't have the cluster CA installed locally):

```
$ xh --verify=no https://localhost:8443/healthz
HTTP/2.0 200 OK
content-length: 15
content-type: application/json; charset=utf-8
date: Sun, 22 Oct 2023 09:09:19 GMT

{
    "status": "ok"
}
```

### Rate limit test

The rate limit is set to 1 pod per 10 seconds. To test this, try scheduling more than one pod in a short period of time:

```
$ kubectl run "tmp-pod-$(date +%s)" --restart Never --image debian:12-slim -- sleep 1
pod/tmp-pod-1698005111 created
$ kubectl run "tmp-pod-$(date +%s)" --restart Never --image debian:12-slim -- sleep 1
Error from server: admission webhook "k8slimiter-pod-creation.k8slimiter.svc" denied the request: rate limit exceeded
```
