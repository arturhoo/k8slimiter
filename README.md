# k8slimiter

Rate limit based Validating Admission Webhooks for Kubernetes

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
$ kubectl apply -f https://github.com/cert-manager/cert-manager/releases/download/v1.13.1/cert-manager.yaml
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
