FROM golang:1.21.3 as build

WORKDIR /go/src/k8slimiter
COPY go.mod go.sum ./
RUN go mod download

COPY main.go ./
RUN CGO_ENABLED=0 go build -o /go/bin/k8slimiter

FROM gcr.io/distroless/static-debian12
COPY --from=build /go/bin/k8slimiter /
CMD ["/k8slimiter"]