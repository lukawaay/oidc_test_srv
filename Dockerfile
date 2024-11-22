FROM golang:1.23 AS build

WORKDIR /app

COPY ./go.mod ./go.sum ./
RUN go mod download

COPY ./internal ./internal
COPY ./cmd ./cmd

RUN CGO_ENABLED=0 GOOS=linux go build -o ./oidc_test_srv ./cmd/oidc_test_srv

FROM gcr.io/distroless/base-debian11 AS build-release

COPY --from=build /app/oidc_test_srv /app/oidc_test_srv

ENV OIDC_TEST_SRV_PORT=8080
EXPOSE 8080

USER nonroot:nonroot

CMD ["/app/oidc_test_srv"]
