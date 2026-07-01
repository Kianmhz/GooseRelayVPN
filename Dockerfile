FROM golang:1.22-alpine AS builder

WORKDIR /src

COPY go.mod go.sum ./
RUN go mod download

COPY . .

ARG TARGETOS
ARG TARGETARCH
ARG VERSION=dev
RUN CGO_ENABLED=0 GOOS=${TARGETOS:-linux} GOARCH=${TARGETARCH:-amd64} go build -trimpath -ldflags "-s -w -X main.version=${VERSION}" -o /out/goose-server ./cmd/server

FROM gcr.io/distroless/static-debian12:nonroot

WORKDIR /app

COPY --from=builder /out/goose-server /app/goose-server
COPY server_config.example.json /app/server_config.example.json

EXPOSE 3109

ENTRYPOINT ["/app/goose-server"]
CMD ["-config", "/app/server_config.json"]
