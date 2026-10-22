# syntax=docker/dockerfile:1
ARG BUILDPLATFORM
FROM --platform=$BUILDPLATFORM golang:1.25-alpine AS build

ARG TARGETOS
ARG TARGETARCH
WORKDIR /src
COPY go.mod go.sum ./
RUN go mod download
COPY . .
RUN CGO_ENABLED=0 GOOS=$TARGETOS GOARCH=$TARGETARCH go build -trimpath -ldflags='-s -w' -o /out/exposure ./cmd/exposure \
    && CGO_ENABLED=0 GOOS=$TARGETOS GOARCH=$TARGETARCH go build -trimpath -ldflags='-s -w' -o /out/exposure-validate-run ./cmd/exposure-validate-run

FROM gcr.io/distroless/static-debian12:nonroot

COPY --from=build /out/exposure /exposure
COPY --from=build /out/exposure-validate-run /usr/local/bin/exposure-validate-run
USER nonroot:nonroot
ENTRYPOINT ["/exposure"]
