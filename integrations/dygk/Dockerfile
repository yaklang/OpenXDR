# syntax=docker/dockerfile:1
# 构建上下文为仓库根目录，镜像内不引用构建机路径。
FROM --platform=$BUILDPLATFORM golang:1.26.9-alpine3.24 AS native
ARG TARGETOS TARGETARCH
ARG GOPROXY=https://proxy.golang.org,direct
ENV GOPROXY=${GOPROXY}
WORKDIR /src
COPY server/go.mod server/go.sum ./
RUN go mod download
COPY server/ ./
RUN CGO_ENABLED=0 GOOS=$TARGETOS GOARCH=$TARGETARCH go build -trimpath -o /decoyhost ./deception/cmd/decoyhost

FROM --platform=$BUILDPLATFORM node:24.22.1-bookworm-slim AS prepare
ARG DYGK_SOURCE=local
ARG DYGK_LOCAL_SOURCE=local-source
RUN if [ "$DYGK_SOURCE" = remote ]; then apt-get update && apt-get install -y --no-install-recommends git ca-certificates && rm -rf /var/lib/apt/lists/*; fi
WORKDIR /module
COPY integrations/dygk/ ./
RUN --mount=type=secret,id=dygk_upstream_token,env=DYGK_UPSTREAM_TOKEN \
    node scripts/prepare-upstream.mjs && node scripts/stage-runtime.mjs /out

FROM node:24.22.1-bookworm-slim
WORKDIR /app
COPY --from=prepare /out/ ./
COPY --from=native /decoyhost /usr/local/bin/decoyhost
RUN mkdir /data && chown 10001:10001 /data
ENV DYGK_STATE_DIR=/data DYGK_LISTEN_HOST=0.0.0.0
USER 10001:10001
CMD ["node", "web/manager.mjs"]
