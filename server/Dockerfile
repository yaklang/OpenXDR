# 构建上下文是仓库根目录：server 需要 proto/ 生成代码已提交。
# 镜像自带默认规则、预设任务与 agent / sensor 安装包（发版时注入），开箱即用；挂载目录并设 RULES_PATH / TASKS_PATH / AGENT_DIST_DIR 可覆盖。
# 离线 IP 归属库同理：发版时注入当月 DB-IP Lite，挂载目录并设 IPDB_DIR 可覆盖
# 编译阶段都跑在构建机本架构上，Go 交叉编译到目标架构：多架构发版时 arm64 不在 QEMU 里编译（模拟下要几个小时）
FROM --platform=$BUILDPLATFORM golang:1.26.9-alpine3.24 AS build
ARG TARGETOS TARGETARCH
# 网络受限时可指向镜像源，例如 --build-arg GOPROXY=https://goproxy.cn,direct
ARG GOPROXY=https://proxy.golang.org,direct
ENV GOPROXY=${GOPROXY}
WORKDIR /src
COPY server/go.mod server/go.sum ./
RUN go mod download
COPY server/ ./
RUN CGO_ENABLED=0 GOOS=$TARGETOS GOARCH=$TARGETARCH go build -o /openxdr-server . && \
    CGO_ENABLED=0 GOOS=$TARGETOS GOARCH=$TARGETARCH go build -o /openxdr-gencerts ./cmd/gencerts && \
    CGO_ENABLED=0 GOOS=$TARGETOS GOARCH=$TARGETARCH go build -o /openxdr-ipdb ./cmd/ipdb

RUN CGO_ENABLED=0 GOOS=linux GOARCH=amd64 go build -o /decoy-dist/decoyhost-linux-amd64 ./cmd/decoyhost && CGO_ENABLED=0 GOOS=linux GOARCH=arm64 go build -o /decoy-dist/decoyhost-linux-arm64 ./cmd/decoyhost

# agent 与 sensor 安装包：发版时用 --build-context agents=<含 dist/ 的目录> 注入，本地构建为空目录
FROM alpine:3.22.6 AS agents
RUN mkdir /dist

# 离线 IP 归属库：发版时用 --build-context ipdb=<含 ipdb/ 的目录> 注入（release.yml 下载并校验）。
# 本地与离线构建不下载，这里是空目录：server 启动日志说明库缺失，归属字段留空，不影响其余功能
FROM alpine:3.22.6 AS ipdb
RUN mkdir /ipdb

# Pi 运行时：server 为每个会话拉起的 Node 子进程。依赖是纯 JS（不跑安装脚本），在构建机上装；
# node 二进制取目标架构镜像里的。npm ci 会先清掉拷进来的 node_modules
FROM node:22.23.3-alpine3.23 AS node-bin

FROM --platform=$BUILDPLATFORM node:22.23.3-alpine3.23 AS pi-runtime
WORKDIR /pi-runtime
COPY server/pi-runtime/ ./
RUN npm ci --omit=dev --ignore-scripts

FROM alpine:3.22.6
# node 依赖 libstdc++；chromium + 中文字体渲染报告，Poppler 将 PDF 页面渲染为视觉模型输入
# 国内构建可传 ALPINE_MIRROR（如 https://mirrors.ustc.edu.cn），默认官方源
ARG ALPINE_MIRROR=
RUN if [ -n "$ALPINE_MIRROR" ]; then sed -i -E "s#https?://dl-cdn.alpinelinux.org#$ALPINE_MIRROR#" /etc/apk/repositories; fi && \
    apk add --no-cache libstdc++ chromium font-noto-cjk poppler-utils && adduser -D -u 10001 openxdr && \
    mkdir -p /run/openxdr/deception && chown openxdr:openxdr /run/openxdr/deception && chmod 700 /run/openxdr/deception
COPY --from=build /openxdr-server /usr/local/bin/openxdr-server
COPY --from=build /openxdr-gencerts /usr/local/bin/openxdr-gencerts
COPY --from=build /openxdr-ipdb /usr/local/bin/openxdr-ipdb
COPY --from=build /decoy-dist/ /opt/openxdr/decoy-dist/
ENV DECOY_DIST_DIR=/opt/openxdr/decoy-dist
COPY rules/ /opt/openxdr/rules/
COPY tasks/ /opt/openxdr/tasks/
# 时序规则随镜像带上，但默认不启用（开发中）：设 TEMPORAL_RULES_PATH=/opt/openxdr/temporal-rules 开启
COPY temporal-rules/ /opt/openxdr/temporal-rules/
COPY --from=agents /dist/ /opt/openxdr/dist/
COPY --from=ipdb /ipdb/ /opt/openxdr/ipdb/
ENV RULES_PATH=/opt/openxdr/rules TASKS_PATH=/opt/openxdr/tasks AGENT_DIST_DIR=/opt/openxdr/dist IPDB_DIR=/opt/openxdr/ipdb
COPY --from=node-bin /usr/local/bin/node /usr/local/bin/node
COPY --from=pi-runtime /pi-runtime /app/pi-runtime
USER openxdr
EXPOSE 8080 8081
ENTRYPOINT ["openxdr-server"]
