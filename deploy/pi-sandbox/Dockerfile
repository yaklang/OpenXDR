# Pi 沙箱：Pi 默认工具（bash/read/edit/write）+ xdr 命令行 + Skill，由 sandboxd 按会话起停。
# 容器里没有任何平台凭据：工具请求经 stdin/stdout 交回平台，网络只放行模型端点（宿主防火墙负责）。
FROM node:24-bookworm-slim
ARG NPM_REGISTRY=https://registry.npmmirror.com
RUN sed -i 's|deb.debian.org|mirrors.ustc.edu.cn|g' /etc/apt/sources.list.d/debian.sources \
 && apt-get update && apt-get install -y --no-install-recommends bash curl jq ca-certificates python3 bsdextrautils procps \
 && rm -rf /var/lib/apt/lists/*
WORKDIR /opt/openxdr-sandbox
COPY package.json package-lock.json ./
RUN npm ci --omit=dev --registry=$NPM_REGISTRY
COPY bridge.mjs model-fallback.mjs ./
COPY skills/ ./skills/
COPY xdr /usr/local/bin/xdr
# jq 薄包装：过滤式里写了 SQL 的 -> 而报语法错时补一句提示，其余行为与退出码不变
COPY jq /usr/local/bin/jq
# 沙箱没有外网：curl / wget 换成立刻报错并指路的包装，xdr 用 /usr/bin/curl 走 unix socket
COPY no-egress /usr/local/bin/curl
RUN ln -s curl /usr/local/bin/wget
RUN useradd -m -u 10010 agent
USER agent
ENV HOME=/home/agent XDR_SOCKET=/tmp/xdr/xdr.sock XDR_CONTEXT=/tmp/xdr/context.json
WORKDIR /home/agent
ENTRYPOINT ["node", "/opt/openxdr-sandbox/bridge.mjs"]
