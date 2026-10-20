# 产物是静态文件，构建阶段跑在构建机本架构上，多架构发版不进 QEMU
FROM --platform=$BUILDPLATFORM node:22.23.3-alpine3.23 AS build
# 网络受限时可指向镜像源，例如 --build-arg NPM_REGISTRY=https://registry.npmmirror.com
ARG NPM_REGISTRY=https://registry.npmjs.org
WORKDIR /src
COPY package.json package-lock.json ./
RUN npm config set registry ${NPM_REGISTRY} && npm ci
COPY . ./
RUN npm run build

FROM nginx:1.30.6-alpine3.24
COPY --from=build /src/dist /usr/share/nginx/html
COPY nginx.conf /etc/nginx/conf.d/default.conf
EXPOSE 80
