FROM node:22-alpine AS build
# 网络受限时可指向镜像源，例如 --build-arg NPM_REGISTRY=https://registry.npmmirror.com
ARG NPM_REGISTRY=https://registry.npmjs.org
WORKDIR /src
COPY package.json package-lock.json ./
RUN npm config set registry ${NPM_REGISTRY} && npm ci
COPY . ./
RUN npm run build

FROM nginx:alpine
COPY --from=build /src/dist /usr/share/nginx/html
COPY nginx.conf /etc/nginx/conf.d/default.conf
EXPOSE 80
