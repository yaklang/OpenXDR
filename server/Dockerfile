# 构建上下文是仓库根目录：server 需要 proto/ 生成代码已提交，rules/ 运行时挂载
FROM golang:1.25-alpine AS build
WORKDIR /src
COPY server/go.mod server/go.sum ./
RUN go mod download
COPY server/ ./
RUN CGO_ENABLED=0 go build -o /openxdr-server .

FROM alpine:3.22
RUN adduser -D -u 10001 openxdr
COPY --from=build /openxdr-server /usr/local/bin/openxdr-server
USER openxdr
EXPOSE 8080 8081
ENTRYPOINT ["openxdr-server"]
