# ──────────────────────────────────────────────────────
# WardenNet Nginx — 多阶段：Node build 前端 → nginx serve
# 一个镜像搞定：前端静态资源 + API 反代
# ──────────────────────────────────────────────────────

# ════════════════════════════════════════════════════
# Stage 1: Node 构建前端
# ════════════════════════════════════════════════════
FROM node:20-alpine AS frontend-builder

WORKDIR /build

# 利用 Docker 缓存层：先 COPY package.json
COPY cloud/web/package*.json ./
RUN npm install --no-audit --no-fund --prefer-offline

# 全部源码
COPY cloud/web/ .
RUN npm run build

# 产物在 /build/dist/

# ════════════════════════════════════════════════════
# Stage 2: Nginx 运行时（反代 API + 托管前端）
# ════════════════════════════════════════════════════
FROM nginx:alpine AS runtime

# 清理默认站点
RUN rm -rf /usr/share/nginx/html/* \
    && rm -f /etc/nginx/conf.d/*.conf \
    && rm -f /etc/nginx/nginx.conf

# 从 builder 拷贝前端构建产物
COPY --from=frontend-builder /build/dist /usr/share/nginx/html

# 拷贝 nginx 主配置（覆盖默认）
COPY deploy/nginx/nginx.conf /etc/nginx/nginx.conf

# SPA fallback
RUN echo 'autoindex off;' >> /etc/nginx/conf.d/spa.conf 2>/dev/null || true

EXPOSE 80
CMD ["nginx", "-g", "daemon off;"]