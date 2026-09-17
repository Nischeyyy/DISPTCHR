# DISPTCHR Manager Portal — React/Vite, served as static files under /manager/
FROM node:20-alpine AS build
WORKDIR /app
COPY package.json package-lock.json ./
RUN npm ci --no-audit --no-fund
COPY . .
RUN npm run build

FROM nginx:1.27-alpine
COPY nginx.conf /etc/nginx/conf.d/default.conf
# vite.config.js sets base: '/manager/', so the bundle expects to be served from that prefix.
COPY --from=build /app/dist /usr/share/nginx/html/manager
EXPOSE 80
HEALTHCHECK --interval=30s --timeout=5s --retries=3 \
    CMD wget -qO- http://localhost/manager/ >/dev/null || exit 1
