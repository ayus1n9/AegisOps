# Multi-stage hardened build for SecureFlow Frontend
# Stage 1: Build static assets
FROM node:22-alpine AS builder

WORKDIR /app
COPY package.json package-lock.json ./
RUN npm ci

COPY tsconfig.json vite.config.ts index.html ./
COPY src/ ./src/
RUN npm run build

# Stage 2: Minimal unprivileged NGINX runtime
FROM nginxinc/nginx-unprivileged:1.27-alpine

USER root
COPY nginx.conf /etc/nginx/nginx.conf
COPY --from=builder /app/dist /usr/share/nginx/html

# Set appropriate non-root file permissions
RUN chown -R 101:101 /usr/share/nginx/html /etc/nginx/nginx.conf

# Switch back to non-root user (nginx UID 101)
USER 101

EXPOSE 3000

HEALTHCHECK --interval=15s --timeout=3s --start-period=5s --retries=3 \
  CMD wget --no-verbose --tries=1 --spider http://127.0.0.1:3000/health || exit 1

CMD ["nginx", "-g", "daemon off;"]
