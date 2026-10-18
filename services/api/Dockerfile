# Multi-stage hardened build for SecureFlow Node.js API Gateway
# Stage 1: Build TypeScript source
FROM node:22-alpine AS builder

WORKDIR /app
COPY package.json package-lock.json ./
RUN npm ci

COPY tsconfig.json ./
COPY src/ ./src/
RUN npm run build

# Stage 2: Hardened, minimal production runtime
FROM node:22-alpine

# Install dumb-init and ensure system libraries are up to date
RUN apk update && apk add --no-cache dumb-init && apk upgrade --no-cache zlib

WORKDIR /app

# Install production-only dependencies and remove npm/npx tools from runtime to minimize attack surface
COPY package.json package-lock.json ./
RUN npm ci --omit=dev && \
    npm cache clean --force && \
    rm -rf /usr/local/lib/node_modules/npm /usr/local/bin/npm /usr/local/bin/npx

# Copy compiled JavaScript output
COPY --from=builder /app/dist ./dist

# Harden ownership and run as built-in non-root user 'node' (UID 1000)
RUN chown -R node:node /app
USER node

EXPOSE 8000

ENV NODE_ENV=production
ENV API_PORT=8000
ENV API_HOST=0.0.0.0

HEALTHCHECK --interval=15s --timeout=3s --start-period=5s --retries=3 \
  CMD node -e "fetch('http://127.0.0.1:8000/health').then(r=>process.exit(r.ok?0:1)).catch(()=>process.exit(1))"

ENTRYPOINT ["dumb-init", "--"]
CMD ["node", "dist/index.js"]
