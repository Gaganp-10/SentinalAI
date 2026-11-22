# Stage 1: Build Frontend Assets
FROM node:26-bookworm-slim AS frontend-builder

WORKDIR /app
COPY frontend/package.json frontend/package-lock.json ./
RUN npm ci
COPY frontend/ ./
ARG VITE_API_BASE_URL=""
ENV VITE_API_BASE_URL=$VITE_API_BASE_URL
ARG VITE_GOOGLE_CLIENT_ID=""
ENV VITE_GOOGLE_CLIENT_ID=$VITE_GOOGLE_CLIENT_ID
RUN npm run build

# Stage 2: Custom Caddy with patched golang.org/x/net (pinned builder tag)
FROM caddy:2.11.9-builder-alpine AS caddy-builder

RUN xcaddy build v2.11.9 --replace golang.org/x/net=golang.org/x/net@v0.62.0 --output /usr/bin/caddy

# Stage 3: Hardened Caddy Image with Static Files (pinned runner tag)
FROM caddy:2.11.9-alpine AS runner

RUN apk upgrade --no-cache

COPY --from=caddy-builder /usr/bin/caddy /usr/bin/caddy
COPY --from=frontend-builder /app/dist /srv
