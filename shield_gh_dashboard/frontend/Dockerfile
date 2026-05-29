# ── Stage 1: Build React app ───────────────────────────────────
FROM node:20-alpine AS builder

WORKDIR /build

# Install dependencies first (layer cache)
COPY shield_gh_dashboard/frontend/package*.json ./
RUN npm ci

# Copy source and build
COPY shield_gh_dashboard/frontend/ .
RUN npm run build

# ── Stage 2: Serve with Nginx ──────────────────────────────────
FROM nginx:1.27-alpine

# Remove default nginx config
RUN rm /etc/nginx/conf.d/default.conf

# Add our proxy config
COPY shield_gh_dashboard/frontend/nginx.conf /etc/nginx/conf.d/shield_gh.conf

# Copy built React app
COPY --from=builder /build/dist /usr/share/nginx/html

EXPOSE 80
CMD ["nginx", "-g", "daemon off;"]
