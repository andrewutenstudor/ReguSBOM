# Stage 1: Build React/Vite app
FROM node:20-alpine AS builder

WORKDIR /app

# Copy package files
COPY package*.json ./
RUN npm install --legacy-peer-deps

# Copy all frontend source
COPY . .

# Optional build-time API URL override (defaults to empty for relative same-origin /api)
ARG VITE_API_URL=""
ENV VITE_API_URL=${VITE_API_URL}

# Build for production
RUN npm run build

# Stage 2: Production Nginx Server
FROM nginx:alpine

# Remove default nginx config & static assets
RUN rm -rf /usr/share/nginx/html/* /etc/nginx/conf.d/default.conf

# Copy production build artifacts
COPY --from=builder /app/dist /usr/share/nginx/html

# Copy optimized nginx configuration
COPY nginx.conf /etc/nginx/conf.d/default.conf

# Configure Nginx for unprivileged non-root execution (UID 10001) for strict OpenShift/RKE2 compliance
RUN adduser -u 10001 -D -S -G nogroup regubom && \
    sed -i 's|/run/nginx.pid|/tmp/nginx.pid|g' /etc/nginx/nginx.conf && \
    sed -i 's|/var/run/nginx.pid|/tmp/nginx.pid|g' /etc/nginx/nginx.conf && \
    sed -i '/user  nginx;/d' /etc/nginx/nginx.conf && \
    touch /tmp/nginx.pid && \
    chown -R 10001:nogroup /usr/share/nginx/html /var/cache/nginx /var/run /run /tmp /etc/nginx/conf.d && \
    chmod -R 777 /var/cache/nginx /var/run /run /tmp

USER 10001

EXPOSE 8080

HEALTHCHECK --interval=30s --timeout=5s --start-period=5s --retries=3 \
  CMD wget -q -O /dev/null http://127.0.0.1:8080/health || exit 1

CMD ["nginx", "-g", "daemon off;"]
