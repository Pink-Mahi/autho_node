# Autho Gateway Node - Docker Image
# Run with: docker run -p 3001:3001 -p 4001:4001 autho-gateway

FROM node:20-alpine

LABEL maintainer="Autho Network"
LABEL description="Autho Gateway Node - Decentralized registry access point"

# Create app directory
WORKDIR /app

# Copy package files
COPY package.json ./

# Install dependencies
RUN npm install --production

# Copy gateway code
COPY gateway-package.js ./

# Create data directory
RUN mkdir -p /app/gateway-data

# Environment variables (can be overridden at runtime)
ENV GATEWAY_PORT=3001
ENV GATEWAY_WS_PORT=4001
ENV NODE_ENV=production

# For public gateway mode, set these at runtime:
# ENV GATEWAY_PUBLIC=true
# ENV GATEWAY_PUBLIC_URL=https://your-domain.com

# Expose ports
EXPOSE 3001 4001

# Health check
HEALTHCHECK --interval=30s --timeout=10s --start-period=5s --retries=3 \
  CMD wget -q --spider http://localhost:3001/health || exit 1

# Run gateway
CMD ["node", "gateway-package.js"]
