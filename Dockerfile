# ============================================
# Stage 1: Build stage
# ============================================
FROM node:18-alpine AS builder

# Install build dependencies
RUN apk add --no-cache python3 make g++

WORKDIR /app

# Copy package files first (better layer caching)
COPY package*.json ./

# Install ALL dependencies (including dev for TypeScript build)
RUN npm ci --include=dev

# Copy source code
COPY tsconfig.json ./
COPY src ./src
COPY public ./public
COPY downloads ./downloads

# Build TypeScript
RUN npm run build

# ============================================
# Stage 2: Production stage (smaller image)
# ============================================
FROM node:18-alpine AS production

WORKDIR /app

# Copy package files
COPY package*.json ./

# Install only production dependencies (no build tools needed)
RUN npm ci --omit=dev --ignore-scripts

# Copy built files from builder stage
COPY --from=builder /app/dist ./dist
COPY --from=builder /app/public ./public
COPY --from=builder /app/downloads ./downloads

# Create data directory
RUN mkdir -p /data

# Expose ports
EXPOSE 3000 4001

# Health check
HEALTHCHECK --interval=30s --timeout=10s --start-period=40s --retries=3 \
  CMD node -e "require('http').get('http://localhost:3000/api/health', (r) => { process.exit(r.statusCode === 200 ? 0 : 1); }).on('error', () => process.exit(1));"

# Start the operator node
CMD ["node", "dist/index.js"]
