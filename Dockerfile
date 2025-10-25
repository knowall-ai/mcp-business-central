# Multi-stage build for Business Central MCP Server (HTTP mode)
FROM node:22-alpine AS builder

# Set working directory
WORKDIR /app

# Copy package files
COPY package.json package-lock.json ./

# Copy source files for build
COPY src ./src
COPY tsconfig.json ./

# Install dependencies and build
RUN --mount=type=cache,target=/root/.npm npm install
RUN npm run build

# Production image
FROM node:22-alpine

# Set working directory
WORKDIR /app

# Copy built files and production dependencies
COPY --from=builder /app/build ./build
COPY --from=builder /app/node_modules ./node_modules
COPY --from=builder /app/package*.json ./

# Expose HTTP server port
EXPOSE 3000

# Run HTTP server (not STDIO)
CMD ["node", "build/http-server.js"]
