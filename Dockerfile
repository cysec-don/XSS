# VulnLab XSS Playground - Dockerfile
# Author: Cysec Don (cysecdon@gmail.com)
#
# ⚠️  WARNING: This builds an INTENTIONALLY VULNERABLE application.
#    DO NOT expose this container to the public internet.

FROM node:18-alpine

LABEL maintainer="Cysec Don <cysecdon@gmail.com>"
LABEL description="VulnLab - Intentionally Vulnerable XSS Playground"
LABEL warning="This application is intentionally vulnerable. DO NOT expose to the internet."

WORKDIR /app

# Copy package files and install dependencies
COPY package.json package-lock.json* ./
RUN npm install --production

# Copy application code
COPY server.js ./
COPY public/ ./public/

# Expose the application port
EXPOSE 3001

# Health check
HEALTHCHECK --interval=30s --timeout=5s --start-period=5s --retries=3 \
  CMD wget -qO- http://localhost:3001/ || exit 1

# Run as non-root user for minimal safety
RUN addgroup -S vulnlab && adduser -S vulnlab -G vulnlab
USER vulnlab

# Start the server
CMD ["node", "server.js"]
