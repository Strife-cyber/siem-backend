# ---- Build Stage ----
FROM node:20 AS builder

WORKDIR /usr/src/app

# Copy dependency manifests
COPY package*.json prisma.config.ts tsconfig.json tsconfig.build.json nest-cli.json ./

# Install ALL dependencies (including devDependencies needed for build)
# PRISMA_SKIP_POSTINSTALL_GENERATE skips engine download in postinstall;
# we run prisma generate explicitly in a later step
ENV PRISMA_SKIP_POSTINSTALL_GENERATE=true
RUN npm install

# Copy source files
COPY src ./src
COPY prisma ./prisma

# Generate Prisma Client before building
RUN npx prisma generate

# Build the NestJS application
RUN npm run build

# ---- Production Stage ----
FROM node:20-alpine AS production

# Install tools needed for healthcheck
RUN apk add --no-cache wget

WORKDIR /usr/src/app

# Copy all node_modules from builder, then prune dev dependencies
# This avoids any network dependency during production stage
COPY --from=builder /usr/src/app/node_modules ./node_modules
COPY --from=builder /usr/src/app/dist ./dist
COPY --from=builder /usr/src/app/generated ./generated
COPY --from=builder /usr/src/app/prisma ./prisma

# Note: keeping full node_modules (including dev deps like prisma CLI)
# because prisma migrate deploy is needed at runtime via entrypoint
# If image size is a concern, move prisma to dependencies

# Copy entrypoint script
COPY docker-entrypoint.sh /usr/local/bin/
RUN chmod +x /usr/local/bin/docker-entrypoint.sh

# Expose the application port
EXPOSE 3000

# Health check
HEALTHCHECK --interval=30s --timeout=3s --start-period=10s --retries=3 \
  CMD wget --no-verbose --tries=1 --spider http://localhost:3000/api/v1/ || exit 1

# Entrypoint runs migrations then starts the app
ENTRYPOINT ["docker-entrypoint.sh"]
