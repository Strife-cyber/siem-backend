# ---- Build Stage ----
FROM node:20 AS builder

WORKDIR /usr/src/app

COPY package*.json prisma.config.ts tsconfig.json tsconfig.build.json nest-cli.json ./

ENV PRISMA_SKIP_POSTINSTALL_GENERATE=true
RUN npm install

COPY src ./src
COPY prisma ./prisma

RUN npx prisma generate
RUN npm run build

# ---- Production Stage ----
FROM node:20-alpine AS production

RUN apk add --no-cache wget

WORKDIR /usr/src/app

COPY --from=builder /usr/src/app/package*.json ./
COPY --from=builder /usr/src/app/node_modules ./node_modules
COPY --from=builder /usr/src/app/dist ./dist
COPY --from=builder /usr/src/app/generated ./generated
COPY --from=builder /usr/src/app/prisma ./prisma

# Create config and verify it exists
RUN echo 'import { defineConfig } from "prisma/config";' > /usr/src/app/prisma.config.ts && \
    echo 'export default defineConfig({' >> /usr/src/app/prisma.config.ts && \
    echo '  schema: "prisma/schema.prisma",' >> /usr/src/app/prisma.config.ts && \
    echo '  migrations: { path: "prisma/migrations" },' >> /usr/src/app/prisma.config.ts && \
    echo '  datasource: { url: process.env.DATABASE_URL },' >> /usr/src/app/prisma.config.ts && \
    echo '});' >> /usr/src/app/prisma.config.ts && \
    echo "=== VERIFY ===" && \
    cat /usr/src/app/prisma.config.ts

# Patch Prisma client to remove import.meta.url (not valid in CJS)
# BusyBox sed needs -i with backup extension; pass '' for no backup
RUN sed -i'' "s/globalThis\['__dirname'\].*//" /usr/src/app/dist/generated/prisma/client.js && \
    sed -i'' "s/globalThis\['__dirname'\].*//" /usr/src/app/dist/generated/prisma/internal/class.js 2>/dev/null || true

# Create entrypoint with detailed debugging
RUN echo '#!/bin/sh' > /usr/local/bin/docker-entrypoint.sh && \
    echo 'set -e' >> /usr/local/bin/docker-entrypoint.sh && \
    echo '' >> /usr/local/bin/docker-entrypoint.sh && \
    echo 'echo "=== Debug Info ==="' >> /usr/local/bin/docker-entrypoint.sh && \
    echo 'echo "PWD: $(pwd)"' >> /usr/local/bin/docker-entrypoint.sh && \
    echo 'echo "DATABASE_URL: $([ -n "$DATABASE_URL" ] && echo IS_SET || echo NOT_SET)"' >> /usr/local/bin/docker-entrypoint.sh && \
    echo 'echo "Config file exists: $([ -f /usr/src/app/prisma.config.ts ] && echo YES || echo NO)"' >> /usr/local/bin/docker-entrypoint.sh && \
    echo 'echo "Prisma dir exists: $([ -d /usr/src/app/prisma ] && echo YES || echo NO)"' >> /usr/local/bin/docker-entrypoint.sh && \
    echo 'echo "Dist dir exists: $([ -d /usr/src/app/dist ] && echo YES || echo NO)"' >> /usr/local/bin/docker-entrypoint.sh && \
    echo '' >> /usr/local/bin/docker-entrypoint.sh && \
    echo 'echo "=== Running Prisma migrations ==="' >> /usr/local/bin/docker-entrypoint.sh && \
    echo 'npx prisma migrate deploy' >> /usr/local/bin/docker-entrypoint.sh && \
    echo 'echo "=== Migrations applied ==="' >> /usr/local/bin/docker-entrypoint.sh && \
    echo '' >> /usr/local/bin/docker-entrypoint.sh && \
    echo 'echo "=== Starting application ==="' >> /usr/local/bin/docker-entrypoint.sh && \
    echo 'exec node dist/src/main' >> /usr/local/bin/docker-entrypoint.sh && \
    chmod +x /usr/local/bin/docker-entrypoint.sh

EXPOSE 3000

HEALTHCHECK --interval=30s --timeout=3s --start-period=10s --retries=3 \
  CMD wget --no-verbose --tries=1 --spider http://localhost:3000/api/v1/ || exit 1

ENTRYPOINT ["docker-entrypoint.sh"]
