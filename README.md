# Smart SIEM CTU — Backend API

<p align="center">
  <strong>Security Information and Event Management System</strong><br />
  Log ingestion, correlation, SOAR automation, UEBA, forensics, and reporting.
</p>

## Overview

The CTU (Counter-Terrorism Unit) Smart SIEM backend ingests security logs from multiple sources, normalizes them into a **Golden Schema**, stores them in **Elasticsearch** for full-text search, and correlates events against **MITRE ATT&CK** rules to detect threats. Detected incidents trigger **SOAR playbooks** (automated response), while **UEBA** profiles track user behavior anomalies.

Built with **NestJS 11**, **Prisma 7** (PostgreSQL), **Elasticsearch**, and **BullMQ** (Redis).

## Architecture

```
┌─────────────┐     ┌──────────────┐     ┌──────────────────┐
│ Collectors  │────▶│  API /auth   │────▶│ PostgreSQL       │
│ (Agents)    │     │  /logs       │     │ (users, rules,   │
└─────────────┘     │  /incidents  │     │  incidents,       │
                    │  /soar       │     │  playbooks,       │
                    │  /ueba       │     │  audit)           │
                    │  /admin      │     └──────────────────┘
                    │  /audit      │
                    │  /reports    │     ┌──────────────────┐
                    │  /dashboard  │────▶│ Elasticsearch    │
                    └──────┬───────┘     │ (log storage,    │
                           │            │  full-text        │
                           ▼             │  search)          │
                    ┌──────────────┐     └──────────────────┘
                    │ BullMQ       │
                    │ (Redis)      │     ┌──────────────────┐
                    │ Logs queue   │────▶│ LogsProcessor    │
                    └──────────────┘     │ → normalize      │
                                         │ → index in ES    │
                                         └──────────────────┘
```

## Tech Stack

| Component | Technology |
|-----------|------------|
| **Runtime** | Node.js 20, TypeScript 5.9 |
| **Framework** | NestJS 11 |
| **ORM** | Prisma 7 (`@prisma/client` with `@prisma/adapter-pg`) |
| **Database (operational)** | PostgreSQL 16 — users, rules, incidents, playbooks, UEBA, audit |
| **Database (logs)** | Elasticsearch 9.x — normalized logs, full-text search, forensics |
| **Queue** | BullMQ 5 + Redis 7 — async log normalization |
| **Auth** | JWT (Passport), bcryptjs, RBAC |
| **API Docs** | Swagger / OpenAPI 3.0 via `@nestjs/swagger` |
| **Validation** | class-validator, class-transformer |
| **Email** | Nodemailer + Handlebars templates |
| **Containerization** | Docker, Docker Compose |

## Prerequisites

- Node.js >= 20
- npm >= 10
- Docker Desktop (for local services)

## Quick Start

### 1. Clone and install

```bash
git clone <repo-url> siem-backend
cd siem-backend
npm install
```

### 2. Start infrastructure services

```bash
docker compose up -d postgres redis elasticsearch
```

### 3. Configure environment

Create a `.env` file:

```env
DATABASE_URL="postgresql://siem:siem_password@localhost:5432/siem_db?schema=public"
REDIS_HOST=localhost
REDIS_PORT=6379
ELASTICSEARCH_URL=http://localhost:9200
JWT_SECRET=change-this-to-a-secure-random-string-in-production
```

### 4. Run database migrations

```bash
npx prisma migrate dev
```

### 5. Start the application

```bash
npm run start:dev
```

The API is available at `http://localhost:3000/api/v1`.  
Swagger docs at `http://localhost:3000/api/docs`.

## Docker (full stack)

```bash
docker compose up --build
```

This starts all 4 services: `postgres`, `redis`, `elasticsearch`, and `app`.  
The `app` service automatically runs `prisma migrate deploy` on startup.

## API Documentation

Once running, visit **`/api/docs`** for the interactive Swagger UI.

### API Endpoints

| Tag | Method | Endpoint | Description | Auth |
|-----|--------|----------|-------------|------|
| **Authentication** | POST | `/auth/login` | Login with username/password | Public |
| | POST | `/auth/register` | Register a new user | Public |
| | GET | `/auth/profile` | Get current user profile | JWT |
| **Dashboard** | GET | `/dashboard/stats` | Crisis room statistics | JWT |
| | GET | `/dashboard/timeline` | Timeline chart data | JWT |
| **Logs** | POST | `/logs` | Ingest raw logs | JWT |
| | GET | `/logs/search` | Full-text log search | JWT |
| **Incidents** | GET | `/incidents` | List incidents (filterable) | JWT |
| | GET | `/incidents/:id` | Incident details | JWT |
| | PATCH | `/incidents/:id` | Update incident status | JWT |
| **Rules (MITRE)** | GET | `/rules` | List correlation rules | JWT |
| | POST | `/rules` | Create rule | ADMIN |
| | PUT | `/rules/:id` | Update rule | ADMIN |
| | DELETE | `/rules/:id` | Delete rule | ADMIN |
| **SOAR** | POST | `/soar/execute` | Execute a playbook | JWT |
| | POST | `/soar/abort` | Abort a playbook | JWT |
| **UEBA** | GET | `/ueba/users` | List risk profiles | JWT |
| | GET | `/ueba/users/:principal` | Get user profile | JWT |
| **Admin** | GET/POST | `/admin/users` | List / Create users | ADMIN |
| | PUT/DELETE | `/admin/users/:id` | Update / Deactivate user | ADMIN |
| | GET/PUT | `/admin/retention` | Retention policies | ADMIN |
| **Audit** | GET | `/audit/trail` | Audit trail logs | JWT |
| | GET | `/audit/integrity/:id` | Verify batch integrity | JWT |
| **Reports** | POST | `/reports/generate` | Generate PDF/Excel report | JWT |
| | GET | `/reports/download/:id` | Download report | JWT |

### Authentication

All endpoints except `/auth/login` and `/auth/register` require a **Bearer JWT token**:

```
Authorization: Bearer <access_token>
```

**Role-Based Access Control (RBAC):**

| Role | Permissions |
|------|-------------|
| `READER` | View dashboards, incidents, logs, rules |
| `ANALYST` | All READER permissions + update incidents, execute playbooks |
| `ADMIN` | All ANALYST permissions + manage users, create/update/delete rules, configure retention |

## Project Structure

```
src/
├── @types/                    # Type declarations (Express Request)
├── auth/                      # Authentication module
│   ├── decorators/            # @Public(), @CurrentUser(), @Roles()
│   ├── dto/                   # SignInDto, SignUpDto
│   ├── guards/                # JwtAuthGuard, RolesGuard
│   ├── strategies/            # LocalStrategy, JwtStrategy
│   ├── auth.controller.ts
│   ├── auth.module.ts
│   └── auth.service.ts
├── prisma/                    # Prisma module (global)
│   ├── prisma.module.ts
│   └── prisma.service.ts
├── elasticsearch/             # Elasticsearch module (global)
│   ├── elasticsearch.module.ts
│   └── elasticsearch.service.ts
├── logs/                      # Logs ingestion & search
│   ├── dto/                   # CreateLogDto, SearchLogsDto
│   ├── interfaces/            # NormalizedLog, LogSearchQuery
│   ├── processors/            # LogsProcessor (BullMQ worker)
│   ├── logs.controller.ts
│   ├── logs.module.ts
│   └── logs.service.ts
├── dashboard/                 # Dashboard (crisis room stats)
│   ├── dto/
│   ├── dashboard.controller.ts
│   ├── dashboard.module.ts
│   └── dashboard.service.ts
├── incidents/                 # Incident lifecycle
│   ├── dto/
│   ├── incidents.controller.ts
│   ├── incidents.module.ts
│   └── incidents.service.ts
├── rules/                     # MITRE ATT&CK correlation rules
│   ├── dto/
│   ├── rules.controller.ts
│   ├── rules.module.ts
│   └── rules.service.ts
├── soar/                      # SOAR playbook execution
│   ├── dto/
│   ├── soar.controller.ts
│   ├── soar.module.ts
│   └── soar.service.ts
├── ueba/                      # User behavior analytics
│   ├── ueba.controller.ts
│   ├── ueba.module.ts
│   └── ueba.service.ts
├── admin/                     # Admin (user & retention management)
│   ├── dto/
│   ├── admin.controller.ts
│   ├── admin.module.ts
│   └── admin.service.ts
├── audit/                     # Audit trail & integrity
│   ├── audit.controller.ts
│   ├── audit.module.ts
│   └── audit.service.ts
├── reports/                   # Report generation
│   ├── dto/
│   ├── reports.controller.ts
│   └── reports.module.ts
├── mail/                      # Email notifications
│   ├── mail.module.ts
│   └── mail.service.ts
├── app.module.ts
├── app.controller.ts
└── main.ts
```

## Database

### PostgreSQL (Prisma)

The schema is defined in `prisma/schema.prisma` and includes:

- **users** — Authentication, MFA, RBAC
- **correlation_rules** — MITRE ATT&CK rules with JSON definition
- **incidents** — Security incidents linked to rules and users
- **playbook_executions** — SOAR automation tracking
- **batch_manifests** — SHA-256 chain of custody (FR-02.3)
- **ueba_profiles** — Behavioral baseline and risk scoring
- **audit_trail** — Full action journaling with IP logging
- **retention_policies** — Data lifecycle configuration

### Elasticsearch

Log index template (`ctu-logs-template`) with Golden Schema:

- `collected_at`, `normalized_at` (date)
- `source_type`, `hostname`, `user_principal` (keyword)
- `source_ip`, `destination_ip` (ip)
- `source_port`, `destination_port` (integer)
- `event_taxonomy`, `action`, `outcome` (keyword)
- `severity` (byte)
- `raw_message` (text with custom analyzer)
- `tags` (keyword array)
- `ingestion_hash` (keyword — SHA-256 for integrity)
- ILM policy: 30-day retention with rollover at 50GB / 7 days

## Scripts

| Command | Description |
|---------|-------------|
| `npm run start:dev` | Start in watch mode |
| `npm run build` | Compile TypeScript |
| `npm run start:prod` | Start production build |
| `npm run lint` | Lint source files |
| `npm run format` | Format with Prettier |
| `npm run test` | Run unit tests |
| `npm run test:e2e` | Run end-to-end tests |
| `npx prisma generate` | Regenerate Prisma Client |
| `npx prisma migrate dev` | Create & apply migrations |
| `npx prisma migrate deploy` | Apply pending migrations (prod) |
| `npx prisma studio` | Open Prisma Studio (GUI) |
| `npx prisma db seed` | Seed database |

## Security

- **Password hashing**: bcrypt with 12 salt rounds via `bcryptjs`
- **JWT**: 24-hour expiration, configurable secret via `JWT_SECRET`
- **Global auth guard**: All routes protected by default; `@Public()` opt-out
- **Role guard**: `@Roles(UserRole.ADMIN)` restricts access
- **Input validation**: `class-validator` with whitelist on all DTOs
- **Audit trail**: All user actions logged in `audit_trail` table
