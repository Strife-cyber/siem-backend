# Guide de Déploiement — Smart SIEM CTU Backend

> Version : 1.0.0 — Dernière mise à jour : Juillet 2026

---

## Table des Matières

1. [Présentation](#1-présentation)
2. [Prérequis Techniques](#2-prérequis-techniques)
3. [Architecture des Services](#3-architecture-des-services)
4. [Variables d'Environnement](#4-variables-denvironnement)
5. [Déploiement en Développement Local](#5-déploiement-en-développement-local)
6. [Déploiement avec Docker Compose (Stack Complète)](#6-déploiement-avec-docker-compose-stack-complète)
7. [Déploiement Manuel sur un Serveur Nu](#7-déploiement-manuel-sur-un-serveur-nu)
8. [Migrations et Gestion de la Base de Données](#8-migrations-et-gestion-de-la-base-de-données)
9. [Configuration du Reverse Proxy (Caddy)](#9-configuration-du-reverse-proxy-caddy)
10. [Sécurisation](#10-sécurisation)
11. [Surveillance et Health Checks](#11-surveillance-et-health-checks)
12. [Sauvegarde et Restauration](#12-sauvegarde-et-restauration)
13. [Dépannage Courant](#13-dépannage-courant)
14. [Procédure de Mise à Jour](#14-procédure-de-mise-à-jour)

---

## 1. Présentation

Ce document décrit les procédures de déploiement du backend **Smart SIEM CTU** — un système de Security Information and Event Management (SIEM) basé sur NestJS 11, Prisma 7, PostgreSQL, Elasticsearch 9, Redis et BullMQ.

### Composants principaux

| Composant | Technologie | Rôle |
|-----------|-------------|------|
| Application API | NestJS 11 (Node.js 20) | API REST, authentification, corrélation, SOAR, UEBA |
| Base opérationnelle | PostgreSQL 16 | Utilisateurs, règles, incidents, playbooks, audit |
| Stockage de logs | Elasticsearch 9.x | Indexation et recherche plein texte des logs normalisés |
| File d'attente | Redis 7 + BullMQ 5 | Traitement asynchrone de la normalisation des logs |
| Reverse Proxy | Caddy 2 | Routage TLS, proxy API / frontend, WebSocket |

---

## 2. Prérequis Techniques

### 2.1 Environnement de développement

| Logiciel | Version minimale |
|----------|------------------|
| Node.js | 20.x LTS |
| npm | 10.x |
| Docker Desktop | 24.x |
| Docker Compose | 2.20+ |
| Git | 2.40+ |

### 2.2 Environnement de production

| Logiciel | Version minimale | Notes |
|----------|------------------|-------|
| Node.js | 20.x LTS | Runtime applicatif |
| Docker | 24.x | Optionnel si déploiement conteneurisé |
| PostgreSQL | 16.x | Base de données principale |
| Redis | 7.x | File d'attente et cache |
| Elasticsearch | 9.4.x | Stockage et recherche de logs |
| Caddy | 2.x | Reverse proxy avec TLS automatique |
| Système | Linux (Ubuntu 22.04+, Debian 12+) | Recommandé pour la production |

### 2.3 Ressources recommandées (production)

| Ressource | Minimum | Recommandé |
|-----------|---------|------------|
| CPU | 4 cœurs | 8 cœurs |
| RAM | 8 Go | 16 Go |
| Stockage | 50 Go SSD | 200 Go+ SSD |
| Elasticsearch heap | 1 Go | 4 Go |

---

## 3. Architecture des Services

### 3.1 Dépendances entre services

```
[Internet / Collecteurs]
         │
         ▼
  ┌─────────────┐
  │   Caddy     │  (Ports 80/443 — Reverse Proxy + TLS)
  └──────┬──────┘
         │
    ┌────┴────┐
    │         │
    ▼         ▼
┌────────┐ ┌──────────┐
│ App    │ │ Frontend │  (API :3000 / Frontend :3001)
└───┬────┘ └──────────┘
    │
    ├──────────────┬──────────────┐
    ▼              ▼              ▼
┌─────────┐ ┌───────────┐ ┌──────────────┐
| Postgres│ │   Redis   │ │ Elasticsearch│
└─────────┘ └───────────┘ └──────────────┘
```

### 3.2 Ports utilisés

| Port | Service | Usage | Accessible depuis l'extérieur |
|------|---------|-------|-------------------------------|
| 80 | Caddy | HTTP | Oui |
| 443 | Caddy | HTTPS | Oui |
| 3000 | App (API) | API REST | Non (via Caddy) |
| 5432 | PostgreSQL | Base de données | Non (interne) |
| 6379 | Redis | Queue | Non (interne) |
| 9200 | Elasticsearch | API ES | Non (interne) |
| 5601 | Kibana | Debug logs | Optionnel |

---

## 4. Variables d'Environnement

### 4.1 Inventaire complet

```env
# ── Application ──
NODE_ENV=production
PORT=3000
CORS_ORIGINS=http://localhost:5173,https://votre-domaine.com

# ── Base de données (PostgreSQL) ──
DATABASE_URL=postgresql://siem:siem_password@postgres:5432/siem_db?schema=public

# ── Redis ──
REDIS_HOST=redis
REDIS_PORT=6379

# ── Elasticsearch ──
ELASTICSEARCH_URL=http://elasticsearch:9200

# ── Authentification ──
JWT_SECRET=<générez-une-clé-aléatoire-sécurisée>
JWT_EXPIRES_IN=24h

# ── Alertes Email ──
SMTP_HOST=smtp.gmail.com
SMTP_PORT=587
SMTP_USER=votre-email@gmail.com
SMTP_PASS=<mot-de-passe-d-application>
SMTP_FROM_NAME='Smart SIEM CTU'
ALERT_EMAIL_TO=admin@example.com
SIEM_DASHBOARD_URL=https://votre-domaine.com

# ── SOAR (Firewall) ──
SOAR_FIREWALL_PROVIDER=pfsense
PFSENSE_URL=http://192.168.1.1:8080
PFSENSE_API_KEY=<clé-api-pfsense>
PFSENSE_TIMEOUT=10000
PFSENSE_REJECT_UNAUTHORIZED=false
```

### 4.2 Génération d'un JWT_SECRET sécurisé

```bash
# Méthode 1 : OpenSSL
openssl rand -base64 64

# Méthode 2 : Node.js
node -e "console.log(require('crypto').randomBytes(48).toString('hex'))"
```

### 4.3 Bonnes pratiques

- Ne **jamais** committer le fichier `.env` dans le dépôt Git (déjà exclu via `.gitignore`).
- Utiliser un gestionnaire de secrets (HashiCorp Vault, AWS Secrets Manager, ou Bitwarden) pour la production.
- En Docker Compose, préférer un fichier `.env` à la racine ou un fichier dédié passé via `--env-file`.
- Restreindre les origines CORS à la liste exacte des domaines autorisés.

---

## 5. Déploiement en Développement Local

### 5.1 Infrastructure locale (PostgreSQL, Redis, Elasticsearch)

```bash
# Démarrer uniquement les services d'infrastructure
docker compose up -d postgres redis elasticsearch

# Vérifier que tout est opérationnel
docker compose ps
```

### 5.2 Application

```bash
# 1. Installer les dépendances
npm install

# 2. Générer le client Prisma
npx prisma generate

# 3. Créer le fichier .env
cat > .env << EOF
DATABASE_URL="postgresql://siem:siem_password@localhost:5432/siem_db?schema=public"
REDIS_HOST=localhost
REDIS_PORT=6379
ELASTICSEARCH_URL=http://localhost:9200
JWT_SECRET=dev-secret-change-in-production
CORS_ORIGINS=http://localhost:5173
SMTP_HOST=smtp.gmail.com
SMTP_PORT=587
SMTP_USER=
SMTP_PASS=
ALERT_EMAIL_TO=admin@example.com
EOF

# 4. Appliquer les migrations Prisma
npx prisma migrate dev

# 5. (Optionnel) Générer une clé API collecteur
npm run api-key:generate

# 6. (Optionnel) Amorcer les règles de corrélation MITRE ATT&CK
npm run seed:rules

# 7. Démarrer l'application en mode développement
npm run start:dev
```

L'API est alors accessible à l'adresse `http://localhost:3000/api/v1` et la documentation Swagger à `http://localhost:3000/api/docs`.

### 5.3 Scripts utiles

```bash
# Mode développement avec rechargement à chaud
npm run start:dev

# Mode debug
npm run start:debug

# Compilation TypeScript
npm run build

# Tests unitaires
npm run test

# Tests d'intégration
npm run test:e2e

# Couverture de code
npm run test:cov

# Linter
npm run lint

# Générateur de logs synthétiques (pour tests)
tsx scripts/generate-synthetic-logs.ts
```

---

## 6. Déploiement avec Docker Compose (Stack Complète)

### 6.1 Préparation

```bash
# 1. Cloner le dépôt
git clone <url-du-depot> siem-backend
cd siem-backend

# 2. Configurer les variables d'environnement
# Créer un fichier .env à la racine (référencé automatiquement par Docker Compose)
```

### 6.2 Lancement de la stack complète

```bash
# Construction et démarrage de tous les services
docker compose up --build -d

# Surveiller les logs
docker compose logs -f

# Vérifier l'état des services
docker compose ps
```

### 6.3 Services démarrés

La commande `docker compose up --build -d` lance les services suivants :

| Service | Image | Dépend de | Démarrage |
|---------|-------|-----------|-----------|
| `postgres` | `postgres:latest` | — | Doit être healthy avant `app` |
| `redis` | `redis:7-alpine` | — | Doit être healthy avant `app` |
| `elasticsearch` | `elasticsearch:9.4.2` | — | Démarrage lent (~30s) |
| `kibana` | `kibana:9.4.3` | elasticsearch | Debug logs uniquement |
| `app` | build local | postgres, redis, elasticsearch | Dernier service |
| `frontend` | `cloudx02/siem-frontend:0.0.2` | app | Après l'API |
| `caddy` | `caddy:2-alpine` | app, frontend | Dernier |

### 6.4 Ordre de démarrage et health checks

Docker Compose est configuré pour attendre que PostgreSQL et Redis soient en bonne santé avant de démarrer l'application. Elasticsearch démarre sans attendre son health check pour éviter un blocage.

Si un health check échoue après `retries` tentatives, le conteneur est marqué comme `unhealthy` mais ne stoppe pas la stack. Vérifiez manuellement :

```bash
docker compose ps
# Les services doivent afficher "Up" ou "healthy"
```

### 6.5 Construction de l'image Docker étape par étape

Le Dockerfile utilise une **construction multi-stages** :

1. **Stage 1 — Build** : Node 20, installation des dépendances, génération Prisma, compilation TypeScript.
2. **Stage 2 — Production** : Node 20-alpine, copie de l'artefact compilé, patch Prisma pour compatibilité CJS, configuration de l'entrée.

```bash
# Construction manuelle (sans Docker Compose)
docker build -t siem-backend:latest .

# Test de l'image localement
docker run --rm -p 3000:3000 --env-file .env siem-backend:latest
```

### 6.6 Services optionnels

- **Kibana** : Accessible sur `http://localhost:5601`. Utile pour le debug des index Elasticsearch. Ne pas exposer en production sans authentification.
- **Frontend** : L'image pré-construite est utilisée. Pour personnaliser, construire depuis le dépôt frontend avec `VITE_API_URL` pointant vers le reverse proxy.

---

## 7. Déploiement Manuel sur un Serveur Nu

### 7.1 Installation des dépendances système (Ubuntu/Debian)

```bash
# Mise à jour du système
sudo apt update && sudo apt upgrade -y

# Installation de Node.js 20 LTS
curl -fsSL https://deb.nodesource.com/setup_20.x | sudo -E bash -
sudo apt install -y nodejs git

# Installation de Docker et Docker Compose
curl -fsSL https://get.docker.com | sh
sudo usermod -aG docker $USER
# Déconnectez-vous et reconnectez-vous pour appliquer les droits

# Vérification
node --version
npm --version
docker --version
```

### 7.2 Déploiement avec Docker Compose (recommandé)

```bash
# 1. Cloner le projet
git clone <url-du-repo> /opt/siem-backend
cd /opt/siem-backend

# 2. Créer le fichier d'environnement
cp .env.example .env
# Éditer .env avec les valeurs de production (voir section 4)

# 3. Modifier docker-compose.yml pour la production :
#    - Remplacer les mots de passe par défaut
#    - Ajuster CORS_ORIGINS avec le domaine réel
#    - Changer JWT_SECRET

# 4. Lancer la stack
docker compose up --build -d

# 5. Vérifier
docker compose ps
curl http://localhost:3000/api/v1

# 6. Créer le premier utilisateur admin
# (via l'API /auth/register puis promouvoir via /admin/users)
```

### 7.3 Déploiement sans Docker (Node.js natif)

Cette approche est déconseillée pour la production mais peut être utilisée pour du prototypage.

```bash
# 1. Installer PostgreSQL 16
sudo apt install -y postgresql-16
sudo systemctl enable --now postgresql

# 2. Créer la base de données
sudo -u postgres psql -c "CREATE USER siem WITH PASSWORD 'siem_password';"
sudo -u postgres psql -c "CREATE DATABASE siem_db OWNER siem;"

# 3. Installer Redis
sudo apt install -y redis-server
sudo systemctl enable --now redis-server

# 4. Installer Elasticsearch 9.x (voir doc officielle Elastic)

# 5. Cloner et configurer l'application
git clone <url-du-repo> /opt/siem-backend
cd /opt/siem-backend
npm install --production
npx prisma generate
npx prisma migrate deploy

# 6. Démarrer avec PM2 (process manager)
npm install -g pm2
pm2 start dist/main.js --name siem-backend
pm2 save
pm2 startup
```

### 7.4 Configuration systemd (déploiement natif)

```ini
# /etc/systemd/system/siem-backend.service
[Unit]
Description=Smart SIEM CTU Backend
After=network.target postgresql.service redis-server.service
Requires=postgresql.service redis-server.service

[Service]
Type=simple
User=siem
WorkingDirectory=/opt/siem-backend
ExecStart=/usr/bin/node dist/main
Restart=always
RestartSec=10
Environment=NODE_ENV=production
Environment=PORT=3000
Environment=DATABASE_URL=postgresql://siem:...
Environment=REDIS_HOST=localhost
Environment=REDIS_PORT=6379
Environment=ELASTICSEARCH_URL=http://localhost:9200
Environment=JWT_SECRET=<secret>
Environment=CORS_ORIGINS=https://votre-domaine.com

[Install]
WantedBy=multi-user.target
```

```bash
sudo systemctl daemon-reload
sudo systemctl enable --now siem-backend
sudo systemctl status siem-backend
```

---

## 8. Migrations et Gestion de la Base de Données

### 8.1 Commandes Prisma

```bash
# Générer le client Prisma après modification du schéma
npx prisma generate

# Créer une migration après modification du schéma
npx prisma migrate dev --name description_de_la_modification

# Appliquer les migrations en production
npx prisma migrate deploy

# Vérifier l'état des migrations
npx prisma migrate status

# Afficher l'historique des migrations
npx prisma migrate diff
```

### 8.2 Flux de déploiement d'une migration en production

```bash
# Étape 1 : Arrêter l'application ou s'assurer qu'elle tolère les interruptions
docker compose stop app

# Étape 2 : Appliquer les migrations
npx prisma migrate deploy

# Étape 3 : Redémarrer l'application
docker compose start app
```

### 8.3 Amorçage initial

```bash
# Générer une clé API pour les collecteurs
npm run api-key:generate

# Amorcer les règles de corrélation MITRE ATT&CK
npm run seed:rules
```

---

## 9. Configuration du Reverse Proxy (Caddy)

### 9.1 Fichier de configuration (Caddyfile)

Le projet inclut un `Caddyfile` à la racine qui configure :

- **Routage TLS automatique** via Let's Encrypt
- **Proxy inverse** vers l'API backend sur `/api/*`
- **Proxy WebSocket** sur `/ws/*`
- **Proxy frontend** pour toutes les autres routes
- **Headers de sécurité** (HSTS, CSP, X-Frame-Options)
- **Compression Gzip**

### 9.2 Vérification de la configuration

```bash
# Tester le fichier Caddyfile
docker run --rm -v $(pwd)/Caddyfile:/etc/caddy/Caddyfile caddy:2-alpine caddy validate --config /etc/caddy/Caddyfile
```

### 9.3 Déploiement en production (TLS)

Pour que Let's Encrypt fonctionne, le DNS doit pointer vers le serveur. Caddy gère automatiquement la délivrance et le renouvellement des certificats.

```caddy
# Exemple pour un domaine personnalisé
https://siem.example.com {
    # Le TLS est automatique : Caddy obtient et renouvelle les certificats
    header {
        Strict-Transport-Security "max-age=31536000; includeSubDomains; preload"
        X-Content-Type-Options "nosniff"
        X-Frame-Options "DENY"
        Referrer-Policy "strict-origin-when-cross-origin"
    }

    encode gzip

    handle /api/* {
        reverse_proxy app:3000
    }

    handle /ws/* {
        reverse_proxy app:3000
    }

    handle {
        reverse_proxy frontend:3001
    }
}
```

### 9.4 Alternative : Nginx

```nginx
# /etc/nginx/sites-available/siem
server {
    listen 80;
    server_name siem.example.com;
    return 301 https://$server_name$request_uri;
}

server {
    listen 443 ssl http2;
    server_name siem.example.com;

    ssl_certificate /etc/letsencrypt/live/siem.example.com/fullchain.pem;
    ssl_certificate_key /etc/letsencrypt/live/siem.example.com/privkey.pem;

    # API
    location /api/ {
        proxy_pass http://127.0.0.1:3000;
        proxy_set_header Host $host;
        proxy_set_header X-Real-IP $remote_addr;
        proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
        proxy_set_header X-Forwarded-Proto $scheme;
    }

    # WebSocket
    location /ws/ {
        proxy_pass http://127.0.0.1:3000;
        proxy_http_version 1.1;
        proxy_set_header Upgrade $http_upgrade;
        proxy_set_header Connection "upgrade";
    }

    # Frontend
    location / {
        proxy_pass http://127.0.0.1:5173;
    }
}
```

---

## 10. Sécurisation

### 10.1 Recommandations générales

| Domaine | Recommandation |
|---------|----------------|
| JWT_SECRET | Générer avec `openssl rand -base64 64` — ne jamais partager |
| Mots de passe | Tous les mots de passe par défaut (`siem_password`) doivent être changés |
| TLS | Forcer HTTPS via Caddy (Let's Encrypt automatique) |
| CORS | Restreindre `CORS_ORIGINS` aux seuls domaines autorisés |
| Elasticsearch | Activer `xpack.security.enabled=true` en production |
| PostgreSQL | Configurer `pg_hba.conf` pour n'autoriser que les connexions depuis l'application |
| Réseau | Ne pas exposer PostgreSQL, Redis ou Elasticsearch sur des ports publics |
| Updates | Maintenir Node.js, npm et les dépendances à jour via `npm audit` |

### 10.2 Mise en production checklist

- [ ] Changer tous les mots de passe par défaut (PostgreSQL, Redis)
- [ ] Générer et configurer un JWT_SECRET aléatoire
- [ ] Restreindre CORS_ORIGINS au(x) domaine(s) réel(s)
- [ ] Ajouter SMTP avec un mot de passe d'application (Gmail) ou un service dédié
- [ ] Configurer PFSENSE_API_KEY avec une clé réelle
- [ ] Activer le TLS via Caddy (Let's Encrypt)
- [ ] Vérifier que les health checks fonctionnent
- [ ] Configurer les sauvegardes automatiques (voir section 12)
- [ ] Supprimer Kibana de l'exposition publique (ou ajouter une authentification)

### 10.3 Gestion des secrets en production

Pour ne pas exposer les secrets dans `docker-compose.yml`, utiliser un fichier `.env` externe :

```bash
# .env.production (ne PAS committer)
DATABASE_URL=postgresql://siem:password-sécurisé@postgres:5432/siem_db
JWT_SECRET=<secret-généré>
SMTP_PASS=<mot-de-passe-application>
PFSENSE_API_KEY=<clé-api>

# Référencement dans docker-compose.yml
# L'environnement est déjà configuré pour lire depuis le fichier .env
```

Ou mieux, utiliser Docker secrets :

```yaml
# docker-compose.yml (extrait)
app:
  secrets:
    - db_password
    - jwt_secret

secrets:
  db_password:
    file: ./secrets/db_password.txt
  jwt_secret:
    file: ./secrets/jwt_secret.txt
```

### 10.4 RBAC (Role-Based Access Control)

L'API implémente trois rôles :

| Rôle | Permissions |
|------|-------------|
| `READER` | Consultation des dashboards, incidents, logs, règles |
| `ANALYST` | Tout ce que READER peut faire + mise à jour des incidents, exécution de playbooks |
| `ADMIN` | Tout ce que ANALYST peut faire + gestion des utilisateurs, CRUD règles, configuration de rétention |

Attribuer le rôle ADMIN uniquement aux comptes qui en ont strictement besoin.

---

## 11. Surveillance et Health Checks

### 11.1 Health Check du conteneur

Le Dockerfile inclut un health check qui interroge la route Swagger toutes les 30 secondes :

```
HEALTHCHECK --interval=30s --timeout=5s --start-period=15s --retries=3 \
  CMD wget --no-verbose --tries=1 --spider http://localhost:3000/api/docs-json || exit 1
```

### 11.2 Vérification manuelle des services

```bash
# API
curl -s http://localhost:3000/api/docs-json | head -c 100

# PostgreSQL
docker exec siem-postgres pg_isready -U siem -d siem_db

# Redis
docker exec siem-redis redis-cli ping

# Elasticsearch
curl -s http://localhost:9200/_cluster/health

# Logs de l'application
docker compose logs --tail=50 app
```

### 11.3 Points de terminaison de monitoring

| Endpoint | Usage |
|----------|-------|
| `/api/docs-json` | Spécification OpenAPI — sert de health check |
| `/api/v1` | Route racine de l'API — retourne 200 si l'app tourne |

### 11.4 Supervision avec Prometheus (optionnel)

Bien que non intégré nativement, l'application peut être surveillée via :

- **Resource usage** : `docker stats` pour chaque conteneur
- **Logs centralisés** : `docker compose logs --tail=100 -f`
- **Métriques système** : Coupler avec `cAdvisor` + `Prometheus` + `Grafana`

### 11.5 Alertes SMTP

L'application envoie des emails d'alerte via Nodemailer lorsque des incidents de haute sévérité sont détectés ou lorsqu'un playbook SOAR échoue. Configurer les variables SMTP pour activer cette fonctionnalité.

---

## 12. Sauvegarde et Restauration

### 12.1 PostgreSQL

```bash
# Sauvegarde
docker exec -t siem-postgres pg_dump -U siem siem_db > backup_$(date +%Y%m%d_%H%M%S).sql

# Restauration
cat backup_20260709_120000.sql | docker exec -i siem-postgres psql -U siem siem_db

# Sauvegarde automatisée (cron)
# Ajouter dans crontab : 0 2 * * * cd /opt/siem-backend && ./scripts/backup-db.sh
```

Script de sauvegarde automatisée :

```bash
#!/bin/bash
# scripts/backup-db.sh
BACKUP_DIR="/opt/backups/postgres"
mkdir -p "$BACKUP_DIR"
TIMESTAMP=$(date +%Y%m%d_%H%M%S)
docker exec -t siem-postgres pg_dump -U siem siem_db | gzip > "$BACKUP_DIR/siem_$TIMESTAMP.sql.gz"
# Supprimer les backups de plus de 30 jours
find "$BACKUP_DIR" -name "*.sql.gz" -mtime +30 -delete
```

### 12.2 Elasticsearch

```bash
# Sauvegarde snapshot (nécessite un repository configuré)
# Voir la documentation Elasticsearch pour la configuration du snapshot repository

# Alternative : réindexation vers un cluster secondaire
curl -X POST "http://localhost:9200/_reindex" -H 'Content-Type: application/json' -d'
{
  "source": { "index": "ctu-logs-*" },
  "dest":   { "index": "backup-ctu-logs" }
}'
```

### 12.3 Redis

```bash
# Sauvegarde RDB (fichier dump.rdb déjà persistant via le volume docker)
docker exec siem-redis redis-cli SAVE

# Restauration : arrêter Redis, copier le dump.rdb, redémarrer
```

### 12.4 Stratégie de rétention recommandée

| Type | Fréquence | Rétention |
|------|-----------|-----------|
| PostgreSQL | Quotidienne | 30 jours |
| Elasticsearch | Selon ILM policy | 30 jours (configurable via `/admin/retention`) |
| Redis | Automatique (RDB) | 7 jours |
| Logs d'application | Selon politique de rétention SIEM | Configurable via l'API Admin |

---

## 13. Dépannage Courant

### 13.1 L'application ne démarre pas

**Symptômes et causes possibles :**

| Symptôme | Cause probable | Solution |
|----------|---------------|----------|
| `ECONNREFUSED` sur PostgreSQL | PostgreSQL pas encore prêt | Attendre le health check, vérifier `docker compose ps` |
| `Error: Prisma schema validation` | `prisma generate` non exécuté | Exécuter `npx prisma generate` |
| `listen EADDRINUSE :::3000` | Port 3000 déjà occupé | Changer PORT ou tuer le processus existant |
| `Cannot find module '@prisma/client'` | Dépendances manquantes | Exécuter `npm install` puis `npx prisma generate` |

### 13.2 Problèmes de connexion Elasticsearch

```bash
# Vérifier que le service tourne
curl -s http://localhost:9200/_cluster/health | jq .

# Réponse attendue : {"status":"green","cluster_name":"docker-cluster",...}

# Si le cluster est rouge ou jaune
curl -s http://localhost:9200/_cat/indices?v

# Vérifier les logs du conteneur
docker compose logs elasticsearch --tail=50
```

### 13.3 Problèmes de migration Prisma

```bash
# Vérifier l'état des migrations
npx prisma migrate status

# Si une migration est en conflit :
# Option 1 : Réinitialiser la base (⚠️ perte de données)
npx prisma migrate reset

# Option 2 : Marquer manuellement une migration comme appliquée
npx prisma migrate resolve --applied <nom_de_la_migration>
```

### 13.4 Problèmes de WebSocket

```bash
# Vérifier que le proxy Caddy transmet correctement les headers
curl -H "Upgrade: websocket" -H "Connection: Upgrade" \
  -H "Host: localhost" \
  http://localhost:80/ws/
```

### 13.5 Problèmes de mémoire Elasticsearch

Si Elasticsearch échoue avec `OutOfMemoryError` :

```yaml
# Dans docker-compose.yml, ajuster ES_JAVA_OPTS
environment:
  - ES_JAVA_OPTS=-Xms2g -Xmx2g  # Augmenter selon la RAM disponible
```

La limite recommandée pour le heap Elasticsearch est de 50% de la RAM totale du conteneur, sans dépasser 32 Go.

### 13.6 Logs utiles pour le diagnostic

```bash
# Logs en temps réel de l'application
docker compose logs -f app

# 100 dernières lignes de tous les services
docker compose logs --tail=100

# Logs d'un service spécifique avec timestamp
docker compose logs -f --timestamps postgres
```

---

## 14. Procédure de Mise à Jour

### 14.1 Mise à jour du code source

```bash
# 1. Pull des dernières modifications
cd /opt/siem-backend
git pull origin main

# 2. Mettre à jour les dépendances (si package.json a changé)
npm install

# 3. Générer le client Prisma (si schema.prisma a changé)
npx prisma generate

# 4. Appliquer les nouvelles migrations (si présentes)
npx prisma migrate deploy

# 5. Reconstruire l'image Docker
docker compose build app

# 6. Redémarrer l'application
docker compose up -d app
```

### 14.2 Rollback

```bash
# Revenir à une version précédente du code
git checkout <commit-précédent>
npm install
docker compose build app
docker compose up -d app

# Rollback de base de données (si une migration a été appliquée par erreur)
npx prisma migrate reset  # ⚠️ Réinitialise la base (perte de données hors seed)
# OU
npx prisma migrate resolve --rolled-back <nom_migration>
```

### 14.3 Mise à jour des images Elasticsearch

Elasticsearch et Kibana doivent être mis à jour en tandem avec des versions compatibles. Consulter la [matrice de compatibilité Elastic](https://www.elastic.co/support/matrix).

---

## Annexe A : Résumé des Commandes Essentielles

```bash
# Développement
npm install                  # Installer les dépendances
npx prisma generate          # Générer le client Prisma
npx prisma migrate dev       # Créer/appliquer les migrations (dev)
npm run start:dev            # Démarrer en mode développement

# Production (Docker)
docker compose up --build -d  # Construire et démarrer la stack
docker compose logs -f        # Suivre les logs
docker compose stop app       # Arrêter l'application uniquement
docker compose down           # Arrêter et supprimer les conteneurs

# Maintenance
npx prisma migrate deploy     # Appliquer les migrations (production)
npm run api-key:generate      # Créer une clé API collecteur
npm run seed:rules            # Amorcer les règles MITRE

# Diagnostic
docker compose ps             # État des conteneurs
docker compose logs --tail=50 # Dernières lignes de logs
docker stats                  # Utilisation des ressources
```

---

## Annexe B : Fichier `.env.example`

```env
# ── Application ──
NODE_ENV=production
PORT=3000
CORS_ORIGINS=http://localhost:5173

# ── Base de données ──
DATABASE_URL=postgresql://siem:siem_password@postgres:5432/siem_db?schema=public

# ── Redis ──
REDIS_HOST=redis
REDIS_PORT=6379

# ── Elasticsearch ──
ELASTICSEARCH_URL=http://elasticsearch:9200

# ── JWT ──
JWT_SECRET=change-this-to-a-secure-random-string-in-production

# ── SMTP (Alertes Email) ──
SMTP_HOST=smtp.gmail.com
SMTP_PORT=587
SMTP_USER=
SMTP_PASS=
SMTP_FROM_NAME=Smart SIEM CTU
ALERT_EMAIL_TO=admin@example.com
SIEM_DASHBOARD_URL=http://localhost:5173

# ── SOAR (Firewall pfsense) ──
SOAR_FIREWALL_PROVIDER=pfsense
PFSENSE_URL=http://192.168.1.1:8080
PFSENSE_API_KEY=
PFSENSE_TIMEOUT=10000
PFSENSE_REJECT_UNAUTHORIZED=false
```

---

> **Maintenu par** : L'équipe Smart SIEM CTU  
> **Projet** : [siem-backend](../README.md)  
> **Documentation API** : Swagger disponible sur `/api/docs` une fois l'application démarrée
