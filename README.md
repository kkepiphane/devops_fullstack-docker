# Architecture Docker Full-Stack Production-Ready

Architecture complète et robuste pour une application web full-stack containerisée avec FastAPI, React, PostgreSQL, et un stack d'observabilité complet.

## Table des Matières

- [Vue d'ensemble](#vue-densemble)
- [Stack Technique](#stack-technique)
- [Architecture](#architecture)
- [Prérequis](#prérequis)
- [Installation Rapide](#installation-rapide)
- [Configuration](#configuration)
- [Utilisation](#utilisation)
- [Déploiement](#déploiement)
- [Sécurité](#sécurité)
- [Monitoring](#monitoring)
- [Maintenance](#maintenance)
- [Bonnes Pratiques](#bonnes-pratiques)

## Vue d'ensemble

Cette architecture offre:

- **Séparation des responsabilités** avec Nginx comme reverse proxy
- **Scalabilité horizontale** avec support Kubernetes
- **Sécurité robuste** avec JWT, HTTPS, headers de sécurité
- **Observabilité complète** avec Prometheus + Grafana
- **CI/CD automatisé** avec GitHub Actions
- **Cache distribué** avec Redis
- **Tâches asynchrones** avec Celery
- **Backups automatisés** de la base de données
- **Tests automatisés** backend et frontend
- **Multi-environnements** (dev, staging, production)

## Stack Technique

### Backend
- **FastAPI** 0.109+ - Framework Python moderne et performant
- **SQLAlchemy** 2.0+ - ORM avec support async
- **Alembic** - Migrations de base de données
- **Pydantic** 2.0+ - Validation des données
- **Python-JOSE** - Gestion JWT
- **Passlib** - Hashing sécurisé des mots de passe

### Frontend
- **React** 18+ - Library UI moderne
- **Axios** - Client HTTP
- **React Router** - Navigation SPA
- **Nginx** - Serveur web pour le build

### Infrastructure
- **PostgreSQL** 15 - Base de données relationnelle
- **Redis** 7 - Cache et message broker
- **Nginx** 1.25+ - Reverse proxy et load balancer
- **Docker** & **Docker Compose** - Containerisation
- **Celery** - Tâches asynchrones
- **Prometheus** - Collecte de métriques
- **Grafana** - Visualisation et dashboards

## Architecture

```
┌─────────────────────────────────────────────────────────┐
│                      Internet                            │
└────────────────────┬────────────────────────────────────┘
                     │
                ┌────▼─────┐
                │  Nginx   │ :80/:443
                │  Proxy   │ Rate Limiting, SSL, Compression
                └────┬─────┘
                     │
      ┌──────────────┼──────────────┐
      │              │              │
 ┌────▼─────┐  ┌────▼─────┐  ┌────▼─────┐
 │  React   │  │ FastAPI  │  │ Grafana  │
 │:3000 SPA │  │:8000 API │  │:3001 UI  │
 └──────────┘  └────┬─────┘  └──────────┘
                    │
      ┌─────────────┼─────────────┐
      │             │             │
 ┌────▼─────┐ ┌────▼─────┐ ┌────▼─────┐
 │PostgreSQL│ │  Redis   │ │Prometheus│
 │:5432 DB  │ │:6379 KV  │ │:9090 TSB │
 └──────────┘ └────┬─────┘ └──────────┘
                   │
              ┌────▼─────┐
              │  Celery  │
              │  Worker  │
              └──────────┘
```

## Prérequis

- **Docker** 24.0+
- **Docker Compose** 2.20+
- **Make** (optionnel mais recommandé)
- **Git**
- Au moins **4GB RAM** disponible
- **Ports disponibles**: 80, 443, 3000, 5432, 6379, 8000, 9090, 3001

## Installation Rapide

### 1. Cloner le repository

```bash
git clone https://github.com/kkepiphane/devops_fullstack-docker.git
cd devops_fullstack-docker
```

### 2. Configuration initiale

```bash
# Initialiser les variables d'environnement
make init

# Ou manuellement
cp .env.example .env
```

### 3. Éditer `.env` avec vos valeurs

```bash
nano .env  # Modifier au minimum les mots de passe
```

**IMPORTANT**: Changez les valeurs suivantes:
- `DB_PASSWORD`
- `REDIS_PASSWORD`
- `SECRET_KEY` (générer avec `openssl rand -hex 32`)
- `GRAFANA_PASSWORD`

### 4. Lancer l'application

```bash
# Setup complet automatique
make setup

# Ou étape par étape
make dev-build
make dev-up
make migrate
```

### 5. Accéder aux services

- **Frontend**: http://localhost:3000
- **Backend API**: http://localhost:8000
- **API Docs (Swagger)**: http://localhost:8000/docs
- **Grafana**: http://localhost:3001 (admin / mot de passe du .env)
- **Prometheus**: http://localhost:9090

## Configuration

### Variables d'Environnement

Toutes les variables sont documentées dans `.env.example`. Principales catégories:

#### Application
```env
ENVIRONMENT=development|production
LOG_LEVEL=DEBUG|INFO|WARNING|ERROR
```

#### Base de Données
```env
DB_USER=postgres
DB_PASSWORD=your_secure_password
DB_NAME=app_db
```

#### Sécurité
```env
SECRET_KEY=your_secret_key_32_chars_minimum
ALGORITHM=HS256
ACCESS_TOKEN_EXPIRE_MINUTES=30
```

### Configuration Multi-Environnements

#### Développement
```bash
docker-compose -f docker-compose.yml -f docker-compose.dev.yml up
# Ou
make dev-up
```

#### Production
```bash
docker-compose -f docker-compose.yml -f docker-compose.prod.yml up -d
# Ou
make prod-up
```

## Utilisation

### Commandes Makefile

Le `Makefile` simplifie toutes les opérations:

```bash
# Voir toutes les commandes disponibles
make help

# Développement
make dev-up          # Lancer en mode dev
make dev-down        # Arrêter
make logs            # Voir les logs
make logs-backend    # Logs du backend uniquement

# Base de données
make migrate         # Appliquer les migrations
make migrate-create  # Créer une nouvelle migration
make db-shell        # Shell PostgreSQL
make backup          # Backup de la DB
make restore         # Restaurer un backup

# Tests
make test            # Tests backend
make test-cov        # Tests avec coverage
make test-frontend   # Tests frontend

# Production
make prod-build      # Build images production
make prod-up         # Lancer en production
make prod-down       # Arrêter production

# Maintenance
make clean           # Nettoyer conteneurs et volumes
make health          # Vérifier la santé des services
```

### Migrations de Base de Données

```bash
# Créer une nouvelle migration
make migrate-create
# Saisir: "add_users_table"

# Appliquer les migrations
make migrate

# Revenir en arrière
docker-compose exec backend alembic downgrade -1
```

### Tâches Celery

```python
# backend/app/tasks/example.py
from app.tasks.celery_app import celery_app

@celery_app.task
def send_email(to: str, subject: str, body: str):
    # Logique d'envoi d'email
    pass

# Utilisation dans le code
from app.tasks.example import send_email
send_email.delay("user@example.com", "Welcome", "Hello!")
```

## Déploiement

### Déploiement sur Serveur VPS

#### 1. Préparer le serveur

```bash
# Sur le serveur
sudo apt update && sudo apt upgrade -y
sudo apt install docker.io docker-compose git make -y
sudo systemctl enable docker
sudo usermod -aG docker $USER
```

#### 2. Cloner et configurer

```bash
cd /opt
git clone https://github.com/votre-org/devops_fullstack-docker.git app
cd app
cp .env.example .env
nano .env  # Configurer pour production
```

#### 3. Configurer SSL avec Let's Encrypt

```bash
# Installer certbot
sudo apt install certbot

# Obtenir le certificat
sudo certbot certonly --standalone -d yourdomain.com -d www.yourdomain.com

# Copier les certificats
sudo cp /etc/letsencrypt/live/yourdomain.com/fullchain.pem nginx/ssl/
sudo cp /etc/letsencrypt/live/yourdomain.com/privkey.pem nginx/ssl/
```

#### 4. Démarrer en production

```bash
make prod-build
make prod-up
make migrate
```

#### 5. Configurer le renouvellement auto SSL

```bash
# Ajouter au crontab
sudo crontab -e

# Ajouter cette ligne
0 0 * * 0 certbot renew --quiet && docker-compose restart nginx
```

### Déploiement sur Cloud (AWS/GCP/Azure)

#### Option 1: VM avec Docker

Suivre les étapes VPS ci-dessus.

#### Option 2: Kubernetes

```bash
# Générer les manifests Kubernetes
# (nécessite kompose)
kompose convert

# Appliquer
kubectl apply -f k8s/
```

### CI/CD avec GitHub Actions

Le pipeline `.github/workflows/ci-cd.yml` automatise:

1. **Tests** - Backend et Frontend
2. **Linting** - Qualité du code
3. **Security Scan** - Vulnérabilités
4. **Build** - Images Docker
5. **Deploy** - Staging puis Production

#### Configuration des secrets GitHub

```bash
Settings → Secrets → Actions → New repository secret
```

Secrets requis:
- `STAGING_HOST`, `STAGING_USER`, `STAGING_SSH_KEY`
- `PROD_HOST`, `PROD_USER`, `PROD_SSH_KEY`
- `SLACK_WEBHOOK` (optionnel)

## Sécurité

### Checklist de Sécurité Production

- [x] **Mots de passe forts** pour tous les services
- [x] **SECRET_KEY** unique et complexe
- [x] **HTTPS/TLS** avec certificats valides
- [x] **Rate limiting** sur Nginx
- [x] **Headers de sécurité** (HSTS, CSP, X-Frame-Options)
- [x] **Utilisateurs non-root** dans les conteneurs
- [x] **Firewall** configuré (UFW/iptables)
- [x] **Backups** automatisés et testés
- [x] **Logs** centralisés et monitorés
- [x] **Scans de vulnérabilités** réguliers

### Configuration du Firewall

```bash
# UFW (Ubuntu)
sudo ufw allow 22/tcp   # SSH
sudo ufw allow 80/tcp   # HTTP
sudo ufw allow 443/tcp  # HTTPS
sudo ufw enable
```

### Scan de Sécurité

```bash
# Scanner les images Docker
make security-scan

# Ou avec Trivy directement
docker run --rm -v /var/run/docker.sock:/var/run/docker.sock \
  aquasec/trivy image fullstack_backend:latest
```

## Monitoring

### Prometheus

- **URL**: http://localhost:9090
- **Métriques collectées**:
  - Requêtes HTTP (count, duration)
  - Santé des services
  - Métriques système (CPU, RAM, disque)
  - Métriques applicatives custom

### Grafana

- **URL**: http://localhost:3001
- **Login**: admin / (voir GRAFANA_PASSWORD dans .env)

#### Dashboards pré-configurés:
1. **Application Overview** - Vue d'ensemble
2. **API Performance** - Latence, throughput
3. **Infrastructure** - CPU, mémoire, disque
4. **Database** - Connexions, queries, cache hit rate

#### Créer un dashboard custom:

1. Se connecter à Grafana
2. Configuration → Data Sources → Add Prometheus
3. Create → Dashboard → Add panel
4. Configurer les queries PromQL

### Alertes

Configurer des alertes dans `monitoring/prometheus/alert_rules.yml`:

```yaml
groups:
  - name: api_alerts
    rules:
      - alert: HighErrorRate
        expr: rate(http_requests_total{status=~"5.."}[5m]) > 0.05
        for: 5m
        labels:
          severity: critical
        annotations:
          summary: "High error rate detected"
```

## Maintenance

### Backups

#### Backup Manuel

```bash
make backup
# Fichier créé dans: backups/backup_YYYYMMDD_HHMMSS.sql
```

#### Backup Automatique

En production, le service `backup` dans `docker-compose.prod.yml` effectue des backups quotidiens.

#### Restauration

```bash
make restore
# Choisir le fichier de backup à restaurer
```

### Mise à jour de l'Application

```bash
# 1. Sauvegarder la DB
make backup

# 2. Mettre à jour le code
git pull origin main

# 3. Rebuilder les images
make prod-build

# 4. Redémarrer avec les nouvelles images
make prod-up

# 5. Appliquer les migrations
make migrate

# 6. Vérifier la santé
make health
```

### Logs

```bash
# Tous les logs
make logs

# Service spécifique
make logs-backend
make logs-frontend
make logs-nginx

# Logs avec tail
docker-compose logs -f --tail=100 backend

# Logs JSON structurés
docker-compose logs backend | jq
```

### Nettoyage

```bash
# Nettoyer conteneurs et volumes
make clean

# Nettoage complet (images, cache)
make clean-all

# Nettoyer les images Docker non utilisées
docker system prune -a
```


- [FastAPI](https://fastapi.tiangolo.com/)
- [React](https://reactjs.org/)
- [Docker](https://www.docker.com/)
- [Prometheus](https://prometheus.io/)

## Ressources

- [Documentation FastAPI](https://fastapi.tiangolo.com/)
- [Docker Best Practices](https://docs.docker.com/develop/dev-best-practices/)
- [PostgreSQL Documentation](https://www.postgresql.org/docs/)
- [Nginx Configuration Guide](https://nginx.org/en/docs/)
- [Prometheus Querying](https://prometheus.io/docs/prometheus/latest/querying/basics/)

---

Si ce projet vous aide, n'hésitez pas à lui donner une étoile !