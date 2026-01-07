#!/bin/bash

# ==============================================================================
# Script de Démarrage Rapide - Full-Stack Application
# ==============================================================================

set -e  # Arrêter en cas d'erreur

# Couleurs pour l'output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

# Fonction pour afficher des messages colorés
info() {
    echo -e "${BLUE}ℹ${NC} $1"
}

success() {
    echo -e "${GREEN}✓${NC} $1"
}

warning() {
    echo -e "${YELLOW}⚠${NC} $1"
}

error() {
    echo -e "${RED}✗${NC} $1"
}

# Banner
echo ""
echo -e "${BLUE}╔═══════════════════════════════════════════════════════╗${NC}"
echo -e "${BLUE}║                                                       ║${NC}"
echo -e "${BLUE}║     🚀 Full-Stack Application - Quick Start 🚀       ║${NC}"
echo -e "${BLUE}║                                                       ║${NC}"
echo -e "${BLUE}╚═══════════════════════════════════════════════════════╝${NC}"
echo ""

# ==============================================================================
# 1. Vérification des Prérequis
# ==============================================================================

info "Étape 1/7 : Vérification des prérequis..."

# Vérifier Docker
if ! command -v docker &> /dev/null; then
    error "Docker n'est pas installé !"
    echo "   Installez Docker : https://docs.docker.com/get-docker/"
    exit 1
else
    DOCKER_VERSION=$(docker --version | cut -d ' ' -f3 | cut -d ',' -f1)
    success "Docker trouvé (version $DOCKER_VERSION)"
fi

# Vérifier Docker Compose
if ! command -v docker-compose &> /dev/null; then
    error "Docker Compose n'est pas installé !"
    echo "   Installez Docker Compose : https://docs.docker.com/compose/install/"
    exit 1
else
    COMPOSE_VERSION=$(docker-compose --version | cut -d ' ' -f4 | cut -d ',' -f1)
    success "Docker Compose trouvé (version $COMPOSE_VERSION)"
fi

# Vérifier que Docker est actif
if ! docker info &> /dev/null; then
    error "Le daemon Docker n'est pas actif !"
    echo "   Démarrez Docker et réessayez"
    exit 1
else
    success "Docker daemon actif"
fi

# Vérifier les ports disponibles
PORTS=(80 3000 5432 6379 8000 9090 3001)
PORTS_BUSY=()

for port in "${PORTS[@]}"; do
    if lsof -Pi :$port -sTCP:LISTEN -t >/dev/null 2>&1 ; then
        PORTS_BUSY+=($port)
    fi
done

if [ ${#PORTS_BUSY[@]} -gt 0 ]; then
    warning "Les ports suivants sont déjà utilisés : ${PORTS_BUSY[*]}"
    echo "   Libérez-les ou modifiez les ports dans docker-compose.dev.yml"
    read -p "   Continuer quand même ? (y/N) " -n 1 -r
    echo
    if [[ ! $REPLY =~ ^[Yy]$ ]]; then
        exit 1
    fi
fi

success "Prérequis vérifiés !"

# ==============================================================================
# 2. Création du fichier .env
# ==============================================================================

info "Étape 2/7 : Configuration de l'environnement..."

if [ -f .env ]; then
    warning "Le fichier .env existe déjà"
    read -p "   Voulez-vous le recréer ? (y/N) " -n 1 -r
    echo
    if [[ $REPLY =~ ^[Yy]$ ]]; then
        cp .env .env.backup.$(date +%Y%m%d_%H%M%S)
        info "Backup créé : .env.backup.*"
        cp .env.example .env
    fi
else
    cp .env.example .env
    success "Fichier .env créé depuis .env.example"
fi

# Génération automatique des secrets
info "Génération des secrets sécurisés..."

# Générer SECRET_KEY
if command -v openssl &> /dev/null; then
    SECRET_KEY=$(openssl rand -hex 32)
    sed -i.bak "s/SECRET_KEY=.*/SECRET_KEY=$SECRET_KEY/" .env
    success "SECRET_KEY généré"
else
    warning "OpenSSL non trouvé, SECRET_KEY non généré automatiquement"
fi

# Générer mots de passe
DB_PASSWORD=$(openssl rand -base64 16 | tr -d "=+/" | cut -c1-20)
REDIS_PASSWORD=$(openssl rand -base64 16 | tr -d "=+/" | cut -c1-20)
GRAFANA_PASSWORD=$(openssl rand -base64 12 | tr -d "=+/" | cut -c1-16)

sed -i.bak "s/DB_PASSWORD=.*/DB_PASSWORD=$DB_PASSWORD/" .env
sed -i.bak "s/REDIS_PASSWORD=.*/REDIS_PASSWORD=$REDIS_PASSWORD/" .env
sed -i.bak "s/GRAFANA_PASSWORD=.*/GRAFANA_PASSWORD=$GRAFANA_PASSWORD/" .env

# Nettoyer les fichiers backup
rm -f .env.bak

success "Mots de passe générés et configurés"

# ==============================================================================
# 3. Création des répertoires nécessaires
# ==============================================================================

info "Étape 3/7 : Création des répertoires..."

mkdir -p backups
mkdir -p nginx/ssl
mkdir -p logs

touch backups/.gitkeep
touch nginx/ssl/.gitkeep

success "Répertoires créés"

# ==============================================================================
# 4. Build des images Docker
# ==============================================================================

info "Étape 4/7 : Build des images Docker..."
echo "   Cela peut prendre plusieurs minutes la première fois..."

docker-compose -f docker-compose.yml -f docker-compose.dev.yml build --quiet

success "Images Docker buildées"

# ==============================================================================
# 5. Démarrage des services
# ==============================================================================

info "Étape 5/7 : Démarrage des services..."

docker-compose -f docker-compose.yml -f docker-compose.dev.yml up -d

success "Services démarrés"

# ==============================================================================
# 6. Attente de la disponibilité des services
# ==============================================================================

info "Étape 6/7 : Attente de la disponibilité des services..."

# Fonction pour attendre un service
wait_for_service() {
    local service=$1
    local url=$2
    local max_attempts=30
    local attempt=0

    echo -n "   Attente de $service"
    
    while [ $attempt -lt $max_attempts ]; do
        if curl -sf "$url" > /dev/null 2>&1; then
            echo ""
            success "$service est prêt"
            return 0
        fi
        echo -n "."
        sleep 2
        attempt=$((attempt + 1))
    done
    
    echo ""
    warning "$service tarde à démarrer (vérifiez les logs)"
    return 1
}

# Attendre PostgreSQL
info "Attente de PostgreSQL..."
sleep 5
docker-compose exec -T postgres pg_isready -U postgres > /dev/null 2>&1
success "PostgreSQL prêt"

# Attendre Redis
wait_for_service "Redis" "http://localhost:6379"

# Attendre Backend
wait_for_service "Backend" "http://localhost:8000/health"

# Attendre Frontend
wait_for_service "Frontend" "http://localhost:3000"

# ==============================================================================
# 7. Migrations de base de données
# ==============================================================================

info "Étape 7/7 : Application des migrations..."

# Attendre un peu que le backend soit complètement prêt
sleep 3

# Appliquer les migrations
if docker-compose exec -T backend alembic upgrade head; then
    success "Migrations appliquées"
else
    warning "Erreur lors des migrations (normal si c'est la première fois sans migrations)"
fi

# ==============================================================================
# Résumé et Instructions
# ==============================================================================

echo ""
echo -e "${GREEN}╔═══════════════════════════════════════════════════════╗${NC}"
echo -e "${GREEN}║                                                       ║${NC}"
echo -e "${GREEN}║        ✓ Application démarrée avec succès ! ✓        ║${NC}"
echo -e "${GREEN}║                                                       ║${NC}"
echo -e "${GREEN}╚═══════════════════════════════════════════════════════╝${NC}"
echo ""

echo -e "${BLUE}📍 Services disponibles :${NC}"
echo ""
echo -e "   🎨 Frontend React       : ${GREEN}http://localhost:3000${NC}"
echo -e "   🔧 Backend API          : ${GREEN}http://localhost:8000${NC}"
echo -e "   📚 API Docs (Swagger)   : ${GREEN}http://localhost:8000/docs${NC}"
echo -e "   📖 API Docs (ReDoc)     : ${GREEN}http://localhost:8000/redoc${NC}"
echo -e "   📊 Grafana              : ${GREEN}http://localhost:3001${NC} (admin / $GRAFANA_PASSWORD)"
echo -e "   📈 Prometheus           : ${GREEN}http://localhost:9090${NC}"
echo -e "   🗄️  Adminer (PostgreSQL) : ${GREEN}http://localhost:8080${NC}"
echo -e "   📦 Redis Commander      : ${GREEN}http://localhost:8081${NC}"
echo -e "   📧 MailHog              : ${GREEN}http://localhost:8025${NC}"
echo ""

echo -e "${BLUE}🔑 Credentials :${NC}"
echo ""
echo -e "   Database Password    : ${YELLOW}$DB_PASSWORD${NC}"
echo -e "   Redis Password       : ${YELLOW}$REDIS_PASSWORD${NC}"
echo -e "   Grafana Password     : ${YELLOW}$GRAFANA_PASSWORD${NC}"
echo ""
echo -e "   ${YELLOW}⚠ Sauvegardez ces mots de passe ! Ils sont dans le fichier .env${NC}"
echo ""

echo -e "${BLUE}📋 Commandes utiles :${NC}"
echo ""
echo -e "   make logs            # Voir tous les logs"
echo -e "   make logs-backend    # Logs du backend uniquement"
echo -e "   make logs-frontend   # Logs du frontend uniquement"
echo -e "   make ps              # Status des services"
echo -e "   make dev-down        # Arrêter tous les services"
echo -e "   make dev-up          # Redémarrer les services"
echo -e "   make help            # Voir toutes les commandes"
echo ""

echo -e "${BLUE}🐛 En cas de problème :${NC}"
echo ""
echo -e "   make logs            # Vérifier les logs"
echo -e "   make health          # Vérifier la santé des services"
echo -e "   make clean           # Nettoyer et redémarrer"
echo ""

echo -e "${BLUE}📚 Documentation :${NC}"
echo ""
echo -e "   README.md            # Documentation générale"
echo -e "   LOCAL_SETUP.md       # Guide de setup local détaillé"
echo -e "   SECURITY.md          # Guide de sécurité"
echo ""

echo -e "${GREEN}✨ Bon développement ! ✨${NC}"
echo ""

# Ouvrir le navigateur automatiquement (optionnel)
read -p "Voulez-vous ouvrir l'application dans le navigateur ? (Y/n) " -n 1 -r
echo
if [[ ! $REPLY =~ ^[Nn]$ ]]; then
    if command -v xdg-open &> /dev/null; then
        xdg-open http://localhost:3000
    elif command -v open &> /dev/null; then
        open http://localhost:3000
    elif command -v start &> /dev/null; then
        start http://localhost:3000
    else
        info "Ouvrez manuellement : http://localhost:3000"
    fi
fi