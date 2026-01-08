# Makefile pour simplifier les commandes Docker et DevOps
.PHONY: help build up down restart logs clean test migrate backup restore

# Variables
DOCKER_COMPOSE = docker compose
DOCKER_COMPOSE_DEV = docker compose -f docker-compose.yml -f docker-compose.dev.yml
DOCKER_COMPOSE_PROD = docker compose -f docker-compose.yml -f docker-compose.prod.yml

# Couleurs pour l'output
GREEN  := $(shell tput -Txterm setaf 2)
YELLOW := $(shell tput -Txterm setaf 3)
RESET  := $(shell tput -Txterm sgr0)

## help: Affiche ce message d'aide
help:
	@echo ''
	@echo 'Usage:'
	@echo '  ${YELLOW}make${RESET} ${GREEN}<target>${RESET}'
	@echo ''
	@echo 'Targets:'
	@awk 'BEGIN {FS = ":.*?## "} { \
		if (/^[a-zA-Z_-]+:.*?##.*$$/) {printf "    ${YELLOW}%-20s${GREEN}%s${RESET}\n", $$1, $$2} \
		else if (/^## .*$$/) {printf "  ${GREEN}%s${RESET}\n", substr($$1,4)} \
		}' $(MAKEFILE_LIST)

## Développement:

## dev-build: Build les images en mode développement
dev-build:
	$(DOCKER_COMPOSE_DEV) build

## dev-up: Lance l'application en mode développement
dev-up:
	$(DOCKER_COMPOSE_DEV) up -d
	@echo "${GREEN}Application démarrée en mode développement${RESET}"
	@echo "Frontend: http://localhost:3000"
	@echo "Backend API: http://localhost:8000"
	@echo "API Docs: http://localhost:8000/docs"
	@echo "Grafana: http://localhost:3001"

## dev-down: Arrête l'application en mode développement
dev-down:
	$(DOCKER_COMPOSE_DEV) down

## Production:

## prod-build: Build les images en mode production
prod-build:
	$(DOCKER_COMPOSE_PROD) build --no-cache

## prod-up: Lance l'application en mode production
prod-up:
	$(DOCKER_COMPOSE_PROD) up -d
	@echo "${GREEN}Application démarrée en mode production${RESET}"

## prod-down: Arrête l'application en mode production
prod-down:
	$(DOCKER_COMPOSE_PROD) down

## Commandes générales:

## build: Build toutes les images
build:
	$(DOCKER_COMPOSE) build

## up: Lance tous les services
up:
	$(DOCKER_COMPOSE) up -d

## down: Arrête tous les services
down:
	$(DOCKER_COMPOSE) down

## restart: Redémarre tous les services
restart: down up

## stop: Arrête les conteneurs sans les supprimer
stop:
	$(DOCKER_COMPOSE) stop

## start: Démarre les conteneurs existants
start:
	$(DOCKER_COMPOSE) start

## Logs et monitoring:

## logs: Affiche les logs de tous les services
logs:
	$(DOCKER_COMPOSE) logs -f

## logs-backend: Affiche les logs du backend
logs-backend:
	$(DOCKER_COMPOSE) logs -f backend

## logs-frontend: Affiche les logs du frontend
logs-frontend:
	$(DOCKER_COMPOSE) logs -f frontend

## logs-nginx: Affiche les logs de Nginx
logs-nginx:
	$(DOCKER_COMPOSE) logs -f nginx

## ps: Liste les conteneurs en cours d'exécution
ps:
	$(DOCKER_COMPOSE) ps

## Database:

## migrate: Exécute les migrations Alembic
migrate:
	$(DOCKER_COMPOSE) exec backend alembic upgrade head

## migrate-create: Crée une nouvelle migration
migrate-create:
	@read -p "Nom de la migration: " name; \
	$(DOCKER_COMPOSE) exec backend alembic revision --autogenerate -m "$$name"

## db-shell: Ouvre un shell PostgreSQL
db-shell:
	$(DOCKER_COMPOSE) exec postgres psql -U postgres -d app_db

## backup: Sauvegarde la base de données
backup:
	@mkdir -p backups
	@echo "${YELLOW}Création du backup...${RESET}"
	$(DOCKER_COMPOSE) exec -T postgres pg_dump -U postgres app_db > backups/backup_$$(date +%Y%m%d_%H%M%S).sql
	@echo "${GREEN}Backup créé dans backups/${RESET}"

## restore: Restaure la base de données depuis un backup
restore:
	@echo "${YELLOW}Fichiers de backup disponibles:${RESET}"
	@ls -1 backups/*.sql
	@read -p "Nom du fichier à restaurer: " file; \
	$(DOCKER_COMPOSE) exec -T postgres psql -U postgres -d app_db < $$file
	@echo "${GREEN}Base de données restaurée${RESET}"

## Tests:

## test: Lance les tests du backend
test:
	$(DOCKER_COMPOSE) exec backend pytest -v

## test-cov: Lance les tests avec coverage
test-cov:
	$(DOCKER_COMPOSE) exec backend pytest --cov=app --cov-report=html

## test-frontend: Lance les tests du frontend
test-frontend:
	$(DOCKER_COMPOSE) exec frontend npm test

## Shell:

## shell-backend: Ouvre un shell dans le conteneur backend
shell-backend:
	$(DOCKER_COMPOSE) exec backend bash

## shell-frontend: Ouvre un shell dans le conteneur frontend
shell-frontend:
	$(DOCKER_COMPOSE) exec frontend sh

## Nettoyage:

## clean: Supprime les conteneurs, volumes et images
clean:
	$(DOCKER_COMPOSE) down -v --remove-orphans
	@echo "${YELLOW}Suppression des images orphelines...${RESET}"
	docker image prune -f
	@echo "${GREEN}Nettoyage terminé${RESET}"

## clean-all: Nettoyage complet (conteneurs, volumes, images, cache)
clean-all:
	$(DOCKER_COMPOSE) down -v --rmi all --remove-orphans
	docker system prune -af --volumes
	@echo "${GREEN}Nettoyage complet terminé${RESET}"

## Security:

## security-scan: Scan de sécurité des images Docker
security-scan:
	@echo "${YELLOW}Scan de sécurité avec Trivy...${RESET}"
	docker run --rm -v /var/run/docker.sock:/var/run/docker.sock aquasec/trivy image fullstack_backend:latest
	docker run --rm -v /var/run/docker.sock:/var/run/docker.sock aquasec/trivy image fullstack_frontend:latest

## Utilitaires:

## init: Initialise le projet (copie .env.example vers .env)
init:
	@if [ ! -f .env ]; then \
		cp .env.example .env; \
		echo "${GREEN}.env créé depuis .env.example${RESET}"; \
		echo "${YELLOW}N'oubliez pas de modifier les valeurs sensibles!${RESET}"; \
	else \
		echo "${YELLOW}.env existe déjà${RESET}"; \
	fi

## setup: Setup complet du projet
setup: init dev-build dev-up migrate
	@echo "${GREEN}Setup terminé! L'application est prête.${RESET}"

## health: Vérifie la santé des services
health:
	@echo "${YELLOW}Vérification de la santé des services...${RESET}"
	@curl -f http://localhost/health && echo " ${GREEN}✓ Nginx${RESET}" || echo " ${YELLOW}✗ Nginx${RESET}"
	@curl -f http://localhost:8000/health && echo " ${GREEN}✓ Backend${RESET}" || echo " ${YELLOW}✗ Backend${RESET}"