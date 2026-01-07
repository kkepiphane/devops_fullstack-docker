# Multi-stage build pour optimiser la taille de l'image
FROM python:3.11-slim as base

# Variables d'environnement pour Python
ENV PYTHONUNBUFFERED=1 \
    PYTHONDONTWRITEBYTECODE=1 \
    PIP_NO_CACHE_DIR=1 \
    PIP_DISABLE_PIP_VERSION_CHECK=1

WORKDIR /app

# Installation des dépendances système
RUN apt-get update && apt-get install -y \
    gcc \
    postgresql-client \
    && rm -rf /var/lib/apt/lists/*

# Stage de build des dépendances
FROM base as builder

COPY requirements.txt .
RUN pip install --user --no-warn-script-location -r requirements.txt

# Stage final
FROM base as runtime

# Créer un utilisateur non-root pour la sécurité
RUN useradd -m -u 1000 appuser && \
    chown -R appuser:appuser /app

# Copier les dépendances depuis le builder
COPY --from=builder --chown=appuser:appuser /root/.local /home/appuser/.local

# Ajouter le PATH des binaires Python
ENV PATH=/home/appuser/.local/bin:$PATH

# Copier le code de l'application
COPY --chown=appuser:appuser . .

# Passer à l'utilisateur non-root
USER appuser

# Healthcheck
HEALTHCHECK --interval=30s --timeout=10s --start-period=40s --retries=3 \
    CMD python -c "import requests; requests.get('http://localhost:8000/health')"

# Port exposé
EXPOSE 8000

# Commande de démarrage avec Uvicorn
CMD ["uvicorn", "app.main:app", "--host", "0.0.0.0", "--port", "8000", "--workers", "4"]