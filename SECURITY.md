# 🔐 Guide de Sécurité Production

## Principes de Sécurité

### 1. Defense in Depth (Défense en Profondeur)

L'architecture implémente plusieurs couches de sécurité:

```
┌─────────────────────────────────────────┐
│ WAF / Cloudflare (Optionnel)           │
├─────────────────────────────────────────┤
│ Nginx (Rate Limiting, Headers)         │
├─────────────────────────────────────────┤
│ Network Isolation (Docker Networks)    │
├─────────────────────────────────────────┤
│ Application (JWT, Validation)          │
├─────────────────────────────────────────┤
│ Database (Permissions, Encryption)     │
└─────────────────────────────────────────┘
```

### 2. Principe du Moindre Privilège

- Conteneurs exécutés en tant qu'utilisateur non-root
- Permissions strictes sur les fichiers
- Accès base de données limité

### 3. Sécurité par Défaut

- HTTPS activé par défaut en production
- Headers de sécurité automatiques
- Rate limiting configuré

## 🔑 Gestion des Secrets

### Génération de Secrets Forts

```bash
# SECRET_KEY pour JWT (minimum 32 caractères)
openssl rand -hex 32

# Mot de passe aléatoire
openssl rand -base64 32

# UUID unique
python3 -c "import uuid; print(uuid.uuid4())"
```

### Stockage des Secrets

#### Développement
```bash
# Utiliser .env (jamais commité dans Git)
echo ".env" >> .gitignore
```

#### Production

**Option 1: Variables d'environnement système**
```bash
# /etc/environment
export SECRET_KEY="votre_secret_ici"
```

**Option 2: Docker Secrets**
```yaml
# docker-compose.prod.yml
secrets:
  db_password:
    file: ./secrets/db_password.txt

services:
  backend:
    secrets:
      - db_password
```

**Option 3: Vault (Recommandé)**
```bash
# Utiliser HashiCorp Vault ou AWS Secrets Manager
vault kv put secret/app/prod \
  db_password="xxx" \
  secret_key="yyy"
```

### Rotation des Secrets

**Calendrier recommandé:**
- JWT SECRET_KEY: Tous les 90 jours
- Mots de passe DB: Tous les 180 jours
- Mots de passe utilisateurs: Expiration forcée à 90 jours

**Script de rotation:**
```bash
#!/bin/bash
# scripts/rotate-secrets.sh

OLD_SECRET=$(grep SECRET_KEY .env | cut -d '=' -f2)
NEW_SECRET=$(openssl rand -hex 32)

# Backup
cp .env .env.backup

# Remplacer
sed -i "s/$OLD_SECRET/$NEW_SECRET/" .env

# Redémarrer
docker-compose restart backend
```

## 🛡️ Sécurisation Nginx

### Configuration SSL/TLS Renforcée

```nginx
# nginx/nginx-ssl.conf
server {
    listen 443 ssl http2;
    server_name yourdomain.com;

    # Certificats SSL
    ssl_certificate /etc/nginx/ssl/fullchain.pem;
    ssl_certificate_key /etc/nginx/ssl/privkey.pem;

    # Protocoles sécurisés uniquement
    ssl_protocols TLSv1.2 TLSv1.3;
    
    # Ciphers forts
    ssl_ciphers 'ECDHE-ECDSA-AES128-GCM-SHA256:ECDHE-RSA-AES128-GCM-SHA256:ECDHE-ECDSA-AES256-GCM-SHA384:ECDHE-RSA-AES256-GCM-SHA384';
    ssl_prefer_server_ciphers off;

    # Session SSL
    ssl_session_cache shared:SSL:10m;
    ssl_session_timeout 10m;
    ssl_session_tickets off;

    # OCSP Stapling
    ssl_stapling on;
    ssl_stapling_verify on;
    ssl_trusted_certificate /etc/nginx/ssl/chain.pem;

    # HSTS (HTTP Strict Transport Security)
    add_header Strict-Transport-Security "max-age=63072000; includeSubDomains; preload" always;
    
    # Headers de sécurité
    add_header X-Frame-Options "DENY" always;
    add_header X-Content-Type-Options "nosniff" always;
    add_header X-XSS-Protection "1; mode=block" always;
    add_header Referrer-Policy "no-referrer-when-downgrade" always;
    add_header Content-Security-Policy "default-src 'self' https:; script-src 'self' 'unsafe-inline' 'unsafe-eval'; style-src 'self' 'unsafe-inline';" always;
    add_header Permissions-Policy "geolocation=(), microphone=(), camera=()" always;
}
```

### Rate Limiting Avancé

```nginx
# Différents taux selon les endpoints
http {
    # Zone pour l'authentification (plus restrictif)
    limit_req_zone $binary_remote_addr zone=auth_limit:10m rate=5r/m;
    
    # Zone pour l'API (normal)
    limit_req_zone $binary_remote_addr zone=api_limit:10m rate=10r/s;
    
    # Zone pour les uploads
    limit_req_zone $binary_remote_addr zone=upload_limit:10m rate=1r/s;

    server {
        location /api/v1/auth {
            limit_req zone=auth_limit burst=3 nodelay;
            limit_req_status 429;
        }

        location /api {
            limit_req zone=api_limit burst=20 nodelay;
        }

        location /api/upload {
            limit_req zone=upload_limit burst=2;
            client_max_body_size 10M;
        }
    }
}
```

## 🔐 Sécurité Backend

### Authentification JWT Sécurisée

```python
# backend/app/core/security.py

from datetime import datetime, timedelta
from typing import Optional
import secrets

def create_secure_token(data: dict, expires_delta: Optional[timedelta] = None) -> str:
    """Crée un token JWT sécurisé avec des claims supplémentaires"""
    to_encode = data.copy()
    
    # Expiration
    if expires_delta:
        expire = datetime.utcnow() + expires_delta
    else:
        expire = datetime.utcnow() + timedelta(minutes=15)
    
    # Claims de sécurité
    to_encode.update({
        "exp": expire,
        "iat": datetime.utcnow(),
        "jti": secrets.token_urlsafe(32),  # JWT ID unique
        "type": "access",
        "ver": "1"  # Version du token
    })
    
    return jwt.encode(to_encode, settings.SECRET_KEY, algorithm=settings.ALGORITHM)

# Blacklist de tokens (utiliser Redis)
async def is_token_blacklisted(jti: str) -> bool:
    """Vérifie si un token est révoqué"""
    return await redis.exists(f"blacklist:{jti}")

async def revoke_token(jti: str, exp: datetime):
    """Révoque un token"""
    ttl = int((exp - datetime.utcnow()).total_seconds())
    await redis.setex(f"blacklist:{jti}", ttl, "1")
```

### Protection contre les Attaques Courantes

#### 1. SQL Injection

```python
# ✅ BON - Utiliser SQLAlchemy ORM
user = db.query(User).filter(User.email == email).first()

# ✅ BON - Paramètres bindés
db.execute(text("SELECT * FROM users WHERE email = :email"), {"email": email})

# ❌ MAUVAIS - Concaténation de strings
db.execute(f"SELECT * FROM users WHERE email = '{email}'")
```

#### 2. XSS (Cross-Site Scripting)

```python
from fastapi.encoders import jsonable_encoder
from html import escape

# Échapper les données utilisateur
def sanitize_input(user_input: str) -> str:
    return escape(user_input.strip())

# Validation stricte avec Pydantic
class UserInput(BaseModel):
    comment: str = Field(..., max_length=1000, regex=r'^[a-zA-Z0-9\s\.,!?-]+$')
```

#### 3. CSRF (Cross-Site Request Forgery)

```python
from fastapi import Depends, HTTPException, Header
import secrets

# Générer un token CSRF
def generate_csrf_token() -> str:
    return secrets.token_urlsafe(32)

# Middleware de vérification CSRF
async def verify_csrf_token(
    x_csrf_token: str = Header(...),
    stored_token: str = Depends(get_stored_csrf_token)
):
    if not secrets.compare_digest(x_csrf_token, stored_token):
        raise HTTPException(status_code=403, detail="Invalid CSRF token")
```

#### 4. Injection de Commandes

```python
import subprocess
import shlex

# ❌ MAUVAIS
subprocess.run(f"ls {user_input}", shell=True)

# ✅ BON
allowed_commands = ["ls", "pwd"]
if command in allowed_commands:
    subprocess.run([command], shell=False)
```

### Validation et Sanitization

```python
from pydantic import BaseModel, validator, EmailStr
import re

class UserRegistration(BaseModel):
    email: EmailStr
    password: str
    username: str
    
    @validator('password')
    def password_strength(cls, v):
        if len(v) < 12:
            raise ValueError('Password must be at least 12 characters')
        if not re.search(r'[A-Z]', v):
            raise ValueError('Password must contain uppercase')
        if not re.search(r'[a-z]', v):
            raise ValueError('Password must contain lowercase')
        if not re.search(r'\d', v):
            raise ValueError('Password must contain digit')
        if not re.search(r'[!@#$%^&*]', v):
            raise ValueError('Password must contain special character')
        return v
    
    @validator('username')
    def username_alphanumeric(cls, v):
        if not re.match(r'^[a-zA-Z0-9_-]{3,20}$', v):
            raise ValueError('Invalid username format')
        return v
```

## 🗄️ Sécurité Base de Données

### Configuration PostgreSQL Sécurisée

```ini
# postgresql.conf
password_encryption = scram-sha-256
ssl = on
ssl_cert_file = '/etc/ssl/certs/server.crt'
ssl_key_file = '/etc/ssl/private/server.key'

# Connexions
listen_addresses = 'localhost'
max_connections = 100

# Logging
log_connections = on
log_disconnections = on
log_duration = on
log_statement = 'ddl'
```

### Permissions Strictes

```sql
-- Créer un utilisateur avec privilèges limités
CREATE USER app_user WITH PASSWORD 'strong_password';
GRANT CONNECT ON DATABASE app_db TO app_user;
GRANT USAGE ON SCHEMA public TO app_user;
GRANT SELECT, INSERT, UPDATE, DELETE ON ALL TABLES IN SCHEMA public TO app_user;

-- Retirer les privilèges superuser
REVOKE ALL ON DATABASE postgres FROM PUBLIC;

-- Read-only user pour les backups
CREATE USER backup_user WITH PASSWORD 'backup_password';
GRANT CONNECT ON DATABASE app_db TO backup_user;
GRANT SELECT ON ALL TABLES IN SCHEMA public TO backup_user;
```

### Chiffrement des Données Sensibles

```python
from cryptography.fernet import Fernet

class EncryptedField:
    """Champ de base de données chiffré"""
    
    def __init__(self):
        self.fernet = Fernet(settings.ENCRYPTION_KEY)
    
    def encrypt(self, value: str) -> str:
        return self.fernet.encrypt(value.encode()).decode()
    
    def decrypt(self, value: str) -> str:
        return self.fernet.decrypt(value.encode()).decode()

# Utilisation dans les modèles
class User(Base):
    __tablename__ = "users"
    
    id = Column(Integer, primary_key=True)
    email = Column(String, unique=True, index=True)
    ssn = Column(String)  # Numéro de sécurité sociale chiffré
    
    @property
    def decrypted_ssn(self):
        return encrypted_field.decrypt(self.ssn)
```

## 🔍 Audit et Monitoring de Sécurité

### Logging de Sécurité

```python
import logging
from datetime import datetime

security_logger = logging.getLogger("security")

# Logger les événements de sécurité
def log_security_event(event_type: str, user_id: int, details: dict):
    security_logger.warning(
        f"Security Event: {event_type}",
        extra={
            "event_type": event_type,
            "user_id": user_id,
            "timestamp": datetime.utcnow().isoformat(),
            "details": details
        }
    )

# Exemples d'événements à logger
- Failed login attempts
- Password changes
- Permission changes
- Data access
- API key usage
- Suspicious activities
```

### Détection d'Anomalies

```python
from datetime import datetime, timedelta
from collections import defaultdict

class AnomalyDetector:
    """Détecte les comportements suspects"""
    
    def __init__(self):
        self.failed_attempts = defaultdict(list)
    
    async def check_brute_force(self, ip: str) -> bool:
        """Détecte les tentatives de brute force"""
        now = datetime.utcnow()
        
        # Nettoyer les anciennes tentatives
        self.failed_attempts[ip] = [
            t for t in self.failed_attempts[ip]
            if now - t < timedelta(minutes=15)
        ]
        
        # Bloquer si trop de tentatives
        if len(self.failed_attempts[ip]) >= 5:
            log_security_event("brute_force_detected", None, {"ip": ip})
            return True
        
        self.failed_attempts[ip].append(now)
        return False
```

### Alertes de Sécurité

```python
import aiohttp

async def send_security_alert(event: str, details: dict):
    """Envoie une alerte de sécurité"""
    
    # Slack
    async with aiohttp.ClientSession() as session:
        await session.post(
            settings.SLACK_WEBHOOK_URL,
            json={
                "text": f"🚨 Security Alert: {event}",
                "attachments": [{
                    "color": "danger",
                    "fields": [
                        {"title": k, "value": str(v), "short": True}
                        for k, v in details.items()
                    ]
                }]
            }
        )
    
    # Email
    await send_email(
        to=settings.SECURITY_EMAIL,
        subject=f"Security Alert: {event}",
        body=str(details)
    )
```

## 🔄 Checklist de Sécurité Pre-Production

### Infrastructure
- [ ] Firewall configuré (UFW/iptables)
- [ ] Ports non nécessaires fermés
- [ ] SSH avec clé uniquement (pas de mot de passe)
- [ ] Fail2ban installé et configuré
- [ ] Backups automatisés et testés
- [ ] Monitoring actif (Prometheus + Alertes)

### Application
- [ ] HTTPS/TLS activé avec certificats valides
- [ ] Headers de sécurité configurés
- [ ] Rate limiting activé
- [ ] CORS configuré correctement
- [ ] Tous les secrets en variables d'environnement
- [ ] Validation stricte des entrées
- [ ] Logs de sécurité actifs
- [ ] Gestion d'erreurs sans fuites d'information

### Base de Données
- [ ] Mots de passe forts
- [ ] Connexions chiffrées (SSL)
- [ ] Privilèges minimaux
- [ ] Backups réguliers
- [ ] Logs d'audit activés
- [ ] Chiffrement des données sensibles

### Docker
- [ ] Images à jour (pas de CVE connus)
- [ ] Utilisateurs non-root
- [ ] Networks isolés
- [ ] Secrets Docker utilisés
- [ ] Scan de sécurité réussi
- [ ] Health checks configurés

### Code
- [ ] Dépendances à jour
- [ ] Pas de secrets hardcodés
- [ ] Tests de sécurité réussis
- [ ] Revue de code effectuée
- [ ] Documentation à jour

## 📚 Ressources

- [OWASP Top 10](https://owasp.org/www-project-top-ten/)
- [CIS Docker Benchmark](https://www.cisecurity.org/benchmark/docker)
- [PostgreSQL Security](https://www.postgresql.org/docs/current/security.html)
- [FastAPI Security](https://fastapi.tiangolo.com/tutorial/security/)
- [Mozilla SSL Configuration Generator](https://ssl-config.mozilla.org/)