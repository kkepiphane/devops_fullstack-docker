# ☸️ Guide de Migration vers Kubernetes

## Vue d'ensemble

Ce guide détaille comment migrer l'application Docker Compose vers Kubernetes pour une scalabilité et une résilience accrues.

## 📊 Architecture Kubernetes

```
┌─────────────────────────────────────────────────────┐
│              Ingress Controller                     │
│            (Nginx / Traefik)                        │
└─────────────┬───────────────────────────────────────┘
              │
    ┌─────────┼─────────┐
    │         │         │
┌───▼────┐ ┌──▼───┐ ┌──▼───────┐
│Frontend│ │Backend│ │Monitoring│
│  Pod   │ │  Pod  │ │   Pod    │
│  x3    │ │  x5   │ │   x1     │
└────────┘ └───┬───┘ └──────────┘
               │
       ┌───────┼───────┐
       │       │       │
   ┌───▼──┐ ┌──▼──┐ ┌─▼────┐
   │ PG   │ │Redis│ │Celery│
   │StatefulSet│Pod│ │ Pod  │
   │  x3  │ │ x1  │ │  x3  │
   └──────┘ └─────┘ └──────┘
```

## 🚀 Préparation de la Migration

### 1. Prérequis

```bash
# Installer kubectl
curl -LO "https://dl.k8s.io/release/$(curl -L -s https://dl.k8s.io/release/stable.txt)/bin/linux/amd64/kubectl"
sudo install -o root -g root -m 0755 kubectl /usr/local/bin/kubectl

# Installer Helm
curl https://raw.githubusercontent.com/helm/helm/main/scripts/get-helm-3 | bash

# Cluster Kubernetes (choisir une option)
# - Minikube (local)
# - K3s (léger)
# - EKS (AWS)
# - GKE (Google Cloud)
# - AKS (Azure)
```

### 2. Structure des Manifests

```
k8s/
├── base/                      # Configuration de base
│   ├── namespace.yaml
│   ├── configmap.yaml
│   ├── secrets.yaml
│   └── ingress.yaml
├── backend/
│   ├── deployment.yaml
│   ├── service.yaml
│   ├── hpa.yaml              # Horizontal Pod Autoscaler
│   └── pdb.yaml              # Pod Disruption Budget
├── frontend/
│   ├── deployment.yaml
│   ├── service.yaml
│   └── hpa.yaml
├── database/
│   ├── statefulset.yaml
│   ├── service.yaml
│   ├── pvc.yaml              # Persistent Volume Claim
│   └── backup-cronjob.yaml
├── redis/
│   ├── deployment.yaml
│   └── service.yaml
├── celery/
│   ├── deployment.yaml
│   └── hpa.yaml
├── monitoring/
│   ├── prometheus/
│   └── grafana/
└── kustomization.yaml         # Kustomize overlay
```

## 📦 Manifests Kubernetes

### Namespace

```yaml
# k8s/base/namespace.yaml
apiVersion: v1
kind: Namespace
metadata:
  name: fullstack-app
  labels:
    name: fullstack-app
    environment: production
```

### ConfigMap

```yaml
# k8s/base/configmap.yaml
apiVersion: v1
kind: ConfigMap
metadata:
  name: app-config
  namespace: fullstack-app
data:
  ENVIRONMENT: "production"
  LOG_LEVEL: "INFO"
  ALGORITHM: "HS256"
  ACCESS_TOKEN_EXPIRE_MINUTES: "30"
  POSTGRES_HOST: "postgres-service"
  REDIS_HOST: "redis-service"
  # Ajouter d'autres configurations non sensibles
```

### Secrets (à créer avec kubectl)

```yaml
# k8s/base/secrets.yaml (template - NE PAS COMMITER LES VRAIES VALEURS)
apiVersion: v1
kind: Secret
metadata:
  name: app-secrets
  namespace: fullstack-app
type: Opaque
data:
  # Encoder en base64: echo -n "value" | base64
  DB_PASSWORD: <base64-encoded>
  REDIS_PASSWORD: <base64-encoded>
  SECRET_KEY: <base64-encoded>
  GRAFANA_PASSWORD: <base64-encoded>
```

**Création avec kubectl:**
```bash
kubectl create secret generic app-secrets \
  --from-literal=DB_PASSWORD='your_password' \
  --from-literal=REDIS_PASSWORD='your_password' \
  --from-literal=SECRET_KEY='your_secret' \
  --from-literal=GRAFANA_PASSWORD='your_password' \
  -n fullstack-app
```

### Backend Deployment

```yaml
# k8s/backend/deployment.yaml
apiVersion: apps/v1
kind: Deployment
metadata:
  name: backend
  namespace: fullstack-app
  labels:
    app: backend
spec:
  replicas: 3
  strategy:
    type: RollingUpdate
    rollingUpdate:
      maxSurge: 1
      maxUnavailable: 0
  selector:
    matchLabels:
      app: backend
  template:
    metadata:
      labels:
        app: backend
      annotations:
        prometheus.io/scrape: "true"
        prometheus.io/port: "8000"
        prometheus.io/path: "/metrics"
    spec:
      securityContext:
        runAsNonRoot: true
        runAsUser: 1000
        fsGroup: 1000
      containers:
      - name: backend
        image: your-registry/fullstack-backend:latest
        imagePullPolicy: Always
        ports:
        - containerPort: 8000
          name: http
          protocol: TCP
        env:
        - name: DATABASE_URL
          value: "postgresql://$(DB_USER):$(DB_PASSWORD)@postgres-service:5432/$(DB_NAME)"
        - name: REDIS_URL
          value: "redis://:$(REDIS_PASSWORD)@redis-service:6379/0"
        envFrom:
        - configMapRef:
            name: app-config
        - secretRef:
            name: app-secrets
        resources:
          requests:
            cpu: 100m
            memory: 256Mi
          limits:
            cpu: 1000m
            memory: 512Mi
        livenessProbe:
          httpGet:
            path: /health
            port: 8000
          initialDelaySeconds: 30
          periodSeconds: 10
          timeoutSeconds: 5
          failureThreshold: 3
        readinessProbe:
          httpGet:
            path: /health
            port: 8000
          initialDelaySeconds: 10
          periodSeconds: 5
          timeoutSeconds: 3
          failureThreshold: 3
        volumeMounts:
        - name: logs
          mountPath: /app/logs
      volumes:
      - name: logs
        emptyDir: {}
```

### Backend Service

```yaml
# k8s/backend/service.yaml
apiVersion: v1
kind: Service
metadata:
  name: backend-service
  namespace: fullstack-app
  labels:
    app: backend
spec:
  type: ClusterIP
  ports:
  - port: 8000
    targetPort: 8000
    protocol: TCP
    name: http
  selector:
    app: backend
```

### Horizontal Pod Autoscaler

```yaml
# k8s/backend/hpa.yaml
apiVersion: autoscaling/v2
kind: HorizontalPodAutoscaler
metadata:
  name: backend-hpa
  namespace: fullstack-app
spec:
  scaleTargetRef:
    apiVersion: apps/v1
    kind: Deployment
    name: backend
  minReplicas: 3
  maxReplicas: 10
  metrics:
  - type: Resource
    resource:
      name: cpu
      target:
        type: Utilization
        averageUtilization: 70
  - type: Resource
    resource:
      name: memory
      target:
        type: Utilization
        averageUtilization: 80
  behavior:
    scaleDown:
      stabilizationWindowSeconds: 300
      policies:
      - type: Percent
        value: 50
        periodSeconds: 60
    scaleUp:
      stabilizationWindowSeconds: 0
      policies:
      - type: Percent
        value: 100
        periodSeconds: 30
```

### Pod Disruption Budget

```yaml
# k8s/backend/pdb.yaml
apiVersion: policy/v1
kind: PodDisruptionBudget
metadata:
  name: backend-pdb
  namespace: fullstack-app
spec:
  minAvailable: 2
  selector:
    matchLabels:
      app: backend
```

### PostgreSQL StatefulSet

```yaml
# k8s/database/statefulset.yaml
apiVersion: apps/v1
kind: StatefulSet
metadata:
  name: postgres
  namespace: fullstack-app
spec:
  serviceName: postgres-service
  replicas: 3
  selector:
    matchLabels:
      app: postgres
  template:
    metadata:
      labels:
        app: postgres
    spec:
      containers:
      - name: postgres
        image: postgres:15-alpine
        ports:
        - containerPort: 5432
          name: postgres
        env:
        - name: POSTGRES_DB
          valueFrom:
            configMapKeyRef:
              name: app-config
              key: DB_NAME
        - name: POSTGRES_USER
          valueFrom:
            secretKeyRef:
              name: app-secrets
              key: DB_USER
        - name: POSTGRES_PASSWORD
          valueFrom:
            secretKeyRef:
              name: app-secrets
              key: DB_PASSWORD
        - name: PGDATA
          value: /var/lib/postgresql/data/pgdata
        volumeMounts:
        - name: postgres-storage
          mountPath: /var/lib/postgresql/data
        resources:
          requests:
            cpu: 500m
            memory: 1Gi
          limits:
            cpu: 2000m
            memory: 2Gi
        livenessProbe:
          exec:
            command:
            - pg_isready
            - -U
            - $(POSTGRES_USER)
          initialDelaySeconds: 30
          periodSeconds: 10
        readinessProbe:
          exec:
            command:
            - pg_isready
            - -U
            - $(POSTGRES_USER)
          initialDelaySeconds: 5
          periodSeconds: 5
  volumeClaimTemplates:
  - metadata:
      name: postgres-storage
    spec:
      accessModes: [ "ReadWriteOnce" ]
      storageClassName: "fast-ssd"
      resources:
        requests:
          storage: 50Gi
```

### Ingress

```yaml
# k8s/base/ingress.yaml
apiVersion: networking.k8s.io/v1
kind: Ingress
metadata:
  name: app-ingress
  namespace: fullstack-app
  annotations:
    kubernetes.io/ingress.class: nginx
    cert-manager.io/cluster-issuer: letsencrypt-prod
    nginx.ingress.kubernetes.io/rate-limit: "100"
    nginx.ingress.kubernetes.io/ssl-redirect: "true"
    nginx.ingress.kubernetes.io/force-ssl-redirect: "true"
spec:
  tls:
  - hosts:
    - yourdomain.com
    - www.yourdomain.com
    secretName: tls-secret
  rules:
  - host: yourdomain.com
    http:
      paths:
      - path: /api
        pathType: Prefix
        backend:
          service:
            name: backend-service
            port:
              number: 8000
      - path: /
        pathType: Prefix
        backend:
          service:
            name: frontend-service
            port:
              number: 3000
```

## 🔧 Helm Chart (Alternative)

### Structure Helm

```
helm/
└── fullstack-app/
    ├── Chart.yaml
    ├── values.yaml
    ├── values-prod.yaml
    ├── values-staging.yaml
    └── templates/
        ├── backend/
        ├── frontend/
        ├── database/
        ├── ingress.yaml
        └── _helpers.tpl
```

### Chart.yaml

```yaml
# helm/fullstack-app/Chart.yaml
apiVersion: v2
name: fullstack-app
description: Full-Stack Application with FastAPI and React
type: application
version: 1.0.0
appVersion: "1.0.0"
keywords:
  - fastapi
  - react
  - postgresql
maintainers:
  - name: Your Name
    email: your.email@domain.com
```

### values.yaml

```yaml
# helm/fullstack-app/values.yaml
global:
  environment: production
  domain: yourdomain.com

backend:
  replicaCount: 3
  image:
    repository: your-registry/fullstack-backend
    tag: latest
    pullPolicy: Always
  resources:
    requests:
      cpu: 100m
      memory: 256Mi
    limits:
      cpu: 1000m
      memory: 512Mi
  autoscaling:
    enabled: true
    minReplicas: 3
    maxReplicas: 10
    targetCPUUtilization: 70

frontend:
  replicaCount: 2
  image:
    repository: your-registry/fullstack-frontend
    tag: latest
  resources:
    requests:
      cpu: 50m
      memory: 128Mi
    limits:
      cpu: 200m
      memory: 256Mi

postgres:
  replicaCount: 3
  storage:
    size: 50Gi
    storageClass: fast-ssd
  resources:
    requests:
      cpu: 500m
      memory: 1Gi
    limits:
      cpu: 2000m
      memory: 2Gi

redis:
  replicaCount: 1
  resources:
    requests:
      cpu: 100m
      memory: 128Mi
    limits:
      cpu: 500m
      memory: 512Mi

ingress:
  enabled: true
  className: nginx
  annotations:
    cert-manager.io/cluster-issuer: letsencrypt-prod
  tls:
    enabled: true
    secretName: tls-secret
```

### Installation Helm

```bash
# Ajouter le repository
helm repo add fullstack-app ./helm/fullstack-app

# Installer en développement
helm install fullstack-app ./helm/fullstack-app \
  -f helm/fullstack-app/values.yaml \
  -n fullstack-app

# Installer en production
helm install fullstack-app ./helm/fullstack-app \
  -f helm/fullstack-app/values-prod.yaml \
  -n fullstack-app

# Mettre à jour
helm upgrade fullstack-app ./helm/fullstack-app \
  -f helm/fullstack-app/values-prod.yaml \
  -n fullstack-app

# Rollback
helm rollback fullstack-app 1 -n fullstack-app
```

## 🔄 Migration Progressive

### Stratégie Blue-Green

```bash
# Déployer la nouvelle version (green)
kubectl apply -f k8s/backend/deployment-green.yaml

# Tester
kubectl port-forward service/backend-service-green 8000:8000

# Basculer le traffic
kubectl patch service backend-service -p '{"spec":{"selector":{"version":"green"}}}'

# Supprimer l'ancienne version si OK
kubectl delete deployment backend-blue
```

### Stratégie Canary

```yaml
# k8s/backend/canary-deployment.yaml
apiVersion: apps/v1
kind: Deployment
metadata:
  name: backend-canary
  namespace: fullstack-app
spec:
  replicas: 1  # 10% du traffic
  # ... même config que deployment principal
```

## 📊 Monitoring sur Kubernetes

### Prometheus Operator

```bash
# Installer Prometheus Operator
helm repo add prometheus-community https://prometheus-community.github.io/helm-charts
helm install prometheus prometheus-community/kube-prometheus-stack \
  -n monitoring --create-namespace
```

### ServiceMonitor pour Backend

```yaml
# k8s/monitoring/servicemonitor.yaml
apiVersion: monitoring.coreos.com/v1
kind: ServiceMonitor
metadata:
  name: backend-metrics
  namespace: fullstack-app
spec:
  selector:
    matchLabels:
      app: backend
  endpoints:
  - port: http
    path: /metrics
    interval: 30s
```

## 🚀 Déploiement Complet

### Script de Déploiement

```bash
#!/bin/bash
# scripts/deploy-k8s.sh

set -e

NAMESPACE="fullstack-app"
ENVIRONMENT=${1:-production}

echo "🚀 Deploying to Kubernetes ($ENVIRONMENT)..."

# Créer le namespace
kubectl create namespace $NAMESPACE --dry-run=client -o yaml | kubectl apply -f -

# Appliquer les secrets
echo "🔐 Creating secrets..."
kubectl apply -f k8s/base/secrets.yaml -n $NAMESPACE

# Appliquer les ConfigMaps
echo "⚙️ Creating configmaps..."
kubectl apply -f k8s/base/configmap.yaml -n $NAMESPACE

# Déployer la base de données
echo "🗄️ Deploying database..."
kubectl apply -f k8s/database/ -n $NAMESPACE
kubectl rollout status statefulset/postgres -n $NAMESPACE

# Déployer Redis
echo "📦 Deploying Redis..."
kubectl apply -f k8s/redis/ -n $NAMESPACE
kubectl rollout status deployment/redis -n $NAMESPACE

# Déployer le backend
echo "🔧 Deploying backend..."
kubectl apply -f k8s/backend/ -n $NAMESPACE
kubectl rollout status deployment/backend -n $NAMESPACE

# Déployer Celery
echo "⚙️ Deploying Celery..."
kubectl apply -f k8s/celery/ -n $NAMESPACE
kubectl rollout status deployment/celery -n $NAMESPACE

# Déployer le frontend
echo "🎨 Deploying frontend..."
kubectl apply -f k8s/frontend/ -n $NAMESPACE
kubectl rollout status deployment/frontend -n $NAMESPACE

# Appliquer l'Ingress
echo "🌐 Creating ingress..."
kubectl apply -f k8s/base/ingress.yaml -n $NAMESPACE

# Vérifier le statut
echo "✅ Deployment complete!"
kubectl get pods -n $NAMESPACE
kubectl get services -n $NAMESPACE
kubectl get ingress -n $NAMESPACE

echo "🔍 To check logs: kubectl logs -f deployment/backend -n $NAMESPACE"
echo "🌐 Application should be available at: https://yourdomain.com"
```

## 💡 Bonnes Pratiques Kubernetes

### 1. Gestion des Resources

```yaml
# Toujours définir requests et limits
resources:
  requests:
    cpu: 100m       # Minimum garanti
    memory: 256Mi
  limits:
    cpu: 1000m      # Maximum autorisé
    memory: 512Mi
```

### 2. Health Checks

```yaml
# Liveness: Redémarrer si le container est bloqué
livenessProbe:
  httpGet:
    path: /health
    port: 8000
  initialDelaySeconds: 30
  periodSeconds: 10

# Readiness: Ne pas envoyer de traffic tant que pas prêt
readinessProbe:
  httpGet:
    path: /health
    port: 8000
  initialDelaySeconds: 5
  periodSeconds: 5
```

### 3. Security Context

```yaml
securityContext:
  runAsNonRoot: true
  runAsUser: 1000
  readOnlyRootFilesystem: true
  capabilities:
    drop:
      - ALL
```

### 4. Network Policies

```yaml
# k8s/base/network-policy.yaml
apiVersion: networking.k8s.io/v1
kind: NetworkPolicy
metadata:
  name: backend-network-policy
  namespace: fullstack-app
spec:
  podSelector:
    matchLabels:
      app: backend
  policyTypes:
  - Ingress
  - Egress
  ingress:
  - from:
    - podSelector:
        matchLabels:
          app: frontend
    ports:
    - protocol: TCP
      port: 8000
  egress:
  - to:
    - podSelector:
        matchLabels:
          app: postgres
    ports:
    - protocol: TCP
      port: 5432
```

## 📚 Ressources

- [Kubernetes Documentation](https://kubernetes.io/docs/)
- [Helm Documentation](https://helm.sh/docs/)
- [Kubernetes Best Practices](https://kubernetes.io/docs/concepts/configuration/overview/)
- [12 Factor App](https://12factor.net/)