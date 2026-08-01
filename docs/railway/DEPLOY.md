# Deploy no Railway — Dashboard Z.T.K. (Grátis)

![Railway](https://img.shields.io/badge/Railway-Free_Tier-0B0D0E?logo=railway)
![Deploy](https://img.shields.io/badge/deploy-2_minutos-00ff88)

> **Plataforma:** Railway.app | **Custo:** $0 (free tier) | **Stack:** FastAPI + Jinja2

---

## 1. Deploy em 2 minutos

### Opcao A — Railway Dashboard (recomendado)

```
1. Acesse https://railway.app → Login com GitHub
2. New Project → Deploy from GitHub repo
3. Selecione rcenerini/Z.T.K.
4. Railway detecta railway.json automaticamente
5. Deploy inicia — URL disponivel em ~2 min
```

### Opcao B — Railway CLI

```bash
# Instalar CLI
npm i -g @railway/cli

# Login
railway login

# Link ao projeto
railway link

# Deploy
railway up
```

---

## 2. URLs apos deploy

|URL | Descricao |
|-----|-----------|
|`https://ztk.up.railway.app/docs` | Swagger/OpenAPI |
|`https://ztk.up.railway.app/admin.html` | Admin Dashboard (9 tabs) |
|`https://ztk.up.railway.app/dashboard.html` | Exception Dashboard |
|`https://ztk.up.railway.app/api/auth/dev-tokens` | Dev tokens |
|`https://ztk.up.railway.app/api/health` | Health check |

---

## 3. Variaveis de Ambiente (opcional)

| Variavel | Default | Descricao |
|----------|---------|-----------|
| `PORT` | 8000 | Porta (Railway define automaticamente) |
| `ZTK_JWT_SECRET` | dev-secret | JWT signing key (trocar em producao) |

---

## 4. Limites Free Tier

| Recurso | Limite | Suficiente? |
|---------|--------|-------------|
| RAM | 512 MB | ✅ Dashboard usa ~50MB |
| CPU | 0.5 vCPU | ✅ FastAPI e leve |
| Deploy/mes | 500 | ✅ Sobra |
| Execucao | 24/7 (sleep apos inatividade) | ✅ POC |
| Domínio customizado | Sim | ✅ |
