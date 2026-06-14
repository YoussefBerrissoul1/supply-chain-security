# Guide de démarrage et de tests du projet

Ce guide décrit toutes les commandes nécessaires pour initialiser, démarrer et tester la plateforme d'audit de sécurité de la chaîne d'approvisionnement logicielle sur votre machine locale (Windows).

---

## 1. Origine du mot de passe de la base de données
Le mot de passe de la base de données PostgreSQL (`momo12`) a été récupéré directement depuis la configuration par défaut définie dans le code source de l'application à la ligne 31 du fichier [backend/app/core/config.py](file:///c:/Users/joseph/Documents/supply-chain-security/backend/app/core/config.py#L31) :
```python
DB_PASSWORD: str = "momo12"
```
Lors de la reprise du projet après votre formatage, nous avons testé ce mot de passe par défaut sur votre serveur PostgreSQL local. La connexion ayant réussi, nous avons pu recréer automatiquement la base de données `supply_chain_security` et appliquer le schéma.

---

## 2. Commandes de démarrage rapide

### Étape A : Activer l'environnement virtuel (venv)
Ouvrez un terminal Windows (PowerShell) dans le dossier du projet, puis déplacez-vous dans le dossier `backend` et activez l'environnement virtuel :
```powershell
cd c:\Users\joseph\Documents\supply-chain-security\backend
.\venv\Scripts\Activate.ps1
```

### Étape B : Appliquer les migrations de la base de données (Alembic)
Pour s'assurer que toutes les tables PostgreSQL sont créées et à jour :
```powershell
# Depuis le dossier backend avec venv activé :
alembic upgrade head
```

### Étape C : Démarrer le serveur FastAPI (Backend)
Pour démarrer le serveur API en mode de rechargement automatique (reload) lors du développement :
```powershell
# Option 1 (Recommandée - exécute le module python principal) :
python -m app.main

# Option 2 (Via la commande directe uvicorn) :
uvicorn app.main:app --reload
```
Le serveur sera disponible sur [http://localhost:8000](http://localhost:8000). Vous pouvez accéder à la documentation interactive des APIs (Swagger UI) sur [http://localhost:8000/docs](http://localhost:8000/docs).

---

## 3. Commandes de tests et validation

### Test de diagnostic de l'API (Health Check)
Vous pouvez vérifier que l'API fonctionne et qu'elle se connecte correctement à la base de données PostgreSQL en exécutant cette requête HTTP :
- **Via votre navigateur** ou un outil comme Postman : Ouvrez l'adresse [http://localhost:8000/api/v1/health](http://localhost:8000/api/v1/health)
- **Via PowerShell** :
  ```powershell
  Invoke-RestMethod -Uri "http://localhost:8000/api/v1/health" -Method Get
  ```
  Le résultat attendu est :
  ```json
  {
    "status": "healthy",
    "version": "1.0.0",
    "database": "connected"
  }
  ```

### Lancer les tests interactifs de diagnostic
Pour valider les différents services individuellement (clonage Git, scan Trivy, requête API OSV), nous pourrons utiliser le script de démonstration. Pour l'exécuter :
```powershell
# Depuis le dossier backend avec venv activé :
python scan_demo.py
```
*(Note : le script `scan_demo.py` avait été créé comme outil temporaire de démonstration avant le formatage).*
