# Guide de Démarrage et Commandes de Test

Ce document regroupe toutes les commandes nécessaires pour démarrer le projet et exécuter les tests.

---

## 1. Prérequis et Initialisation

Avant de lancer les commandes, ouvrez votre terminal (PowerShell ou CMD) à la racine du dossier backend :
```powershell
cd c:\Users\joseph\Documents\supply-chain-security\backend
```

### A. Activer l'environnement virtuel Python (venv)
- **Sur Windows (PowerShell)** :
  ```powershell
  .\venv\Scripts\Activate.ps1
  ```
- **Sur Windows (CMD)** :
  ```cmd
  .\venv\Scripts\activate.bat
  ```

---

## 2. Lancer le Projet (Serveur API)

Pour démarrer le serveur FastAPI local avec rechargement automatique lors des modifications de code (mode debug) :
```bash
python -m uvicorn app.main:app --host 127.0.0.1 --port 8000 --reload .\venv\Scripts\Activate.ps1
```

Une fois lancé, vous verrez s'afficher :
- L'URL de l'API : `http://127.0.0.1:8000`
- La documentation interactive (Swagger UI) : `http://127.0.0.1:8000/docs`

---

## 3. Comment Tester l'API

### A. Via l'interface Swagger (Recommandé)
1. Ouvrez votre navigateur et allez sur : `http://127.0.0.1:8000/docs`
2. Déroulez la route **`POST /api/v1/analyze`** (icône verte).
3. Cliquez sur le bouton **"Try it out"** à droite.
4. Remplissez le corps de la requête avec les données de votre choix (ex. pour un scan Standard rapide) :
   ```json
   {
     "repo_url": "https://github.com/YoussefBerrissoul1/Nestle-Shop-Full-App-E-Commerce.git",
     "scan_type": "standard"
   }
   ```
5. Cliquez sur le gros bouton bleu **"Execute"**.
6. Vous obtiendrez une réponse `201 Created` contenant le statut `pending` et confirmant l'enregistrement en base PostgreSQL.

### B. Consulter l'historique des analyses
- Allez sur **`GET /api/v1/analyses`**, cliquez sur **"Try it out"** puis **"Execute"**. L'API vous retournera la liste des 10 dernières analyses stockées en base PostgreSQL.

---

## 4. Maintenance de la Base de Données (Alembic)

Si vous modifiez les modèles SQLAlchemy (`app/models/`) et souhaitez mettre à jour la base PostgreSQL :

1. **Générer une nouvelle migration automatique** :
   ```bash
   python -m alembic revision --autogenerate -m "nom_de_la_modification"
   ```
2. **Appliquer la migration sur PostgreSQL** :
   ```bash
   python -m alembic upgrade head
   ```

---

## 5. Activer l'IA (Gemini)

1. Obtenez une clé gratuite sur **[Google AI Studio](https://aistudio.google.com/)**.
2. Ouvrez le fichier de configuration `.env` : [backend/.env](file:///c:/Users/joseph/Documents/supply-chain-security/backend/.env)
3. Modifiez la ligne 9 pour y coller votre clé :
   ```env
   GEMINI_API_KEY=AIzaSyVotreCleObtenueSurLeSite...
   ```
4. Le service IA de FastAPI prendra automatiquement le relais à la place des règles de secours locales !
