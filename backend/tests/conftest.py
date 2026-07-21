# conftest.py — configuration pytest pour le backend
# Ajoute le répertoire backend/ au PYTHONPATH automatiquement

import sys
from pathlib import Path

# S'assurer que le répertoire backend/ est dans sys.path
backend_dir = Path(__file__).resolve().parent.parent
if str(backend_dir) not in sys.path:
    sys.path.insert(0, str(backend_dir))
