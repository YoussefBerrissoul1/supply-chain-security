"""
Classe abstraite de base pour tous les providers CVE.
Définit l'interface commune (query individuel + query_batch optionnel).
"""
from abc import ABC, abstractmethod
from app.services.dependency_scanner import DependencyInfo
from app.services.cve_providers.models import VulnerabilityResult


class BaseCVEProvider(ABC):
    """
    Interface commune à tous les providers CVE (OSV, GHSA, NVD).
    
    Les sous-classes doivent implémenter :
    - query(dep)       : scan d'une dépendance unique
    - name (property)  : nom du provider
    
    Optionnel :
    - query_batch(deps): scan de plusieurs dépendances en une seule requête.
                         Par défaut, appelle query() en boucle.
                         OSVProvider override cette méthode avec /v1/querybatch.
    """

    @property
    @abstractmethod
    def name(self) -> str:
        """Nom lisible du provider (ex: 'OSV', 'GHSA', 'NVD')."""
        pass

    @abstractmethod
    def query(self, dep: DependencyInfo) -> list[VulnerabilityResult]:
        """
        Interroge ce provider pour une dépendance unique.
        Retourne une liste de VulnerabilityResult (vide si aucune CVE).
        """
        pass

    def query_batch(
        self, deps: list[DependencyInfo]
    ) -> dict[str, list[VulnerabilityResult]]:
        """
        Interroge ce provider pour plusieurs dépendances.
        
        Par défaut : appelle query() en boucle (1 requête par dépendance).
        
        Les providers supportant un endpoint batch (ex: OSV /v1/querybatch)
        peuvent override cette méthode pour n'envoyer qu'une seule requête HTTP.
        
        Retourne :
            dict["{name}@{version}" -> list[VulnerabilityResult]]
        """
        results: dict[str, list[VulnerabilityResult]] = {}
        for dep in deps:
            dep_key = f"{dep.name}@{dep.version}"
            try:
                results[dep_key] = self.query(dep)
            except Exception:
                results[dep_key] = []
        return results
