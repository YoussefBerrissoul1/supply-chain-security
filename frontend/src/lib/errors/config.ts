import { 
  AlertTriangle, 
  Ban, 
  ShieldAlert, 
  SearchX, 
  Clock, 
  GitMerge, 
  Ghost, 
  FileWarning, 
  Activity, 
  ServerCrash, 
  CloudOff, 
  Wrench, 
  Timer,
  HelpCircle
} from 'lucide-react';
import { ErrorMetadata } from './types';

// Centralized source of truth for all status metadata
export const STATUS_CONFIG: Record<string | number, ErrorMetadata> = {
  400: {
    code: 400,
    title: 'Requête incorrecte',
    description: "Le serveur n'a pas pu comprendre votre requête en raison d'une syntaxe invalide. Veuillez vérifier vos données et réessayer.",
    icon: AlertTriangle,
    actions: [{ label: "Retour à l'accueil", href: '/', primary: true }]
  },
  401: {
    code: 401,
    title: 'Non autorisé',
    description: "Vous devez être authentifié pour accéder à cette ressource. Votre session a peut-être expiré.",
    icon: ShieldAlert,
    actions: [{ label: 'Se connecter', href: '/login', primary: true }, { label: "Retour à l'accueil", href: '/' }]
  },
  403: {
    code: 403,
    title: 'Accès refusé',
    description: "Vous n'avez pas les permissions nécessaires pour accéder à cette ressource ou effectuer cette action.",
    icon: Ban,
    actions: [{ label: "Retour à l'accueil", href: '/', primary: true }]
  },
  404: {
    code: 404,
    title: 'Page introuvable',
    description: "La page ou la ressource que vous recherchez n'existe pas, a été supprimée, ou son nom a changé.",
    icon: SearchX,
    actions: [{ label: "Retour à l'accueil", href: '/', primary: true }]
  },
  408: {
    code: 408,
    title: 'Délai dépassé',
    description: "La requête a mis trop de temps à aboutir. Veuillez vérifier votre connexion et réessayer.",
    icon: Clock,
    actions: [{ label: 'Réessayer', onClick: () => window.location.reload(), primary: true }]
  },
  409: {
    code: 409,
    title: 'Conflit de données',
    description: "La requête ne peut être traitée en l'état actuel car elle entre en conflit avec une autre ressource.",
    icon: GitMerge,
    actions: [{ label: 'Actualiser la page', onClick: () => window.location.reload(), primary: true }]
  },
  410: {
    code: 410,
    title: 'Ressource disparue',
    description: "Cette ressource n'est plus disponible et a été supprimée de manière permanente.",
    icon: Ghost,
    actions: [{ label: "Retour à l'accueil", href: '/', primary: true }]
  },
  422: {
    code: 422,
    title: 'Entité non traitable',
    description: "Les données envoyées sont syntaxiquement correctes mais n'ont pas pu être traitées (ex: erreur de validation).",
    icon: FileWarning,
    actions: [{ label: 'Vérifier la saisie', onClick: () => window.history.back(), primary: true }]
  },
  429: {
    code: 429,
    title: 'Trop de requêtes',
    description: "Vous avez envoyé trop de requêtes dans un laps de temps réduit. Veuillez patienter un moment avant de réessayer.",
    icon: Activity,
    actions: [{ label: 'Réessayer plus tard', onClick: () => window.location.reload(), primary: true }]
  },
  500: {
    code: 500,
    title: 'Erreur serveur',
    description: "Une erreur interne inattendue s'est produite sur le serveur. Nos équipes techniques ont été notifiées.",
    icon: ServerCrash,
    actions: [{ label: "Retour à l'accueil", href: '/', primary: true }, { label: 'Réessayer', onClick: () => window.location.reload() }]
  },
  502: {
    code: 502,
    title: 'Mauvaise passerelle',
    description: "Le serveur a reçu une réponse invalide depuis le serveur distant. Le service est temporairement indisponible.",
    icon: CloudOff,
    actions: [{ label: 'Réessayer', onClick: () => window.location.reload(), primary: true }]
  },
  503: {
    code: 503,
    title: 'Service indisponible',
    description: "Le serveur est actuellement incapable de traiter votre requête (maintenance ou surcharge). Veuillez réessayer plus tard.",
    icon: Wrench,
    actions: [{ label: 'Réessayer', onClick: () => window.location.reload(), primary: true }]
  },
  504: {
    code: 504,
    title: 'Délai d\'attente de la passerelle',
    description: "Le serveur n'a pas reçu de réponse à temps de la part des services en amont. La connexion est lente ou instable.",
    icon: Timer,
    actions: [{ label: 'Réessayer', onClick: () => window.location.reload(), primary: true }]
  },
  UNKNOWN: {
    code: 'UNKNOWN',
    title: 'Erreur inattendue',
    description: "Un comportement imprévu s'est produit. L'erreur a été enregistrée de manière sécurisée pour analyse.",
    icon: HelpCircle,
    actions: [{ label: "Retour à l'accueil", href: '/', primary: true }, { label: 'Recharger', onClick: () => window.location.reload() }]
  }
};
