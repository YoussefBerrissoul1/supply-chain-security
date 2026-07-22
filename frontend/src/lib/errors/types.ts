import { LucideIcon } from 'lucide-react';

export interface ErrorAction {
  label: string;
  href?: string;
  onClick?: () => void;
  primary?: boolean;
}

export interface ErrorMetadata {
  code: number | 'UNKNOWN';
  title: string;
  description: string;
  icon: LucideIcon;
  actions: ErrorAction[];
}
