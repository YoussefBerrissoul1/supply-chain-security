import React, { Component, ErrorInfo, ReactNode } from 'react';
import { logger } from '@/lib/errors/logger';
import { StatusLayout } from '@/components/error/StatusLayout';

interface Props {
  children?: ReactNode;
}

interface State {
  hasError: boolean;
  error: Error | null;
}

export class ErrorBoundary extends Component<Props, State> {
  public state: State = {
    hasError: false,
    error: null,
  };

  public static getDerivedStateFromError(error: Error): State {
    return { hasError: true, error };
  }

  public componentDidCatch(error: Error, errorInfo: ErrorInfo) {
    // Log the error centrally securely
    logger.error(error, { errorInfo, source: 'ErrorBoundary' });
  }

  public render() {
    if (this.state.hasError) {
      // Use the generic UNKNOWN status layout which provides the secure fallback UI
      return <StatusLayout code="UNKNOWN" />;
    }

    return this.props.children;
  }
}

