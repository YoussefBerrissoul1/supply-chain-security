export const logger = {
  /**
   * Centralized error logging utility.
   * In a production enterprise app, this integrates with Sentry, Datadog, etc.
   */
  error: (err: unknown, context?: Record<string, unknown>) => {
    // Safely log to console without leaking to the user UI
    console.error('[NEXORA Error Logger]', err, context ? { context } : '');
    // TODO: Send to external monitoring service
  },
  warn: (message: string, context?: Record<string, unknown>) => {
    console.warn('[NEXORA Warning Logger]', message, context ? { context } : '');
  }
};
