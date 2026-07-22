import React, { lazy, Suspense } from 'react';
import { QueryClient, QueryClientProvider } from '@tanstack/react-query';
import { Toaster } from '@/components/ui/toaster';
import { TooltipProvider } from '@/components/ui/tooltip';
import { motion } from 'framer-motion';
import { Switch, Route } from 'wouter';

import { useScrollTheme } from './hooks/useScrollTheme';
import { Navbar }         from './components/Navbar';
import { Hero }           from './sections/Hero';
import { Probleme }       from './sections/Probleme';
import { Features }       from './sections/Features';
import { TerminalAnimated } from './sections/Terminal';
import { SRMIntegration } from './sections/SRMIntegration';
import { Score }          from './sections/Score';
import { Resultats }      from './sections/Resultats';
import { SRMEntreprise }  from './sections/SRMEntreprise';
import { SRMPont }        from './sections/SRMPont';
import { TechStack }      from './sections/TechStack';
import { CTAFinal }       from './sections/CTAFinal';
import { Footer }         from './sections/Footer';
import { ScanPage }       from './pages/ScanPage';

// Security and Error Handling
import { ProtectedRoute } from './components/ProtectedRoute';
import { ErrorBoundary } from './components/ErrorBoundary';

// Lazy load status pages
const Page400 = lazy(() => import('./pages/status/Page400'));
const Page401 = lazy(() => import('./pages/status/Page401'));
const Page403 = lazy(() => import('./pages/status/Page403'));
const Page404 = lazy(() => import('./pages/status/Page404'));
const Page408 = lazy(() => import('./pages/status/Page408'));
const Page409 = lazy(() => import('./pages/status/Page409'));
const Page410 = lazy(() => import('./pages/status/Page410'));
const Page422 = lazy(() => import('./pages/status/Page422'));
const Page429 = lazy(() => import('./pages/status/Page429'));
const Page500 = lazy(() => import('./pages/status/Page500'));
const Page502 = lazy(() => import('./pages/status/Page502'));
const Page503 = lazy(() => import('./pages/status/Page503'));
const Page504 = lazy(() => import('./pages/status/Page504'));
const PageUnknown = lazy(() => import('./pages/status/PageUnknown'));

const queryClient = new QueryClient();

// A simple component to trigger the ErrorBoundary intentionally
function TestError() {
  throw new Error('This is a test error to show the ErrorBoundary page');
  return <div />;
}

function LandingPage() {
  const { backgroundColor, textColor } = useScrollTheme();

  return (
    <div className="w-full min-h-screen font-sans antialiased text-[#12131a]">
      <Navbar />
      <div id="projet"><Hero /></div>
      <motion.div style={{ backgroundColor, color: textColor }} className="transition-colors duration-100 ease-linear">
        <Probleme />
        <Features />
        <TerminalAnimated />
        <SRMIntegration />
        <Score />
        <Resultats />
        <SRMEntreprise />
        <SRMPont />
        <TechStack />
        <CTAFinal />
      </motion.div>
      <Footer />
    </div>
  );
}

function App() {
  return (
    <ErrorBoundary>
      <QueryClientProvider client={queryClient}>
        <TooltipProvider>
          <Suspense fallback={<div className="min-h-screen bg-[#f7f8fb]" />}>
            <Switch>
              {/* Core Routes */}
              <Route path="/" component={LandingPage} />
              
              {/* Protected Routes */}
              <Route path="/scan">
                <ProtectedRoute component={ScanPage} />
              </Route>

              {/* Status & Error Testing Routes */}
              <Route path="/test-error" component={TestError} />
              <Route path="/400" component={Page400} />
              <Route path="/401" component={Page401} />
              <Route path="/403" component={Page403} />
              <Route path="/404" component={Page404} />
              <Route path="/408" component={Page408} />
              <Route path="/409" component={Page409} />
              <Route path="/410" component={Page410} />
              <Route path="/422" component={Page422} />
              <Route path="/429" component={Page429} />
              <Route path="/500" component={Page500} />
              <Route path="/502" component={Page502} />
              <Route path="/503" component={Page503} />
              <Route path="/504" component={Page504} />
              
              {/* Catch-all 404 Route */}
              <Route component={Page404} />
            </Switch>
          </Suspense>
          <Toaster />
        </TooltipProvider>
      </QueryClientProvider>
    </ErrorBoundary>
  );
}

export default App;

