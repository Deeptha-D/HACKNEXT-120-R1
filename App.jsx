import React, { useState } from 'react';
import { AuthProvider, useAuth } from './context/AuthContext';
import { AccessibilityProvider } from './context/AccessibilityContext';
import Navbar from './components/Navbar';
import ParticleBackground from './components/ParticleBackground';
import RagAssistantWidget from './components/RagAssistantWidget';
import LandingPage from './pages/LandingPage';
import LoginPage from './pages/LoginPage';
import RegisterPage from './pages/RegisterPage';
import DashboardPage from './pages/DashboardPage';
import VaultPage from './pages/VaultPage';
import SecurityCenterPage from './pages/SecurityCenterPage';
import AuditLogsPage from './pages/AuditLogsPage';
import AdminDashboardPage from './pages/AdminDashboardPage';
import RagSupportPage from './pages/RagSupportPage';
import { Shield, Lock, Eye, Terminal } from 'lucide-react';

function AppContent() {
  const { isAuthenticated, user } = useAuth();
  const [currentRoute, setCurrentRoute] = useState('landing');

  // Route selector
  const renderRoute = () => {
    switch (currentRoute) {
      case 'login':
        return <LoginPage onNavigate={setCurrentRoute} />;
      case 'register':
        return <RegisterPage onNavigate={setCurrentRoute} />;
      case 'dashboard':
        return isAuthenticated ? (
          <DashboardPage onNavigate={setCurrentRoute} />
        ) : (
          <LoginPage onNavigate={setCurrentRoute} />
        );
      case 'vault':
        return isAuthenticated ? (
          <VaultPage />
        ) : (
          <LoginPage onNavigate={setCurrentRoute} />
        );
      case 'security':
        return isAuthenticated ? (
          <SecurityCenterPage />
        ) : (
          <LoginPage onNavigate={setCurrentRoute} />
        );
      case 'audit-logs':
        return isAuthenticated ? (
          <AuditLogsPage />
        ) : (
          <LoginPage onNavigate={setCurrentRoute} />
        );
      case 'admin':
        return isAuthenticated ? (
          <AdminDashboardPage />
        ) : (
          <LoginPage onNavigate={setCurrentRoute} />
        );
      case 'support':
        return <RagSupportPage />;
      default:
        return <LandingPage onNavigate={setCurrentRoute} />;
    }
  };

  return (
    <div className="min-h-screen flex flex-col relative text-slate-100 bg-navy-950">
      {/* WCAG Skip to Main Content Link for screen readers & keyboard navigation */}
      <a
        href="#main-content"
        className="sr-only focus:not-sr-only focus:absolute focus:top-2 focus:left-2 focus:z-50 focus:p-3 focus:bg-cyan-500 focus:text-navy-950 focus:font-bold focus:rounded-xl focus:shadow-glow-cyan"
      >
        Skip to main content
      </a>

      {/* Ambient Cyber Grid & Particle Canvas */}
      <ParticleBackground />

      {/* Navigation Header */}
      <Navbar currentRoute={currentRoute} onNavigate={setCurrentRoute} />

      {/* Main Page Content */}
      <main id="main-content" className="flex-1 relative z-10">
        {renderRoute()}
      </main>

      {/* Persistent Floating RAG Assistant Widget */}
      <RagAssistantWidget />

      {/* Footer */}
      <footer className="relative z-10 border-t border-slate-800/80 bg-navy-950/90 py-8 px-4 text-center text-xs text-slate-400">
        <div className="max-w-7xl mx-auto flex flex-col sm:flex-row items-center justify-between gap-4">
          <div className="flex items-center gap-2">
            <Shield className="w-4 h-4 text-cyan-400" />
            <span className="font-semibold text-white">AegisAuth Platform</span>
            <span>•</span>
            <span>Adaptive Zero-Trust Identity</span>
          </div>

          <div className="flex flex-wrap items-center justify-center gap-4 text-[11px] font-mono text-slate-400">
            <span className="flex items-center gap-1">
              <Lock className="w-3 h-3 text-cyan-400" /> AES-256-GCM Vault
            </span>
            <span className="flex items-center gap-1">
              <Eye className="w-3 h-3 text-emerald-400" /> WCAG 2.1 AA Compliant
            </span>
            <span className="flex items-center gap-1">
              <Terminal className="w-3 h-3 text-purple-400" /> TShark Packet Inspector
            </span>
          </div>

          <div className="text-[11px] text-slate-500 font-mono">
            Secure when risk is high. Frictionless when risk is low.
          </div>
        </div>
      </footer>
    </div>
  );
}

export default function App() {
  return (
    <AccessibilityProvider>
      <AuthProvider>
        <AppContent />
      </AuthProvider>
    </AccessibilityProvider>
  );
}
