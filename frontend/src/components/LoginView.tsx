import React, { useState } from 'react';
import { 
  ShieldCheck, 
  Lock, 
  User, 
  KeyRound, 
  ArrowRight, 
  Loader2, 
  ChevronLeft,
  AlertCircle,
  Languages
} from 'lucide-react';
import { api } from '../services/api';
import { AuthUser } from '../types';
import { useI18n } from '../i18n/LanguageContext';

interface LoginViewProps {
  onLoginSuccess: (user: AuthUser) => void;
  currentTheme?: string;
}

export const LoginView: React.FC<LoginViewProps> = ({ onLoginSuccess, currentTheme = 'uriel-ops' }) => {
  const { lang, setLang, L } = useI18n();
  const [step, setStep] = useState<'credentials' | 'totp'>('credentials');
  const [username, setUsername] = useState('');
  const [password, setPassword] = useState('');
  const [tempToken, setTempToken] = useState('');
  const [totpCode, setTotpCode] = useState('');
  const [isLoading, setIsLoading] = useState(false);
  const [error, setError] = useState<string | null>(null);

  const handleCredentialsSubmit = async (e: React.FormEvent) => {
    e.preventDefault();
    if (!username.trim() || !password) {
      setError(L('Please enter both username and password.', 'Inserisci sia username che password.'));
      return;
    }

    setIsLoading(true);
    setError(null);

    try {
      const res = await api.login(username.trim(), password);
      if (res.requires_2fa && res.temp_token) {
        setTempToken(res.temp_token);
        setStep('totp');
      } else if (res.user) {
        onLoginSuccess(res.user);
      } else {
        // Fallback user state
        onLoginSuccess({ id: 1, username: username.trim(), two_factor_enabled: false });
      }
    } catch (err: any) {
      setError(err.message || L('Invalid credentials or connection error.', 'Credenziali non valide o errore di connessione.'));
    } finally {
      setIsLoading(false);
    }
  };

  const handleTotpSubmit = async (e: React.FormEvent) => {
    e.preventDefault();
    if (!totpCode.trim() || totpCode.trim().length !== 6) {
      setError(L('Please enter the 6-digit security code.', 'Inserisci il codice di sicurezza a 6 cifre.'));
      return;
    }

    setIsLoading(true);
    setError(null);

    try {
      const res = await api.verify2FA(tempToken, totpCode.trim());
      if (res.user) {
        onLoginSuccess(res.user);
      } else {
        onLoginSuccess({ id: 1, username, two_factor_enabled: true });
      }
    } catch (err: any) {
      setError(err.message || L('Invalid or expired 2FA code. Please try again.', 'Codice 2FA errato o scaduto. Riprova.'));
    } finally {
      setIsLoading(false);
    }
  };

  return (
    <div className="min-h-screen w-full flex items-center justify-center p-4 bg-canvas">
      <div className="w-full max-w-sm">
        {/* Brand header */}
        <div className="text-center mb-6">
          <img
            src={`/urielscan-logo-${currentTheme}.png`}
            alt="UrielScan"
            className="w-56 h-auto mx-auto mb-2 object-contain select-none transition-all duration-200"
          />
          <p className="text-xs text-theme-secondary mt-1">
            {L('Purple Team Security Assessment & Exposure Management', 'Purple Team Security Assessment & Gestione Esposizione')}
          </p>
        </div>

        {/* Card */}
        <div className="card-industrial p-6 shadow-2xl bg-panel relative">
          {/* Top card header with Language toggle */}
          <div className="flex items-center justify-between pb-3 mb-4 border-b border-theme-subtle">
            <span className="text-[11px] font-mono uppercase tracking-wider text-theme-muted font-bold">
              {step === 'credentials' ? L('Authentication', 'Autenticazione') : L('2FA Challenge', 'Verifica 2FA')}
            </span>
            <div className="inline-flex items-center gap-1 px-1.5 py-0.5 rounded border border-theme bg-subtle text-[10px] font-mono">
              <Languages className="w-3 h-3 text-theme-muted" />
              <button
                type="button"
                onClick={() => setLang('en')}
                className={`px-1 py-0.2 rounded font-bold uppercase transition-colors ${
                  lang === 'en' ? 'bg-theme-accent text-white' : 'text-theme-muted hover:text-theme-primary'
                }`}
              >
                EN
              </button>
              <span className="text-theme-subtle">|</span>
              <button
                type="button"
                onClick={() => setLang('it')}
                className={`px-1 py-0.2 rounded font-bold uppercase transition-colors ${
                  lang === 'it' ? 'bg-theme-accent text-white' : 'text-theme-muted hover:text-theme-primary'
                }`}
              >
                IT
              </button>
            </div>
          </div>

          {error && (
            <div className="mb-4 p-2.5 rounded border border-red-500/30 bg-red-950/20 text-red-400 text-xs flex items-center gap-2">
              <AlertCircle className="w-4 h-4 shrink-0" />
              <span>{error}</span>
            </div>
          )}

          {step === 'credentials' ? (
            <form onSubmit={handleCredentialsSubmit} className="space-y-4">
              <div>
                <label className="block text-xs font-semibold text-theme-secondary mb-1">
                  {L('Username', 'Nome Utente')}
                </label>
                <div className="relative">
                  <span className="absolute inset-y-0 left-0 pl-3 flex items-center pointer-events-none text-theme-muted">
                    <User className="w-4 h-4" />
                  </span>
                  <input
                    type="text"
                    value={username}
                    onChange={(e) => setUsername(e.target.value)}
                    required
                    autoFocus
                    placeholder="admin"
                    className="input-industrial w-full pl-9 pr-3 py-2 text-xs"
                  />
                </div>
              </div>

              <div>
                <label className="block text-xs font-semibold text-theme-secondary mb-1">
                  {L('Operator Password', 'Password Operatore')}
                </label>
                <div className="relative">
                  <span className="absolute inset-y-0 left-0 pl-3 flex items-center pointer-events-none text-theme-muted">
                    <Lock className="w-4 h-4" />
                  </span>
                  <input
                    type="password"
                    value={password}
                    onChange={(e) => setPassword(e.target.value)}
                    required
                    placeholder="••••••••"
                    className="input-industrial w-full pl-9 pr-3 py-2 text-xs"
                  />
                </div>
              </div>

              <div className="pt-2">
                <button
                  type="submit"
                  disabled={isLoading}
                  className="btn-primary w-full py-2 px-4 text-xs font-semibold flex items-center justify-center gap-2"
                >
                  {isLoading ? (
                    <Loader2 className="w-4 h-4 animate-spin" />
                  ) : (
                    <>
                      <span>{L('Sign in to Console', 'Accedi alla Console')}</span>
                      <ArrowRight className="w-3.5 h-3.5" />
                    </>
                  )}
                </button>
              </div>

              <div className="mt-4 pt-3 border-t border-theme-subtle text-center">
                <p className="text-[11px] text-theme-muted font-mono">
                  {L('Default installation credentials: ', 'Credenziali predefinite installazione: ')}<strong className="text-theme-secondary">admin / admin</strong>
                </p>
              </div>
            </form>
          ) : (
            <form onSubmit={handleTotpSubmit} className="space-y-4">
              <div className="text-center mb-3">
                <div className="inline-flex p-2 rounded border border-theme bg-subtle text-theme-accent mb-2">
                  <KeyRound className="w-5 h-5" />
                </div>
                <h3 className="text-xs font-bold text-theme-primary">
                  {L('Two-Factor Authentication (2FA TOTP)', 'Autenticazione a Due Fattori (2FA TOTP)')}
                </h3>
                <p className="text-[11px] text-theme-secondary mt-1">
                  {L('Enter the 6-digit temporary code from your authenticator app.', 'Inserisci il codice temporaneo a 6 cifre dalla tua app di autenticazione.')}
                </p>
              </div>

              <div>
                <input
                  type="text"
                  maxLength={6}
                  value={totpCode}
                  onChange={(e) => setTotpCode(e.target.value.replace(/\D/g, ''))}
                  required
                  autoFocus
                  placeholder="000000"
                  className="input-industrial w-full py-2.5 text-center text-lg font-mono tracking-widest tabular-nums"
                />
              </div>

              <div className="pt-2 flex items-center gap-2">
                <button
                  type="button"
                  onClick={() => {
                    setStep('credentials');
                    setError(null);
                  }}
                  className="btn-secondary py-2 px-3 text-xs flex items-center gap-1"
                >
                  <ChevronLeft className="w-3.5 h-3.5" />
                  <span>{L('Back', 'Indietro')}</span>
                </button>
                <button
                  type="submit"
                  disabled={isLoading || totpCode.length !== 6}
                  className="btn-primary flex-1 py-2 px-3 text-xs font-semibold flex items-center justify-center gap-2 disabled:opacity-50"
                >
                  {isLoading ? (
                    <Loader2 className="w-4 h-4 animate-spin" />
                  ) : (
                    <span>{L('Verify & Enter', 'Verifica & Entra')}</span>
                  )}
                </button>
              </div>
            </form>
          )}
        </div>

        {/* Footer info */}
        <div className="mt-6 text-center text-[11px] text-theme-muted">
          <span>{L('UrielScan Enterprise • Multi-Tenant MSSP Architecture', 'UrielScan Enterprise • Architettura Multi-Tenant MSSP')}</span>
        </div>
      </div>
    </div>
  );
};
