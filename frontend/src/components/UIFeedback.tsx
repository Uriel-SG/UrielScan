import React, { createContext, useContext, useState, useEffect, useCallback } from 'react';
import { 
  AlertTriangle, 
  CheckCircle2, 
  Info, 
  XCircle, 
  X, 
  Loader2 
} from 'lucide-react';
import { useI18n } from '../i18n/LanguageContext';

export type ToastType = 'success' | 'error' | 'info' | 'warning';

export interface ToastItem {
  id: string;
  type: ToastType;
  message: string;
  title?: string;
}

interface ToastContextType {
  showToast: (message: string, type?: ToastType, title?: string) => void;
}

const ToastContext = createContext<ToastContextType | undefined>(undefined);

export const ToastProvider: React.FC<{ children: React.ReactNode }> = ({ children }) => {
  const { L } = useI18n();
  const [toasts, setToasts] = useState<ToastItem[]>([]);

  const showToast = useCallback((message: string, type: ToastType = 'info', title?: string) => {
    const id = `${Date.now()}-${Math.random().toString(36).substring(2, 7)}`;
    const newToast: ToastItem = { id, type, message, title };
    setToasts((prev) => [...prev, newToast]);

    setTimeout(() => {
      setToasts((prev) => prev.filter((t) => t.id !== id));
    }, 4500);
  }, []);

  const removeToast = useCallback((id: string) => {
    setToasts((prev) => prev.filter((t) => t.id !== id));
  }, []);

  return (
    <ToastContext.Provider value={{ showToast }}>
      {children}
      {/* Toast viewport */}
      <div className="fixed bottom-4 right-4 z-50 flex flex-col gap-2 max-w-md w-full pointer-events-none px-3">
        {toasts.map((toast) => {
          let borderClass = 'border-theme';
          let icon = <Info className="w-4 h-4 text-sky-400 shrink-0" />;

          if (toast.type === 'success') {
            borderClass = 'border-emerald-500/40 bg-emerald-950/20';
            icon = <CheckCircle2 className="w-4 h-4 text-emerald-400 shrink-0" />;
          } else if (toast.type === 'error') {
            borderClass = 'border-red-500/40 bg-red-950/20';
            icon = <XCircle className="w-4 h-4 text-red-400 shrink-0" />;
          } else if (toast.type === 'warning') {
            borderClass = 'border-amber-500/40 bg-amber-950/20';
            icon = <AlertTriangle className="w-4 h-4 text-amber-400 shrink-0" />;
          }

          return (
            <div
              key={toast.id}
              className={`pointer-events-auto flex items-start gap-3 p-3 card-industrial shadow-xl backdrop-blur-md transition-all animate-in fade-in slide-in-from-bottom-2 ${borderClass}`}
              style={{ backgroundColor: 'var(--bg-panel)' }}
            >
              <div className="mt-0.5">{icon}</div>
              <div className="flex-1 min-w-0">
                {toast.title && (
                  <div className="text-xs font-semibold text-theme-primary mb-0.5">
                    {toast.title}
                  </div>
                )}
                <div className="text-xs text-theme-secondary break-words leading-relaxed">
                  {toast.message}
                </div>
              </div>
              <button
                onClick={() => removeToast(toast.id)}
                className="text-theme-muted hover:text-theme-primary transition-colors p-0.5"
                aria-label={L('Close notification', 'Chiudi notifica')}
              >
                <X className="w-3.5 h-3.5" />
              </button>
            </div>
          );
        })}
      </div>
    </ToastContext.Provider>
  );
};

export const useToast = (): ToastContextType => {
  const context = useContext(ToastContext);
  if (!context) {
    throw new Error('useToast deve essere utilizzato all\'interno di un ToastProvider');
  }
  return context;
};

// ==========================================
// CUSTOM CONFIRM MODAL (NO WINDOW.CONFIRM)
// ==========================================

export interface ConfirmModalProps {
  isOpen: boolean;
  title: string;
  description: string;
  confirmText?: string;
  cancelText?: string;
  isDestructive?: boolean;
  isLoading?: boolean;
  onConfirm: () => void | Promise<void>;
  onCancel: () => void;
}

export const ConfirmModal: React.FC<ConfirmModalProps> = ({
  isOpen,
  title,
  description,
  confirmText,
  cancelText,
  isDestructive = true,
  isLoading = false,
  onConfirm,
  onCancel,
}) => {
  const { L } = useI18n();
  const finalConfirmText = confirmText ?? L('Confirm', 'Conferma');
  const finalCancelText = cancelText ?? L('Cancel', 'Annulla');

  // ESC key handler
  useEffect(() => {
    const handleKeyDown = (e: KeyboardEvent) => {
      if (e.key === 'Escape' && isOpen && !isLoading) {
        onCancel();
      }
    };
    window.addEventListener('keydown', handleKeyDown);
    return () => window.removeEventListener('keydown', handleKeyDown);
  }, [isOpen, isLoading, onCancel]);

  if (!isOpen) return null;

  return (
    <div className="fixed inset-0 z-50 flex items-center justify-center p-4 bg-black/60 backdrop-blur-sm animate-in fade-in duration-150">
      <div 
        className="card-industrial w-full max-w-md p-6 shadow-2xl relative border-theme overflow-hidden"
        style={{ backgroundColor: 'var(--bg-panel)' }}
      >
        <div className="flex items-start gap-3.5 mb-4">
          <div className={`p-2.5 rounded border shrink-0 ${isDestructive ? 'bg-red-500/10 border-red-500/30 text-red-500' : 'bg-amber-500/10 border-amber-500/30 text-amber-500'}`}>
            <AlertTriangle className="w-5 h-5" />
          </div>
          <div className="flex-1 min-w-0">
            <h3 className="text-sm font-bold text-theme-primary tracking-tight mb-1">
              {title}
            </h3>
            <p className="text-xs text-theme-secondary leading-relaxed">
              {description}
            </p>
          </div>
        </div>

        <div className="flex items-center justify-end gap-2.5 mt-6 pt-3 border-t border-theme-subtle">
          <button
            type="button"
            disabled={isLoading}
            onClick={onCancel}
            className="btn-secondary px-3.5 py-1.5 text-xs font-medium disabled:opacity-50"
          >
            {finalCancelText}
          </button>
          <button
            type="button"
            disabled={isLoading}
            onClick={onConfirm}
            className={`px-3.5 py-1.5 text-xs font-semibold rounded flex items-center gap-1.5 disabled:opacity-50 ${
              isDestructive 
                ? 'bg-red-600 hover:bg-red-700 text-white' 
                : 'btn-primary'
            }`}
          >
            {isLoading && <Loader2 className="w-3.5 h-3.5 animate-spin" />}
            {finalConfirmText}
          </button>
        </div>
      </div>
    </div>
  );
};
