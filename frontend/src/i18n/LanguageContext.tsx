import React, { createContext, useContext, useState, useCallback } from 'react';

export type Language = 'en' | 'it';

const STORAGE_KEY = 'urielscan_lang';

interface LanguageContextValue {
  lang: Language;
  setLang: (lang: Language) => void;
  locale: string;
  L: (en: string, it: string) => string;
}

const LanguageContext = createContext<LanguageContextValue>({
  lang: 'en',
  setLang: () => {},
  locale: 'en-US',
  L: (en) => en,
});

export const LanguageProvider: React.FC<{ children: React.ReactNode }> = ({ children }) => {
  const [lang, setLangState] = useState<Language>(() => {
    try {
      const saved = localStorage.getItem(STORAGE_KEY);
      if (saved === 'en' || saved === 'it') return saved;
    } catch {
      // ignore storage errors
    }
    return 'en';
  });

  const setLang = useCallback((next: Language) => {
    setLangState(next);
    try {
      localStorage.setItem(STORAGE_KEY, next);
    } catch {
      // ignore storage errors
    }
  }, []);

  const L = useCallback((en: string, it: string) => (lang === 'it' ? it : en), [lang]);
  const locale = lang === 'it' ? 'it-IT' : 'en-US';

  return (
    <LanguageContext.Provider value={{ lang, setLang, locale, L }}>
      {children}
    </LanguageContext.Provider>
  );
};

export const useI18n = () => useContext(LanguageContext);
