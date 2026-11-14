/** @type {import('tailwindcss').Config} */
export default {
  content: [
    "./index.html",
    "./src/**/*.{js,ts,jsx,tsx}",
  ],
  darkMode: 'class',
  theme: {
    extend: {
      colors: {
        cyber: {
          dark: '#080a0f',
          card: '#0f141f',
          cardHover: '#161d2d',
          cardActive: '#1c2538',
          border: '#243048',
          borderSubtle: '#182032',
          purple: {
            DEFAULT: '#8b5cf6',
            glow: '#a855f7',
            dark: '#4c1d95',
            light: '#c084fc'
          },
          cyan: {
            DEFAULT: '#06b6d4',
            glow: '#22d3ee',
            dark: '#0e7490'
          },
          red: {
            DEFAULT: '#ef4444',
            glow: '#f87171',
            dark: '#7f1d1d'
          },
          emerald: {
            DEFAULT: '#10b981',
            glow: '#34d399',
            dark: '#064e3b'
          },
          amber: {
            DEFAULT: '#f59e0b',
            glow: '#fbbf24',
            dark: '#78350f'
          }
        }
      },
      boxShadow: {
        'purple-glow': '0 0 25px -5px rgba(139, 92, 246, 0.4)',
        'cyan-glow': '0 0 25px -5px rgba(6, 182, 212, 0.4)',
        'red-glow': '0 0 25px -5px rgba(239, 68, 68, 0.4)',
        'emerald-glow': '0 0 25px -5px rgba(16, 185, 129, 0.4)',
        'glass': '0 8px 32px 0 rgba(0, 0, 0, 0.37)'
      },
      backdropBlur: {
        xs: '2px',
      }
    },
  },
  plugins: [],
}
