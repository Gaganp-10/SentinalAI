/** @type {import('tailwindcss').Config} */
export default {
  content: [
    "./index.html",
    "./src/**/*.{js,ts,jsx,tsx}",
  ],
  theme: {
    extend: {
      colors: {
        // SOC Design System — Phase 1
        void: '#070B09',
        panel: '#0F1613',
        'panel-hover': '#151F1A',
        'border-glow': '#1E3A2C',
        'border-glow-active': '#2ECC71',
        'text-primary': '#E7F5EC',
        'text-secondary': '#7C9186',
        'signal-green': '#2ECC71',
        'signal-green-bright': '#39FF88',
        sev: {
          critical: '#E5484D',
          high: '#F5A623',
          medium: '#F0C94A',
          low: '#4FD1C5',
          resolved: '#2ECC71',
        },
        // Legacy aliases (map old names → new palette)
        'panel-raised': '#151F1A',
        hair: '#1E3A2C',
        primary: '#E7F5EC',
        secondary: '#7C9186',
        amber: '#F5A623',
        cyan: '#4FD1C5',
        severity: {
          critical: '#E5484D',
          high: '#F5A623',
          medium: '#F0C94A',
          low: '#4FD1C5',
          info: '#7C9186',
        },
      },
      fontFamily: {
        sans: ['"IBM Plex Sans"', 'system-ui', '-apple-system', 'sans-serif'],
        mono: ['"IBM Plex Mono"', 'ui-monospace', 'monospace'],
        display: ['"Space Grotesk"', 'system-ui', 'sans-serif'],
      },
      // Type scale: 12 / 14 / 16 / 20 / 28 / 40 (+ intermediates for text-2xl/3xl)
      fontSize: {
        xs: ['12px', { lineHeight: '1.5' }],
        sm: ['14px', { lineHeight: '1.5' }],
        base: ['16px', { lineHeight: '1.6' }],
        lg: ['20px', { lineHeight: '1.4' }],
        xl: ['28px', { lineHeight: '1.3' }],
        '2xl': ['32px', { lineHeight: '1.25' }],
        '3xl': ['36px', { lineHeight: '1.2' }],
        '4xl': ['40px', { lineHeight: '1.15' }],
      },
      borderRadius: {
        DEFAULT: '6px',
        sm: '4px',
        md: '6px',
        lg: '8px',
        xl: '10px',
        '2xl': '12px',
        full: '9999px',
      },
      boxShadow: {
        glow: '0 0 24px -8px rgba(46, 204, 113, 0.35)',
        'glow-sm': '0 0 16px -6px rgba(46, 204, 113, 0.25)',
        'glow-focus': '0 0 0 1px var(--border-glow-active), 0 0 16px -4px rgba(46, 204, 113, 0.35)',
      },
      transitionDuration: {
        DEFAULT: '150ms',
        fast: '100ms',
        normal: '200ms',
      },
    },
  },
  plugins: [],
}
