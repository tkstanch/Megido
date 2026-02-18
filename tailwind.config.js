/** @type {import('tailwindcss').Config} */
module.exports = {
  content: [
    './templates/**/*.html',
    './*/templates/**/*.html',
    './static/**/*.js',
    './sqli_web/frontend/**/*.tsx',
    './sqli_web/frontend/**/*.ts',
  ],
  darkMode: 'class', // Enable class-based dark mode
  theme: {
    extend: {
      screens: {
        'xs': '375px',    // Mobile small
        'sm': '640px',    // Mobile large
        'md': '768px',    // Tablet
        'lg': '1024px',   // Laptop
        'xl': '1280px',   // Desktop
        '2xl': '1536px',  // Large desktop
        '3xl': '1920px',  // Full HD
        '4xl': '2560px',  // 4K
        'ultra': '3840px', // Ultra-wide/4K
      },
      spacing: {
        '128': '32rem',
        '144': '36rem',
      },
      fontSize: {
        '2xs': ['0.625rem', { lineHeight: '0.875rem' }],
        'fluid-xs': 'clamp(0.75rem, 1vw + 0.5rem, 0.875rem)',
        'fluid-sm': 'clamp(0.875rem, 1vw + 0.6rem, 1rem)',
        'fluid-base': 'clamp(1rem, 1.2vw + 0.7rem, 1.125rem)',
        'fluid-lg': 'clamp(1.125rem, 1.5vw + 0.8rem, 1.25rem)',
        'fluid-xl': 'clamp(1.25rem, 2vw + 0.9rem, 1.5rem)',
        'fluid-2xl': 'clamp(1.5rem, 2.5vw + 1rem, 2rem)',
        'fluid-3xl': 'clamp(1.875rem, 3vw + 1.2rem, 2.5rem)',
        'fluid-4xl': 'clamp(2.25rem, 4vw + 1.5rem, 3rem)',
      },
      colors: {
        // Enhanced primary purple/blue gradient theme
        primary: {
          50: '#f0f4ff',
          100: '#e0e9ff',
          200: '#c7d7fe',
          300: '#a5bbfc',
          400: '#8496f8',
          500: '#667eea', // Main primary color
          600: '#5568d3',
          700: '#4553b8',
          800: '#3a4694',
          900: '#333d76',
          950: '#1e2244',
        },
        secondary: {
          50: '#faf5ff',
          100: '#f3e8ff',
          200: '#e9d5ff',
          300: '#d8b4fe',
          400: '#c084fc',
          500: '#764ba2',
          600: '#6a4391',
          700: '#5d3b80',
          800: '#4c2e6a',
          900: '#3d2454',
        },
        // Enhanced status colors
        success: {
          50: '#ecfdf5',
          100: '#d1fae5',
          200: '#a7f3d0',
          300: '#6ee7b7',
          400: '#34d399',
          500: '#10b981',
          DEFAULT: '#10b981',
          600: '#059669',
          700: '#047857',
          800: '#065f46',
          dark: '#065f46',
          900: '#064e3b',
        },
        warning: {
          50: '#fffbeb',
          100: '#fef3c7',
          200: '#fde68a',
          300: '#fcd34d',
          400: '#fbbf24',
          500: '#f59e0b',
          DEFAULT: '#f59e0b',
          600: '#d97706',
          700: '#b45309',
          800: '#92400e',
          dark: '#92400e',
          900: '#78350f',
        },
        danger: {
          50: '#fef2f2',
          100: '#fee2e2',
          200: '#fecaca',
          300: '#fca5a5',
          400: '#f87171',
          500: '#ef4444',
          DEFAULT: '#ef4444',
          600: '#dc2626',
          700: '#b91c1c',
          800: '#991b1b',
          dark: '#991b1b',
          900: '#7f1d1d',
        },
        info: {
          50: '#eff6ff',
          100: '#dbeafe',
          200: '#bfdbfe',
          300: '#93c5fd',
          400: '#60a5fa',
          500: '#3b82f6',
          DEFAULT: '#3b82f6',
          600: '#2563eb',
          700: '#1d4ed8',
          800: '#1e40af',
          dark: '#1e40af',
          900: '#1e3a8a',
        },
        // Severity colors for security tools
        severity: {
          critical: '#dc2626',
          high: '#ea580c',
          medium: '#f59e0b',
          low: '#10b981',
        },
        // Professional Classic Colors v2.4
        emerald: {
          50: '#ecfdf5',
          100: '#d1fae5',
          200: '#a7f3d0',
          300: '#6ee7b7',
          400: '#34d399',
          500: '#10b981',
          600: '#059669',
          700: '#047857',
          800: '#065f46',
          900: '#064e3b',
        },
        sapphire: {
          50: '#eff6ff',
          100: '#dbeafe',
          200: '#bfdbfe',
          300: '#93c5fd',
          400: '#60a5fa',
          500: '#3b82f6',
          600: '#2563eb',
          700: '#1d4ed8',
          800: '#1e40af',
          900: '#1e3a8a',
        },
        ruby: {
          50: '#fef2f2',
          100: '#fee2e2',
          200: '#fecaca',
          300: '#fca5a5',
          400: '#f87171',
          500: '#ef4444',
          600: '#dc2626',
          700: '#b91c1c',
          800: '#991b1b',
          900: '#7f1d1d',
        },
        slate: {
          50: '#f8fafc',
          100: '#f1f5f9',
          200: '#e2e8f0',
          300: '#cbd5e1',
          400: '#94a3b8',
          500: '#64748b',
          600: '#475569',
          700: '#334155',
          800: '#1e293b',
          900: '#0f172a',
        },
        // Ethereal Futuristic Colors v2.5
        neon: {
          emerald: '#00ff9d',
          blue: '#00d4ff',
          pink: '#ff00ff',
          purple: '#b026ff',
          cyan: '#00ffff',
        },
        cyber: {
          50: '#e6f1ff',
          100: '#cce3ff',
          200: '#99c7ff',
          300: '#66abff',
          400: '#338fff',
          500: '#0073ff',
          600: '#005ccc',
          700: '#004599',
          800: '#002e66',
          900: '#001733',
        },
        midnight: {
          50: '#e8eaf6',
          100: '#c5cae9',
          200: '#9fa8da',
          300: '#7986cb',
          400: '#5c6bc0',
          500: '#3f51b5',
          600: '#3949ab',
          700: '#303f9f',
          800: '#283593',
          900: '#1a237e',
          950: '#0f172a',
        },
        indigo: {
          50: '#eef2ff',
          100: '#e0e7ff',
          200: '#c7d2fe',
          300: '#a5b4fc',
          400: '#818cf8',
          500: '#6366f1',
          600: '#4f46e5',
          700: '#4338ca',
          800: '#3730a3',
          900: '#312e81',
          950: '#1e1b4b',
        },
      },
      fontFamily: {
        sans: [
          'Inter var', 
          '-apple-system', 
          'BlinkMacSystemFont', 
          'Segoe UI', 
          'Roboto', 
          'Oxygen', 
          'Ubuntu', 
          'Cantarell', 
          'Fira Sans', 
          'Droid Sans', 
          'Helvetica Neue', 
          'sans-serif'
        ],
        mono: [
          'JetBrains Mono',
          'Fira Code',
          'ui-monospace', 
          'SFMono-Regular', 
          'Monaco', 
          'Consolas', 
          'Liberation Mono', 
          'Courier New', 
          'monospace'
        ],
      },
      fontSize: {
        '2xs': ['0.625rem', { lineHeight: '0.875rem' }],
      },
      boxShadow: {
        'xs': '0 1px 2px 0 rgba(0, 0, 0, 0.05)',
        'card': '0 1px 3px 0 rgba(0, 0, 0, 0.1), 0 1px 2px 0 rgba(0, 0, 0, 0.06)',
        'card-hover': '0 10px 15px -3px rgba(0, 0, 0, 0.1), 0 4px 6px -2px rgba(0, 0, 0, 0.05)',
        'premium': '0 20px 25px -5px rgba(0, 0, 0, 0.1), 0 10px 10px -5px rgba(0, 0, 0, 0.04)',
        'premium-lg': '0 25px 50px -12px rgba(0, 0, 0, 0.25)',
        'inner-premium': 'inset 0 2px 4px 0 rgba(0, 0, 0, 0.06)',
        'glow-primary': '0 0 20px rgba(102, 126, 234, 0.4)',
        'glow-success': '0 0 20px rgba(16, 185, 129, 0.4)',
        'glow-danger': '0 0 20px rgba(239, 68, 68, 0.4)',
      },
      backgroundImage: {
        'gradient-primary': 'linear-gradient(135deg, #667eea 0%, #764ba2 100%)',
        'gradient-primary-hover': 'linear-gradient(135deg, #5568d3 0%, #6a4391 100%)',
        'gradient-success': 'linear-gradient(135deg, #10b981 0%, #059669 100%)',
        'gradient-danger': 'linear-gradient(135deg, #ef4444 0%, #dc2626 100%)',
        'gradient-warning': 'linear-gradient(135deg, #f59e0b 0%, #d97706 100%)',
        'gradient-info': 'linear-gradient(135deg, #3b82f6 0%, #2563eb 100%)',
        'gradient-dark': 'linear-gradient(135deg, #1f2937 0%, #111827 100%)',
        'gradient-light': 'linear-gradient(135deg, #f9fafb 0%, #f3f4f6 100%)',
        'gradient-radial': 'radial-gradient(circle, var(--tw-gradient-stops))',
        'gradient-conic': 'conic-gradient(from 180deg at 50% 50%, var(--tw-gradient-stops))',
        'mesh-gradient': 'linear-gradient(135deg, #667eea 0%, #764ba2 50%, #f093fb 100%)',
        // New extreme gradients
        'gradient-aurora': 'linear-gradient(135deg, #667eea 0%, #764ba2 25%, #f093fb 50%, #667eea 75%, #764ba2 100%)',
        'gradient-neon': 'linear-gradient(135deg, #00f5ff 0%, #ff00f5 50%, #00f5ff 100%)',
        'gradient-metallic': 'linear-gradient(135deg, #b8c6db 0%, #f5f7fa 50%, #b8c6db 100%)',
        'gradient-fire': 'linear-gradient(135deg, #ff6b6b 0%, #ffd93d 50%, #ff6b6b 100%)',
        'gradient-ocean': 'linear-gradient(135deg, #667eea 0%, #2563eb 50%, #00d4ff 100%)',
        'gradient-sunset': 'linear-gradient(135deg, #ff6b6b 0%, #ff8787 25%, #ffa94d 50%, #ff6b6b 75%, #ff8787 100%)',
        'gradient-holographic': 'linear-gradient(45deg, #ff00ff 0%, #00ffff 25%, #ffff00 50%, #00ffff 75%, #ff00ff 100%)',
        'gradient-rainbow': 'linear-gradient(90deg, #ff0000 0%, #ff7f00 16.666%, #ffff00 33.333%, #00ff00 50%, #0000ff 66.666%, #4b0082 83.333%, #9400d3 100%)',
      },
      backdropBlur: {
        xs: '2px',
      },
      animation: {
        'fade-in': 'fadeIn 0.3s ease-in-out',
        'fade-in-slow': 'fadeIn 0.5s ease-in-out',
        'slide-in-up': 'slideInUp 0.3s ease-out',
        'slide-in-down': 'slideInDown 0.3s ease-out',
        'slide-in-right': 'slideInRight 0.3s ease-out',
        'slide-in-left': 'slideInLeft 0.3s ease-out',
        'scale-in': 'scaleIn 0.2s ease-out',
        'bounce-subtle': 'bounceSubtle 0.6s ease-in-out',
        'pulse-slow': 'pulse 3s cubic-bezier(0.4, 0, 0.6, 1) infinite',
        'spin-slow': 'spin 3s linear infinite',
        'shimmer': 'shimmer 2s linear infinite',
        // New extreme animations
        'float': 'float 3s ease-in-out infinite',
        'glow-pulse': 'glowPulse 2s ease-in-out infinite',
        'gradient-shift': 'gradientShift 3s ease-in-out infinite',
        'tilt': 'tilt 10s ease-in-out infinite',
        'morph': 'morph 8s ease-in-out infinite',
        'text-shimmer': 'textShimmer 2s linear infinite',
        'ripple': 'ripple 0.6s ease-out',
        'aurora': 'aurora 20s ease-in-out infinite',
        'blob': 'blob 7s ease-in-out infinite',
        'rotate-3d': 'rotate3d 20s linear infinite',
      },
      keyframes: {
        fadeIn: {
          '0%': { opacity: '0' },
          '100%': { opacity: '1' },
        },
        slideInUp: {
          '0%': { transform: 'translateY(20px)', opacity: '0' },
          '100%': { transform: 'translateY(0)', opacity: '1' },
        },
        slideInDown: {
          '0%': { transform: 'translateY(-20px)', opacity: '0' },
          '100%': { transform: 'translateY(0)', opacity: '1' },
        },
        slideInRight: {
          '0%': { transform: 'translateX(100%)', opacity: '0' },
          '100%': { transform: 'translateX(0)', opacity: '1' },
        },
        slideInLeft: {
          '0%': { transform: 'translateX(-100%)', opacity: '0' },
          '100%': { transform: 'translateX(0)', opacity: '1' },
        },
        scaleIn: {
          '0%': { transform: 'scale(0.9)', opacity: '0' },
          '100%': { transform: 'scale(1)', opacity: '1' },
        },
        bounceSubtle: {
          '0%, 100%': { transform: 'translateY(0)' },
          '50%': { transform: 'translateY(-5px)' },
        },
        shimmer: {
          '0%': { backgroundPosition: '-1000px 0' },
          '100%': { backgroundPosition: '1000px 0' },
        },
        // New extreme keyframes
        float: {
          '0%, 100%': { transform: 'translateY(0)' },
          '50%': { transform: 'translateY(-20px)' },
        },
        glowPulse: {
          '0%, 100%': { boxShadow: '0 0 20px rgba(102, 126, 234, 0.4)' },
          '50%': { boxShadow: '0 0 40px rgba(102, 126, 234, 0.8)' },
        },
        gradientShift: {
          '0%, 100%': { backgroundPosition: '0% 50%' },
          '50%': { backgroundPosition: '100% 50%' },
        },
        tilt: {
          '0%, 100%': { transform: 'rotateY(0deg)' },
          '25%': { transform: 'rotateY(2deg)' },
          '75%': { transform: 'rotateY(-2deg)' },
        },
        morph: {
          '0%, 100%': { borderRadius: '60% 40% 30% 70% / 60% 30% 70% 40%' },
          '50%': { borderRadius: '30% 60% 70% 40% / 50% 60% 30% 60%' },
        },
        textShimmer: {
          '0%': { backgroundPosition: '0% 50%' },
          '100%': { backgroundPosition: '200% 50%' },
        },
        ripple: {
          '0%': { transform: 'scale(0)', opacity: '1' },
          '100%': { transform: 'scale(4)', opacity: '0' },
        },
        aurora: {
          '0%, 100%': { 
            backgroundPosition: '0% 50%',
            filter: 'hue-rotate(0deg)'
          },
          '50%': { 
            backgroundPosition: '100% 50%',
            filter: 'hue-rotate(45deg)'
          },
        },
        blob: {
          '0%, 100%': { 
            transform: 'translate(0, 0) scale(1)',
            borderRadius: '60% 40% 30% 70% / 60% 30% 70% 40%'
          },
          '33%': { 
            transform: 'translate(30px, -50px) scale(1.1)',
            borderRadius: '30% 60% 70% 40% / 50% 60% 30% 60%'
          },
          '66%': { 
            transform: 'translate(-20px, 20px) scale(0.9)',
            borderRadius: '50% 50% 50% 50% / 50% 50% 50% 50%'
          },
        },
        rotate3d: {
          '0%': { transform: 'rotateY(0deg)' },
          '100%': { transform: 'rotateY(360deg)' },
        },
      },
      transitionDuration: {
        '400': '400ms',
      },
      transitionTimingFunction: {
        'bounce-in': 'cubic-bezier(0.68, -0.55, 0.265, 1.55)',
      },
    },
  },
  plugins: [],
}
