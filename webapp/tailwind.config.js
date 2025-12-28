
export default {
    content: [
        "./index.html",
        "./src*.{js,ts,jsx,tsx}",
    ],
    theme: {
        extend: {
            colors: {
                'ops': {
                    'black': '#0a0c10',
                    'navy': '#0d1117',
                    'panel': '#161b22',
                    'border': '#21262d',
                    'hover': '#1c2128',
                    'cyan': '#58a6ff',
                    'purple': '#a371f7',
                },
                'threat': {
                    DEFAULT: '#f85149',
                    'dark': '#da3633',
                },
                'secure': {
                    DEFAULT: '#3fb950',
                    'dark': '#238636',
                },
                'intel': {
                    DEFAULT: '#d29922',
                    'dark': '#bb8009',
                },
                'classified': {
                    DEFAULT: '#e3b341',
                    'dark': '#9e6a03',
                },
                'forensic-dark': '#0a0c10',
                'forensic-panel': '#161b22',
                'forensic-border': '#21262d',
                'forensic-accent': '#58a6ff',
                'forensic-success': '#3fb950',
            },
            fontFamily: {
                'inter': ['Inter', 'system-ui', 'sans-serif'],
                'mono': ['JetBrains Mono', 'Fira Code', 'Consolas', 'monospace'],
                'display': ['Inter', 'system-ui', 'sans-serif'],
            },
            boxShadow: {
                'glow-cyan': '0 0 20px rgba(88, 166, 255, 0.3)',
                'glow-green': '0 0 20px rgba(63, 185, 80, 0.3)',
                'glow-red': '0 0 20px rgba(248, 81, 73, 0.3)',
                'glow-amber': '0 0 20px rgba(210, 153, 34, 0.3)',
                'tactical': '0 20px 50px -20px rgba(0, 0, 0, 0.5)',
            },
            backdropBlur: {
                'xs': '2px',
            },
            animation: {
                'pulse-slow': 'pulse 3s cubic-bezier(0.4, 0, 0.6, 1) infinite',
                'spin-slow': 'spin 4s linear infinite',
            },
            borderRadius: {
                '4xl': '2rem',
                '5xl': '2.5rem',
            },
        },
    },
    plugins: [],
}
