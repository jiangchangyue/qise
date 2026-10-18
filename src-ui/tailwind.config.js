/** @type {import('tailwindcss').Config} */
export default {
  content: ["./index.html", "./src/**/*.{js,ts,jsx,tsx}"],
  theme: {
    extend: {
      colors: {
        "qise-deep": "#ffffff",
        "qise-surface": "#ffffff",
        "qise-card": "#f4f4f4",
        "qise-red": "#b74134",
        "qise-blue": "#3e6ae1",
        "qise-green": "#2f7d62",
        "qise-yellow": "#8a6a24",
      },
      fontFamily: {
        sans: ["var(--font-sans)"],
        mono: ["var(--font-mono)"],
      },
    },
  },
  plugins: [],
};
