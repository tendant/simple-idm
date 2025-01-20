/** @type {import('tailwindcss').Config} */
export default {
  content: [
    "./index.html",
    "./src/**/*.{js,ts,jsx,tsx}",
  ],
  theme: {
    extend: {
      colors: {
        primary: {
          7: '#1D4ED8',  // blue-700
          9: '#1E40AF',  // blue-900
          10: '#1E3A8A', // blue-950
        },
      },
    },
  },
  plugins: [],
}
