export default {
  "*.{ts,tsx,js,jsx,cjs,mjs}": [
    "pnpm exec eslint --fix --max-warnings 0 --no-warn-ignored"
  ]
}
