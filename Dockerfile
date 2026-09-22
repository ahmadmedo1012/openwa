# syntax=docker/dockerfile:1.7
# R104 (AG12-2/AG12-3): lockfile-faithful builds (npm ci, not npm install)
# and a production-only runtime image (devDeps no longer ship — was
# ~60-90 MB of typescript/tsx/@types dead weight in every pull).
FROM node:22-alpine AS build
WORKDIR /app
# No git needed in this deps stage (110-K, corrects the stale R104 note):
# npm >= 9.6 resolves full-SHA GitHub git deps (libsignal-node) as TARBALLS
# — no git binary, no ssh. Proven empirically in R109 (a cold-cache npm ci
# with a broken git stub exits 0), and the deps-prod stage below has never
# had git yet installs the same dependency.
# Lockfile copied → reproducible resolution + faster installs.
COPY package.json package-lock.json ./
RUN npm ci --no-audit --no-fund
COPY tsconfig.json ./
COPY src ./src
RUN npm run build

FROM node:22-alpine AS deps-prod
WORKDIR /app
COPY package.json package-lock.json ./
RUN npm ci --omit=dev --no-audit --no-fund

FROM node:22-alpine
ENV NODE_ENV=production DATA_DIR=/data PORT=2785
WORKDIR /app
COPY --from=deps-prod /app/node_modules ./node_modules
COPY --from=build /app/dist ./dist
COPY package.json ./
RUN mkdir -p /data && chown -R node:node /app /data
USER node
EXPOSE 2785
HEALTHCHECK --interval=30s --timeout=5s --start-period=10s \
  CMD wget -qO- http://127.0.0.1:${PORT}/healthz >/dev/null 2>&1 || exit 1
CMD ["node", "dist/index.js"]
