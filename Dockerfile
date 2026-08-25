# syntax=docker/dockerfile:1.7
FROM node:22-alpine AS build
WORKDIR /app
# git is required by npm when a dependency resolves from a git URL.
RUN apk add --no-cache git
COPY package.json ./
RUN npm install --no-audit --no-fund
COPY tsconfig.json ./
COPY src ./src
RUN npm run build

FROM node:22-alpine
ENV NODE_ENV=production DATA_DIR=/data PORT=2785
WORKDIR /app
COPY --from=build /app/node_modules ./node_modules
COPY --from=build /app/dist ./dist
COPY package.json ./
RUN mkdir -p /data && chown -R node:node /app /data
USER node
EXPOSE 2785
HEALTHCHECK --interval=30s --timeout=5s --start-period=10s \
  CMD wget -qO- http://127.0.0.1:${PORT}/healthz >/dev/null 2>&1 || exit 1
CMD ["node", "dist/index.js"]
