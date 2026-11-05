# syntax=docker/dockerfile:1
FROM node:22.11-alpine AS build
WORKDIR /app
COPY package.json package-lock.json ./
RUN npm ci
COPY tsconfig.json tsconfig.build.json ./
COPY src ./src
RUN npm run build && npm prune --omit=dev

FROM node:22.11-alpine
# git: webhook reviews fetch the pull request head commit
RUN apk add --no-cache git
WORKDIR /app
ENV NODE_ENV=production \
    PORT=3000 \
    SENTINELOPS_DATA_DIR=/data
COPY --from=build /app/node_modules ./node_modules
COPY --from=build /app/dist ./dist
COPY package.json ./
COPY assets ./assets
COPY demo ./demo
RUN mkdir -p /data && chown node:node /data
USER node
EXPOSE 3000
VOLUME ["/data"]
HEALTHCHECK --interval=30s --timeout=5s CMD wget -qO- http://127.0.0.1:3000/api/health > /dev/null || exit 1
ENTRYPOINT ["node", "dist/cli.js"]
CMD ["serve"]
