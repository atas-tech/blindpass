FROM node:26-alpine AS deps
WORKDIR /app

COPY package.json package-lock.json ./
COPY .npmrc ./
COPY packages/sps-server/package.json packages/sps-server/package.json
COPY packages/browser-ui/package.json packages/browser-ui/package.json
COPY packages/dashboard/package.json packages/dashboard/package.json
COPY packages/agent-skill/package.json packages/agent-skill/package.json
COPY packages/gateway/package.json packages/gateway/package.json
COPY packages/openclaw-plugin/package.json packages/openclaw-plugin/package.json
COPY packages/i18n/package.json packages/i18n/package.json

RUN npm ci

FROM deps AS build
WORKDIR /app

COPY tsconfig.base.json ./
COPY packages/sps-server/tsconfig.json packages/sps-server/tsconfig.json
COPY packages/sps-server/src packages/sps-server/src
COPY packages/i18n packages/i18n

RUN npm run build --workspace=@blindpass/i18n && npm run build --workspace=@blindpass/sps-server

FROM node:26-alpine AS runtime
WORKDIR /app

ENV NODE_ENV=production
ENV PORT=3100
ENV SPS_HOST=0.0.0.0

COPY package.json package-lock.json ./
COPY .npmrc ./
COPY packages/sps-server/package.json packages/sps-server/package.json
COPY packages/browser-ui/package.json packages/browser-ui/package.json
COPY packages/dashboard/package.json packages/dashboard/package.json
COPY packages/agent-skill/package.json packages/agent-skill/package.json
COPY packages/gateway/package.json packages/gateway/package.json
COPY packages/openclaw-plugin/package.json packages/openclaw-plugin/package.json
COPY packages/i18n/package.json packages/i18n/package.json
COPY --from=build /app/packages/i18n/dist packages/i18n/dist
COPY packages/i18n/locales packages/i18n/locales

RUN npm ci --omit=dev

COPY --from=build /app/packages/sps-server/dist packages/sps-server/dist

EXPOSE 3100

CMD ["node", "packages/sps-server/dist/index.js"]
