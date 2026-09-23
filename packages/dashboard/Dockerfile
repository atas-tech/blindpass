FROM node:26-alpine AS deps
WORKDIR /app

COPY package.json package-lock.json ./
COPY .npmrc ./
COPY packages/browser-ui/package.json packages/browser-ui/package.json
COPY packages/dashboard/package.json packages/dashboard/package.json
COPY packages/sps-server/package.json packages/sps-server/package.json
COPY packages/agent-skill/package.json packages/agent-skill/package.json
COPY packages/gateway/package.json packages/gateway/package.json
COPY packages/openclaw-plugin/package.json packages/openclaw-plugin/package.json
COPY packages/i18n/package.json packages/i18n/package.json

RUN npm ci

FROM deps AS build
WORKDIR /app

ARG VITE_SPS_API_URL
ENV VITE_SPS_API_URL=${VITE_SPS_API_URL}

ARG VITE_TURNSTILE_SITE_KEY
ENV VITE_TURNSTILE_SITE_KEY=${VITE_TURNSTILE_SITE_KEY}

COPY tsconfig.base.json ./
COPY packages/dashboard packages/dashboard
COPY packages/i18n packages/i18n

RUN npm run build --workspace=@blindpass/i18n && npm run build --workspace=@blindpass/dashboard

FROM nginx:1.29-alpine AS runtime

COPY packages/dashboard/nginx.conf /etc/nginx/conf.d/default.conf
COPY --from=build /app/packages/dashboard/dist /usr/share/nginx/html

EXPOSE 8080

CMD ["nginx", "-g", "daemon off;"]
