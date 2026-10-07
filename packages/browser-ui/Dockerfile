FROM node:26-alpine AS deps
WORKDIR /app

COPY package.json package-lock.json ./
COPY .npmrc ./
COPY packages/browser-ui/package.json packages/browser-ui/package.json
COPY packages/agent-skill/package.json packages/agent-skill/package.json
COPY packages/gateway/package.json packages/gateway/package.json
COPY packages/openclaw-plugin/package.json packages/openclaw-plugin/package.json
COPY packages/i18n/package.json packages/i18n/package.json

RUN npm ci

FROM deps AS build
WORKDIR /app

ARG VITE_SPS_API_URL
ENV VITE_SPS_API_URL=${VITE_SPS_API_URL}

COPY packages/browser-ui packages/browser-ui
COPY packages/i18n packages/i18n

RUN npm run build --workspace=@blindpass/i18n && npm run build --workspace=@blindpass/browser-ui

# The CSP names exactly the origin the bundle was built for. A loopback or
# non-https origin fails the build; set BLINDPASS_UI_DEV_IMAGE=1 for a local one.
ARG BLINDPASS_UI_DEV_IMAGE=0
RUN node packages/browser-ui/scripts/render-nginx-conf.mjs \
    packages/browser-ui/nginx.conf.template "${VITE_SPS_API_URL}" /tmp/default.conf \
    $([ "${BLINDPASS_UI_DEV_IMAGE}" = "1" ] && echo --allow-loopback)

FROM nginx:1.29-alpine AS runtime

COPY --from=build /tmp/default.conf /etc/nginx/conf.d/default.conf
COPY --from=build /app/packages/browser-ui/dist /usr/share/nginx/html

EXPOSE 8080

CMD ["nginx", "-g", "daemon off;"]
