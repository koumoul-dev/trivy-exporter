##########################
FROM node:24.13.0-alpine3.23 AS base

WORKDIR /webapp
ENV NODE_ENV=production

##########################
FROM base AS trivy-installer

ARG TRIVY_VERSION=0.68.2

RUN apk update && apk add --no-cache ca-certificates git rpm && update-ca-certificates

RUN apk add --no-cache bash curl tar && \
    cd /root; \
    curl -sSL https://github.com/aquasecurity/trivy/releases/download/v${TRIVY_VERSION}/trivy_${TRIVY_VERSION}_Linux-64bit.tar.gz -o trivy.tar.gz; \
    tar -xvf trivy.tar.gz; \
    mv trivy /usr/local/bin/trivy; \
    rm -rf *;

##########################
FROM base AS package-strip

RUN apk add --no-cache jq moreutils
ADD package.json package-lock.json ./
# remove version from manifest for better caching when building a release
RUN jq '.version="build"' package.json | sponge package.json
RUN jq '.version="build"' package-lock.json | sponge package-lock.json

##########################
FROM base AS installer

RUN apk add --no-cache python3 make g++ git jq moreutils
RUN npm i -g clean-modules@3.0.4
COPY --from=package-strip /webapp/package.json package.json
COPY --from=package-strip /webapp/package-lock.json package-lock.json
RUN npm ci --omit=dev --omit=optional --no-audit --no-fund && npx clean-modules --yes

######################################
FROM base AS main

COPY --from=installer /webapp/node_modules node_modules
COPY --from=trivy-installer /usr/local/bin/trivy /usr/local/bin/trivy
ADD /src src
ADD /index.ts index.ts
ADD package.json README.md LICENSE BUILD.json* ./

VOLUME /var/run/docker.sock
VOLUME /webapp/data
VOLUME /webapp/rootfs
EXPOSE 9090

CMD ["node", "index.ts"]