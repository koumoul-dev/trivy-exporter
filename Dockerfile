############################################################################################################
# Stage: prepare a base image with all native utils pre-installed, used both by builder and definitive image

FROM node:20.11.0-alpine3.18 AS trivy

ARG TRIVY_VERSION=0.48.3

RUN apk update && apk add --no-cache ca-certificates git rpm && update-ca-certificates

# Installation de Trivy
RUN apk add --no-cache bash curl tar && \
    cd /root; \
    curl -sSL https://github.com/aquasecurity/trivy/releases/download/v${TRIVY_VERSION}/trivy_${TRIVY_VERSION}_Linux-64bit.tar.gz -o trivy.tar.gz; \
    tar -xvf trivy.tar.gz; \
    mv trivy /usr/local/bin/trivy; \
    rm -rf *;

######################################
# Stage: nodejs dependencies and build
FROM trivy AS builder

# RUN apk add --no-cache python3 make g++ curl
# RUN ln -s /usr/bin/python3 /usr/bin/python
# RUN apk add --no-cache sqlite-dev

WORKDIR /webapp
ADD package.json .
ADD package-lock.json .

# use clean-modules on the same line as npm ci to be lighter in the cache
RUN npm ci && \
     ./node_modules/.bin/clean-modules --yes --exclude mocha/lib/test.js --exclude "**/*.eslintrc.*"

# Adding server files
ADD utils utils

# Check quality
ADD .gitignore .gitignore
ADD test test
ADD .eslintrc.js .eslintrc.js
RUN npm run lint

# Cleanup /webapp/node_modules so it can be copied by next stage
RUN npm prune --production && \
    rm -rf node_modules/.cache

######################################
# Stage: final image
FROM node:20.11.0-alpine3.18

WORKDIR /webapp
RUN apk add --no-cache dumb-init

# We could copy /webapp whole, but this is better for layering / efficient cache use
COPY --from=builder /webapp/node_modules /webapp/node_modules
ADD utils utils
ADD index.js index.js
ADD app.js app.js


# Adding licence, manifests, etc.
ADD package.json .
ADD README.md BUILD.json* ./
ADD LICENSE .
ADD nodemon.json .

# Copy Trivy binary from the trivy stage to the final image
COPY --from=trivy /usr/local/bin/trivy /usr/local/bin/trivy

# configure node webapp environment
ENV NODE_ENV production
# USER node
VOLUME /var/run/docker.sock
VOLUME /webapp/data
VOLUME /webapp/rootfs
EXPOSE 9000

# --single-child is necessary to wait for running scanners to finish
CMD ["dumb-init", "--single-child", "node", "index.js"]
