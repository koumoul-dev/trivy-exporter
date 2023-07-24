FROM node:alpine

ARG TRIVY_VERSION=0.43.0

RUN apk update && apk add --no-cache ca-certificates git rpm && update-ca-certificates

# Installation de Trivy
RUN apk add --no-cache bash curl tar && \
    cd /root; \
    curl -sSL https://github.com/aquasecurity/trivy/releases/download/v${TRIVY_VERSION}/trivy_${TRIVY_VERSION}_Linux-64bit.tar.gz -o trivy.tar.gz; \
    tar -xvf trivy.tar.gz; \
    mv trivy /usr/local/bin/trivy; \
    rm -rf *;

# Exécution de la commande Trivy avec un argument de ligne de commande personnalisé
CMD ["sh", "-c", "trivy image --scanners vuln node:alpine"]