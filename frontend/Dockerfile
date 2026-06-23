FROM nginx:1.27-alpine

# openssl is used by the entrypoint to mint a self-signed TLS cert at start.
# Installed at build time so the runtime stays fully offline / air-gapped.
RUN apk add --no-cache openssl

# nginx renders templates/*.template -> /etc/nginx/conf.d/ at start, substituting
# ${PUBLIC_HTTPS_PORT} so the HTTP->HTTPS redirect targets the published TLS port.
COPY templates/default.conf.template /etc/nginx/templates/default.conf.template

# Self-signed cert generator (runs before nginx; see script header).
COPY docker-entrypoint.d/10-generate-self-signed-cert.sh /docker-entrypoint.d/10-generate-self-signed-cert.sh
RUN chmod +x /docker-entrypoint.d/10-generate-self-signed-cert.sh

# Dependency-free static GUI (no npm build step) — ideal for air-gapped deployment.
COPY html /usr/share/nginx/html

# Ensure the nginx worker (runs as user 'nginx') can read all assets. The source
# files may carry a restrictive umask from the build host, which causes 403s.
RUN chmod -R a+rX /usr/share/nginx/html

EXPOSE 80 443
