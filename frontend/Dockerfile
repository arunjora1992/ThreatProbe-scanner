FROM nginx:1.27-alpine

# Dependency-free static GUI (no npm build step) — ideal for air-gapped deployment.
COPY nginx.conf /etc/nginx/conf.d/default.conf
COPY html /usr/share/nginx/html

# Ensure the nginx worker (runs as user 'nginx') can read all assets. The source
# files may carry a restrictive umask from the build host, which causes 403s.
RUN chmod -R a+rX /usr/share/nginx/html

EXPOSE 80
