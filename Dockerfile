# syntax=docker/dockerfile:1.7
# Numanski — Static site image
# Zero-dependency: only nginx:alpine + onze HTML-bestanden.

FROM nginx:1.27-alpine

# Vervang de default nginx server-config door die van ons
RUN rm -f /etc/nginx/conf.d/default.conf
COPY nginx.conf /etc/nginx/conf.d/numanski.conf

# Statische bestanden
COPY index.html \
     compliance-scan-tool.html \
     /usr/share/nginx/html/

# Read-only filesystem-vriendelijk: zorg dat alle nginx-state buiten / kan
RUN chown -R nginx:nginx /usr/share/nginx/html \
 && chmod -R a+r       /usr/share/nginx/html

# Healthcheck via interne /healthz endpoint
HEALTHCHECK --interval=30s --timeout=3s --start-period=5s --retries=3 \
  CMD wget --quiet --tries=1 --spider http://127.0.0.1/healthz || exit 1

EXPOSE 80
