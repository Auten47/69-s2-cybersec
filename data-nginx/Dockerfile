FROM nginx:1.27-alpine

RUN apk add --no-cache openssl \
  && mkdir -p /etc/nginx/certs \
  && openssl req -x509 -newkey rsa:2048 -nodes -days 825 \
    -keyout /etc/nginx/certs/tls.key \
    -out /etc/nginx/certs/tls.crt \
    -subj "/C=TH/ST=Bangkok/L=Bangkok/O=RMUTP-CyberSec/OU=Lab/CN=localhost" \
    -addext "subjectAltName=DNS:localhost,IP:127.0.0.1" \
  && chmod 644 /etc/nginx/certs/tls.crt && chmod 600 /etc/nginx/certs/tls.key

COPY default.conf /etc/nginx/conf.d/default.conf