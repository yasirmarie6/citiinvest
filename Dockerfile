FROM caddy:2-alpine

COPY . /srv
WORKDIR /srv

CMD ["sh", "-c, "caddy file-server --listen :$PORT"]
