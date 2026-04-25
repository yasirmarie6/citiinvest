FROM caddy:2-alpine

COPY . /srv
WORKDIR /srv

EXPOSE 8080

CMD ["caddy", "file-server", "--listen", ":8080"]
