FROM alpine:3.20
RUN apk add --no-cache openssl
WORKDIR /certs
COPY generate.sh .
RUN chmod +x generate.sh
ENTRYPOINT ["./generate.sh"]
