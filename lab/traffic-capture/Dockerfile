FROM alpine:3.20
RUN apk add --no-cache tcpdump
ENTRYPOINT ["sh", "-c", "tcpdump -i eth0 -w /pcap/capture-$(date +%Y%m%d-%H%M%S).pcap"]
