FROM scratch
COPY portscan /app/portscan
ENTRYPOINT ["/app/portscan"]