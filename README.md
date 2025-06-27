# portscan

`portscan` is a simple TCP port scanner written in Go.

```
Usage: portscan [--timeout TIMEOUT] [--threads THREADS] [--verbose] [HOST [PORTS [PORTS ...]]]

Positional arguments:
  HOST                   Host or IP to scan
  PORTS                  Port ranges to scan, eg 80 443 200-1000. Defaults to 22-9999 if not specified

Options:
  --timeout TIMEOUT      Timout per port [default: 1s]
  --threads THREADS      Threads to use [default: 100]
  --verbose, -v          Show errors for failed ports [default: false]
  --help, -h             display this help and exit
```