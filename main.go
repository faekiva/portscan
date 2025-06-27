/*
portscan is a simple port scanner that tries to open a range of TCP connections to the given host.
*/
package main

import (
	"context"
	"fmt"
	"log"
	"net"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/alexflint/go-arg"
)

type program struct {
	Host    string        `arg:"positional" help:"Host or IP to scan" default:"localhost"`
	Ports   []string      `arg:"positional" help:"Port ranges to scan, eg 80 443 200-1000. Defaults to 22-9999 if not specified"`
	Timeout time.Duration `arg:"--timeout" help:"Timeout per port" default:"1s"`
	Threads int           `arg:"--threads" help:"Threads to use" default:"100"`
	Verbose bool          `arg:"-v,--verbose" help:"Show errors for failed ports" default:"false"`
}

func processRange(ctx context.Context, ports []string) chan int {
	c := make(chan int)
	done := ctx.Done()
	go func() {
		defer close(c)
		for _, block := range ports {
			rg := strings.Split(block, "-")
			if len(rg) != 1 && len(rg) != 2 {
				log.Print("Cannot interpret range: ", block)
				continue
			}
			var r1, r2 int
			var err error
			r1, err = strconv.Atoi(rg[0])
			if err != nil {
				log.Print("Cannot interpret range: ", block)
				continue
			}
			if len(rg) == 1 {
				r2 = r1
			} else {
				r2, err = strconv.Atoi(rg[1])
				if err != nil {
					log.Print("Cannot interpret range: ", block)
					continue
				}
			}
			for j := r1; j <= r2; j++ {
				select {
				case c <- j:
				case <-done:
					return
				}
			}
		}
	}()
	return c
}

func (p program) scanPorts(ctx context.Context, in <-chan int) chan string {
	out := make(chan string)
	done := ctx.Done()
	var wg sync.WaitGroup
	wg.Add(p.Threads)
	for i := 0; i < p.Threads; i++ {
		go func() {
			defer wg.Done()
			for {
				select {
				case port, ok := <-in:
					if !ok {
						return
					}
					s := p.scanPort(port)
					select {
					case out <- s:
					case <-done:
						return
					}
				case <-done:
					return
				}
			}
		}()
	}
	go func() {
		wg.Wait()
		close(out)
	}()
	return out
}

func (p program) scanPort(port int) string {
	addr := net.JoinHostPort(p.Host, fmt.Sprintf("%d", port))
	conn, err := net.DialTimeout("tcp", addr, p.Timeout)
	if err != nil {
		return fmt.Sprintf("%d: %s", port, err.Error())
	}
	conn.Close()
	return fmt.Sprintf("%d: OK", port)
}

func main() {
	var args program
	arg.MustParse(&args)
	if len(args.Ports) == 0 {
		args.Ports = []string{"22-9999"} // Default range if none specified
	}

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	fmt.Printf("Scanning %s ports %s timeout %s threads %d\n", args.Host, args.Ports, args.Timeout, args.Threads)

	c := processRange(ctx, args.Ports)
	s := args.scanPorts(ctx, c)
	for x := range s {
		if args.Verbose || strings.HasSuffix(x, ": OK") {
			fmt.Println(x)
		}
	}
}
