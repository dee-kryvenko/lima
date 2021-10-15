package main

import (
	"bufio"
	"flag"
	"fmt"
	"log"
	"os"
	"strconv"

	"github.com/lima-vm/lima/pkg/hostagent"
)

func main() {
	flag.Parse()
	udp, err := strconv.Atoi(flag.Arg(0))
	if err != nil {
		panic(err)
	}
	tcp, err := strconv.Atoi(flag.Arg(1))
	if err != nil {
		panic(err)
	}

	log.Printf("udp:%v tcp:%v", udp, tcp)

	dnsServer, err := hostagent.FakeDNSServer(udp, tcp)
	if err != nil {
		panic(err)
	}

	defer dnsServer.Shutdown()
	fmt.Println("Ctrl+C to exit...")
	for {
		_, _ = bufio.NewReader(os.Stdin).ReadBytes('\n')
	}
}
