package main

import (
	"bufio"
	"flag"
	"fmt"
	"log"
	"net"
	"os"

	"github.com/yl2chen/cidranger"
)

func main() {
	ipListFileName := flag.String("ip_file", "", "List of ip addresses")
	networkListFileName := flag.String("network_file", "", "List of networks")

	flag.Parse()
	file, err := os.Open(*ipListFileName)

	if err != nil {
		log.Fatalf("failed opening file: %s", err)
	}

	scanner := bufio.NewScanner(file)
	scanner.Split(bufio.ScanLines)
	var ip_list []string

	for scanner.Scan() {
		ip_list = append(ip_list, scanner.Text())
	}

	file.Close()

	file, err = os.Open(*networkListFileName)

	if err != nil {
		log.Fatalf("failed opening file: %s", err)
	}

	scanner = bufio.NewScanner(file)
	scanner.Split(bufio.ScanLines)
	var networks []string

	for scanner.Scan() {
		networks = append(networks, scanner.Text())
	}

	file.Close()

	ranger := cidranger.NewPCTrieRanger()
	for _, cidr := range networks {
		_, network, _ := net.ParseCIDR(cidr)
		ranger.Insert(cidranger.NewBasicRangerEntry(*network))
	}

	for _, ip := range ip_list {
		contains, _ := ranger.Contains(net.ParseIP(ip))
		if contains {
			fmt.Println(ip)
		}

	}

}
