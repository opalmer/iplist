package main

import (
	"encoding/binary"
	"flag"
	"fmt"
	"net"
	"net/http"
	"regexp"

	log "github.com/Sirupsen/logrus"
	"github.com/opalmer/awsips"
	"github.com/domainr/whois"
)

func handleerror(err error, writer http.ResponseWriter) {
	log.Error(err)
	writer.WriteHeader(http.StatusInternalServerError)
}


func handleaws(writer http.ResponseWriter, request *http.Request) {
	ranges, err := awsips.Get()
	if err != nil {
		handleerror(err, writer)
		return
	}

	for _, prefix := range ranges.Prefixes {
		if (prefix.Region == "us-east-1" ||
			prefix.Region == "GLOBAL" &&
			prefix.Service == "AMAZON") {
			continue
		}
		writer.Write([]byte(prefix.Prefix + "\n"))
	}
}


var RegexInetNum = regexp.MustCompile(`inetnum.*`)
var RegexIPs = regexp.MustCompile(`(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})`)


// RangeToCIDR converts a start and end
func IPRangeToCIDR(start net.IP, end net.IP) string {
	difference := (
		int32(binary.BigEndian.Uint32(start.To4())) ^
		int32(binary.BigEndian.Uint32(end.To4())))
	bits := 32
	mask := 0
	for {
		if difference == 0 {
			break
		}
		difference >>= 1
		bits -= 1
		mask = (mask << 1) | 1
	}

	return fmt.Sprintf("%s/%d", start, bits)
}


func handlehinet(writer http.ResponseWriter, request *http.Request) {
	whoisRequest := &whois.Request{
		Query: "HINET-NET",
		Host: "whois.apnic.net",
	}
	if err := whoisRequest.Prepare(); err != nil {
		handleerror(err, writer)
		return
	}

	response, err := whois.DefaultClient.Fetch(whoisRequest)
	if err != nil {
		handleerror(err, writer)
		return
	}

	for _, match := range RegexInetNum.FindAllString(response.String(), -1) {
		addresses := RegexIPs.FindAllString(match, -1)
		if len(addresses) != 2 {
			log.Errorf(
				"Expected exactly two results: %s", addresses)
			continue
		}
		startIP := net.ParseIP(addresses[0])
		if startIP == nil {
			log.Errorf(
				"%s does not appear to be an ip.", addresses[0])
			continue
		}

		endIP := net.ParseIP(addresses[1])
		if endIP == nil {
			log.Errorf(
				"%s does not appear to be an ip.", addresses[1])
		}

		writer.Write([]byte(IPRangeToCIDR(startIP, endIP) + "\n"))
	}

}


func main() {
	port := flag.Int("port", 5000, "The port to listen on.")
	bind := flag.String("bind", "127.0.0.1", "The address to listen on")
	flag.Parse()
	mux := http.NewServeMux()
	mux.HandleFunc("/aws", handleaws)
	mux.HandleFunc("/hinet", handlehinet)
	log.Fatal(http.ListenAndServe(fmt.Sprintf("%s:%d", *bind, *port), mux))
}
