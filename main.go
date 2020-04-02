/*
MIT License

Copyright (c) 2020 Torstein

Permission is hereby granted, free of charge, to any person obtaining a copy
of this software and associated documentation files (the "Software"), to deal
in the Software without restriction, including without limitation the rights
to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
copies of the Software, and to permit persons to whom the Software is
furnished to do so, subject to the following conditions:

The above copyright notice and this permission notice shall be included in all
copies or substantial portions of the Software.

THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
SOFTWARE.
*/

package main

import (
	"log"
	"log/syslog"
	"net"
	"os"
	"fmt"

	"github.com/oschwald/maxminddb-golang"
	"github.com/spf13/viper"
)

func isInIPList(ipStr string, ipList []string) bool {
	for _, ip := range ipList {
		if ipStr == ip {
			return true
		}
	}
	return false
}

// Adapted code from from https://stackoverflow.com/a/41273687 
func isInPrivateNetwork(ip net.IP) bool {
	_, private24BitBlock, _ := net.ParseCIDR("10.0.0.0/8")
        _, private20BitBlock, _ := net.ParseCIDR("172.16.0.0/12")
        _, private16BitBlock, _ := net.ParseCIDR("192.168.0.0/16")
        return private24BitBlock.Contains(ip) || private20BitBlock.Contains(ip) || private16BitBlock.Contains(ip)
}

func main() {
	if len(os.Args) != 2 {
		log.Fatalln("Expected ip as argument.")
	}
	viper.AddConfigPath(".")
	viper.AddConfigPath("/srv/config")
	viper.SetConfigName("geoip-filter")
	err := viper.ReadInConfig()
	if err != nil {
		log.Fatalf("Failed reading config: %s", err)
	}

	ip := net.ParseIP(os.Args[1])
	if ip == nil {
		log.Fatalf("Failed parsing IP!")
	}
	ipStr := ip.String()
	
	// Establish syslog connection
	logger, err :=  syslog.New(syslog.LOG_NOTICE|syslog.LOG_AUTHPRIV, "geoip-filter")
	if err != nil {
		log.Fatalf("Error opening syslog: %s", err)
	}
	defer logger.Close()
	// Check if in whitelist
	isWhitelisted := isInIPList(ipStr, viper.GetStringSlice("WHITELISTED_IPS"))
	if isWhitelisted {
		fmt.Fprintf(logger,"Allow %s (WHITELIST)", ipStr)
		os.Exit(0)
	}
	// Check if in blacklist
	isBlacklisted := isInIPList(ipStr, viper.GetStringSlice("BLACKLISTED_IPS"))
	if isBlacklisted {
		fmt.Fprintf(logger, "Deny %s (BLACKLIST)", ipStr)
		os.Exit(1)
	}

	// Check if in private network
	isInPrivateNetwork := isInPrivateNetwork(ip)
	if isInPrivateNetwork {
		fmt.Fprintf(logger, "Allow %s (PRIVATE)", ipStr)
		os.Exit(0)
	}
	geoPath := viper.GetString("GEOIPDB_PATH")
	rdr, err := maxminddb.Open(geoPath)
	if err != nil {
		log.Fatalf("Failed opening GeoIP database: %s", err)
	}
	defer rdr.Close()

	var record struct {
		Country struct {
			ISOCode string `maxminddb:"iso_code"`
		} `maxminddb:"country"`
	}
	err = rdr.Lookup(ip, &record)
	if err != nil {
		log.Fatal(err)
	}

	allowedCountries := viper.GetStringSlice("ALLOWED_COUNTRIES")

	for _, c := range allowedCountries {
		if record.Country.ISOCode == c {
			fmt.Fprintf(logger, "Allow %s (%s)", ip.String(), c)
			os.Exit(0)
		}
	}
	fmt.Fprintf(logger, "Deny %s (%s)", ip.String(), record.Country.ISOCode)
	os.Exit(1)
}
