package main

import (
	"fmt"
	"io/ioutil"
	"log"
	"net"
	"net/http"
	"os"
	"strings"
	"time"

	"github.com/cloudflare/cloudflare-go"
	"github.com/pkg/errors"
)

const version = "v2.0.0"

type config struct {
	authkey, authemail, hostname string
}

func getConfig() (*config, error) {
	c := config{
		authkey:   os.Getenv("CF_AUTH_KEY"),
		authemail: os.Getenv("CF_AUTH_EMAIL"),
		hostname:  os.Getenv("CF_HOSTNAME"),
	}
	if c.authkey == "" {
		return nil, errors.New("missing CF_AUTH_KEY")
	}
	if c.authemail == "" {
		return nil, errors.New("missing CF_AUTH_EMAIL")
	}
	if c.hostname == "" {
		return nil, errors.New("missing CF_HOSTNAME")
	}
	return &c, nil
}

func main() {
	log.Printf("info: cfupdate (%s)\n", version)
	var (
		c   *config
		cf  *cloudflare.API
		err error
		ok  bool = true
	)

	c, err = getConfig()
	if err != nil {
		log.Printf("error: %s\n", err)
		os.Exit(1)
		return
	}

	cf, err = cloudflare.New(c.authkey, c.authemail)
	if err != nil {
		log.Printf("error: %s\n", err)
		os.Exit(1)
		return
	}

	err = doUpdate(cf, c, "ipv4")
	if err != nil {
		ok = false
		log.Printf("error: %s\n", err)
	}

	err = doUpdate(cf, c, "ipv6")
	if err != nil {
		ok = false
		log.Printf("error: %s\n", err)
	}

	if ok {
		log.Println("info: finished with no errors")
	} else {
		log.Println("info: finished with some errors")
	}
}

func doUpdate(cf *cloudflare.API, c *config, ipfam string) error {
	var (
		ip   net.IP
		err  error
		zone *cloudflare.Zone
		rec  *cloudflare.DNSRecord
	)
	ip, err = icanhazip(ipfam)
	if err != nil {
		return err
	}

	log.Printf("info: machine's %s address is %s", ipfam, ip)

	zone, err = findZoneFromHostname(cf, c.hostname)
	if err != nil {
		return err
	}

	rec, err = findRecord(cf, zone.ID, ip, c.hostname)
	if err != nil {
		return err
	}

	if rec.Content != ip.String() {
		err = cf.UpdateDNSRecord(zone.ID, rec.ID, cloudflare.DNSRecord{Content: ip.String()})
		if err != nil {
			return err
		}
		log.Printf("info: successfully updated %s!\n", c.hostname)
	} else {
		log.Printf("info: %s content matches this machines ip address", c.hostname)
	}

	return nil
}

func findZoneFromHostname(cf *cloudflare.API, hn string) (*cloudflare.Zone, error) {
	allzones, err := cf.ListZones()
	if err != nil {
		return nil, errors.Wrap(err, "failed to list zones from cloudflare")
	}
	for _, z := range allzones {
		if strings.HasSuffix(hn, z.Name) {
			return &z, nil
		}
	}
	return nil, errors.Errorf("did not find matching zone for '%s'", hn)
}

func findRecord(cf *cloudflare.API, zoneid string, ip net.IP, hn string) (*cloudflare.DNSRecord, error) {
	var rrtype string = "A"
	if ip.To4() == nil {
		rrtype = "AAAA"
	}
	rrs, err := cf.DNSRecords(zoneid, cloudflare.DNSRecord{Name: hn, Type: rrtype})
	if err != nil {
		return nil, errors.Wrap(err, "failed to find dns records")
	}
	if len(rrs) == 0 {
		log.Printf("info: no record found for '%s', creating a new one", hn)
		resp, err := cf.CreateDNSRecord(zoneid, cloudflare.DNSRecord{
			Name:    hn,
			Type:    rrtype,
			Content: ip.String(),
			Proxied: true,
		})
		if err != nil {
			return nil, errors.Wrap(err, "failed to create new dns record")
		}
		if !resp.Success {
			return nil, errors.New("cloudflare reported an unsuccessful response")
		}
		return &resp.Result, nil
	}
	if len(rrs) > 1 {
		log.Printf("warn: more than 1 record found for '%s' with RR type %s", hn, rrtype)
	}
	return &rrs[0], nil
}

func icanhazip(mode string) (net.IP, error) {
	response := make(chan *http.Response)
	errc := make(chan error)
	go func() {
		res, err := http.Get(fmt.Sprintf("https://%s.icanhazip.com", mode))
		if err != nil {
			errc <- err
			return
		}
		response <- res
	}()
	select {
	case <-time.After(time.Duration(5) * time.Second):
		return nil, errors.Errorf("%s address request timed out", mode)
	case err := <-errc:
		return nil, errors.Wrapf(err, "%s address request encountered an error", mode)
	case res := <-response:
		if res.StatusCode != http.StatusOK {
			return nil, errors.Errorf("%s address request returned non-ok status code", mode)
		}
		defer res.Body.Close()
		bytes, err := ioutil.ReadAll(res.Body)
		if err != nil {
			return nil, errors.Wrapf(err, "%s address request failed to read response body", mode)
		}
		ipstring := strings.TrimSpace(string(bytes))
		ip := net.ParseIP(ipstring)
		if ip == nil {
			return nil, errors.New("response from icanhazip was not a valid ip address")
		}
		return ip, nil
	}
}
