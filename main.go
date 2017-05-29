package main

import (
	"fmt"
	"io"
	"io/ioutil"
	"log"
	"net/http"
	"os"
	"os/signal"
	"regexp"
	"strings"
	"sync"
	"syscall"
	"time"

	"github.com/cloudflare/cloudflare-go"
	"github.com/comail/colog"
	"github.com/patrickmn/go-cache"
	"github.com/pkg/errors"
	"github.com/spf13/viper"
)

const (
	version = "v1.0.1"

	defaultConfig = `{
	"cf_auth_key": "[put your api key here]",
	"cf_auth_email": "[put your cf email here]",
	"zone_name": "[put the name of the zone you want to update here]",
	"orange_cloud": false,
	"update_interval": "1m",
	"log_level": "warn",
	"ipv6": false
}
`

	banner = `
     __               _      _       
 __ / _|_  _ _ __  __| |__ _| |_ ___ 
/ _|  _| || | '_ \/ _` + "` / _`" + ` |  _/ -_)
\__|_|  \_,_| .__/\__,_\__,_|\__\___|
            |_|                      
`

	updateModeV6 = "ipv6"
	updateModeV4 = "ipv4"
)

var (
	// there are some concurrent map read and map write issues somewhere in go's HTTP2 code
	cfReqLock = sync.Mutex{}
	cf        *cloudflare.API
	state     *cache.Cache
	config    *viper.Viper
)

type updateResult struct {
	err       error
	cfUpdated bool
}

func configFile() string {
	ps := string(os.PathSeparator)
	return strings.TrimRight(os.Getenv("HOME"), ps) + ps + ".cfupdate.json"
}

func readConfig(cfg io.Reader) (*viper.Viper, error) {
	v := viper.New()
	v.SetConfigType("json")

	v.SetDefault("ipv6", false)
	v.SetDefault("update_interval", "5s")
	v.SetDefault("orange_cloud", false)

	return v, v.ReadConfig(cfg)
}

func updateInterval(v *viper.Viper) time.Duration {
	defDur := time.Duration(5) * time.Second
	if !v.IsSet("update_interval") {
		log.Println("warn: update_interval not specified in configuration. defaulting to 5s.")
		return defDur
	}
	d, err := time.ParseDuration(v.GetString("update_interval"))
	if err != nil {
		log.Println("error: could not parse update_interval: %s", err.Error())
		return defDur
	}
	return d
}

func init() {
	colog.Register()
	colog.ParseFields(true)
	colog.SetMinLevel(colog.LWarning)
	state = cache.New(time.Duration(30)*time.Minute, time.Duration(5)*time.Second)
}

func getHostname(v *viper.Viper) string {
	if v.IsSet("hostname") {
		return v.GetString("hostname")
	}
	var (
		err error
		hn  string
	)
	hn, err = os.Hostname()
	if err != nil {
		log.Fatalf("alert: %s", err.Error())
	}
	return regexp.MustCompile(`(-[0-9]+)?(\.local)$`).ReplaceAllString(hn, "")
}

func setAddress(fam, addr string) {
	state.Set(fmt.Sprintf("%s.addr", fam), addr, cache.NoExpiration)
}

func getAddress(fam string) string {
	v, ok := state.Get(fmt.Sprintf("%s.addr", fam))
	if !ok || v == nil {
		return "<nil>"
	}
	return v.(string)
}

func main() {
	os.Stdout.Write([]byte(banner))
	os.Stdout.Write([]byte(fmt.Sprintf("\n(version: %s)\n\n", version)))
	{
		var err error
		f, err := os.Open(configFile())
		if err != nil {
			if os.IsNotExist(err) {
				log.Printf("looks like you don't have a config file setup. let me create one for you at: %s", configFile())
				f, err = os.Create(configFile())
				f.Write([]byte(defaultConfig))
				f.Close()
				os.Exit(1)
			} else {
				log.Fatalf("alert: %s", err.Error())
			}
		}
		config, err = readConfig(f)
		f.Close()
		if err != nil {
			log.Fatalf("alert: %s", err.Error())
		}
	}

	if !config.IsSet("zone_name") {
		log.Fatal("alert: zone_name is not defined in configuration")
	}
	if !config.IsSet("cf_auth_key") {
		log.Fatal("alert: cf_auth_key is not defined in configuration")
	}
	if !config.IsSet("cf_auth_email") {
		log.Fatal("alert: cf_auth_email is not defined in configuration")
	}

	{
		var err error
		cf, err = cloudflare.New(config.GetString("cf_auth_key"), config.GetString("cf_auth_email"))
		if err != nil {
			log.Fatalf("alert: %s", err.Error())
		}
	}

	if config.IsSet("log_level") {
		l, err := colog.ParseLevel(config.GetString("log_level"))
		if err == nil {
			colog.SetMinLevel(l)
		}
	}

	var setResultChan func(string, chan updateResult)
	var rmResultsChan func(string)
	var getResultsChan func(string) chan updateResult
	{
		lock := sync.RWMutex{}
		results := map[string]chan updateResult{}
		setResultChan = func(fam string, c chan updateResult) {
			lock.Lock()
			defer lock.Unlock()
			results[fam] = c
		}
		rmResultsChan = func(fam string) {
			lock.Lock()
			defer lock.Unlock()
			delete(results, fam)
		}
		getResultsChan = func(fam string) chan updateResult {
			lock.RLock()
			defer lock.RUnlock()
			return results[fam]
		}
	}

	sigchan := make(chan os.Signal, 1)
	signal.Notify(sigchan, syscall.SIGINT, syscall.SIGTERM)

coreLoop:
	for {
		select {
		case v4result := <-getResultsChan(updateModeV4):
			close(getResultsChan(updateModeV4))
			rmResultsChan(updateModeV4)
			if v4result.err != nil {
				log.Printf("error: v4 update error: %s", v4result.err.Error())
			}
			if v4result.cfUpdated {
				log.Printf("info: cf updated with new ip address: %s", getAddress(updateModeV4))
			}
		case v6result := <-getResultsChan(updateModeV6):
			close(getResultsChan(updateModeV6))
			rmResultsChan(updateModeV6)
			if v6result.err != nil {
				log.Printf("error: v6 update error: %s", v6result.err.Error())
			}
			if v6result.cfUpdated {
				log.Printf("info: cf updated with new ip address: %s", getAddress(updateModeV6))
			}
		case <-time.After(updateInterval(config)):
			setResultChan(updateModeV4, make(chan updateResult, 1))
			go update(updateModeV4, getResultsChan(updateModeV4))
			if config.GetBool("ipv6") {
				setResultChan(updateModeV6, make(chan updateResult, 1))
				go update(updateModeV6, getResultsChan(updateModeV6))
			}
		case sig := <-sigchan:
			log.Printf("received %s signal. exiting...", sig.String())
			cleanup()
			break coreLoop
		}
	}
}

func cleanup() {
	state.Flush()
}

func update(mode string, result chan updateResult) {
	log.Printf("debug: updating %s address", mode)
	ur := updateResult{
		err:       nil,
		cfUpdated: false,
	}
	defer func() { result <- ur }()

	// get current ip address
	ip, err := icanhazip(mode)
	if err != nil {
		ur.err = errors.Wrap(err, "failed to retrieve ip address")
		return
	}

	if ip == getAddress(mode) {
		log.Printf("debug: no change in %s address", mode)
		return
	}
	log.Printf("info: ip address has changed from %s to %s", getAddress(mode), ip)

	zid, err := getZoneID(config.GetString("zone_name"))
	if err != nil {
		ur.err = errors.Wrap(err, "failed to retrieve zone id")
		return
	}

	rid, rc, err := getRecord(zid, getHostname(config), mode)
	if err != nil {
		ur.err = errors.Wrap(err, "failed to retrieve record id")
		return
	}
	if rc == ip {
		setAddress(mode, ip)
		log.Printf("cloudflare has up-to-date %s address", mode)
		return
	}

	cfReqLock.Lock()
	defer cfReqLock.Unlock()
	err = cf.UpdateDNSRecord(zid, rid, cloudflare.DNSRecord{
		Content: ip,
		Proxied: config.GetBool("orange_cloud"),
	})
	if err != nil {
		ur.err = errors.Wrap(err, "failed to update cloudflare")
		return
	}
	ur.cfUpdated = true
	setAddress(mode, ip)
	return
}

func icanhazip(mode string) (string, error) {
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
		return "", errors.Errorf("%s address request timed out", mode)
	case err := <-errc:
		return "", errors.Wrapf(err, "%s address request encountered an error", mode)
	case res := <-response:
		if res.StatusCode != http.StatusOK {
			return "", errors.Errorf("%s address request returned non-ok status code", mode)
		}
		defer res.Body.Close()
		bytes, err := ioutil.ReadAll(res.Body)
		if err != nil {
			return "", errors.Wrapf(err, "%s address request failed to read response body", mode)
		}
		return strings.TrimSpace(string(bytes)), nil
	}
	log.Panicf("%s address request reached an unreachable code path", mode)
	return "", nil
}

func getZoneID(zoneName string) (string, error) {
	cfReqLock.Lock()
	defer cfReqLock.Unlock()
	stateKey := fmt.Sprintf("zone.%s.id", zoneName)
	if v, ok := state.Get(stateKey); ok {
		return v.(string), nil
	}
	zones, err := cf.ListZones()
	if err != nil {
		return "", err
	}
	for _, z := range zones {
		if z.Name == zoneName {
			state.SetDefault(stateKey, z.ID)
			return z.ID, nil
		}
	}
	return "", errors.Errorf(`could not find zone with name "%s"`, zoneName)
}

func getRecord(zoneID, recordName, fam string) (string, string, error) {
	cfReqLock.Lock()
	defer cfReqLock.Unlock()
	fqdn := fmt.Sprintf("%s.%s", recordName, config.GetString("zone_name"))
	stateKey := fmt.Sprintf("record.%s.%s.%s.id", zoneID, recordName, fam)
	if v, ok := state.Get(stateKey); ok {
		rec := v.(cloudflare.DNSRecord)
		return rec.ID, rec.Content, nil
	}
	recs, err := cf.DNSRecords(zoneID, cloudflare.DNSRecord{})
	if err != nil {
		return "", "", err
	}
	var recType string
	if fam == updateModeV6 {
		recType = "AAAA"
	} else if fam == updateModeV4 {
		recType = "A"
	} else {
		log.Panicf("unknown ip address family: %s", fam)
	}
	for _, r := range recs {
		if r.Name == fqdn && r.Type == recType {
			state.SetDefault(stateKey, r)
			return r.ID, r.Content, nil
		}
	}
	log.Printf("debug: could not find %s record for %s, creating one...", recType, fqdn)
	var defaultContent string
	if fam == updateModeV6 {
		defaultContent = "0:0:0:0:0:0:0:0"
	} else if fam == updateModeV4 {
		defaultContent = "0.0.0.0"
	} else {
		log.Panicf("unknown ip address family: %s", fam)
	}
	res, err := cf.CreateDNSRecord(zoneID, cloudflare.DNSRecord{
		Type:    recType,
		Content: defaultContent,
		Name:    fqdn,
	})
	if err != nil {
		return "", "", err
	}
	return res.Result.ID, res.Result.Content, nil
}
