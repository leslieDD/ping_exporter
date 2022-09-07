package main

import (
	"context"
	"fmt"
	"net"
	"net/http"
	"strconv"
	"sync"
	"time"

	"github.com/czerwonk/ping_exporter/config"
	mon "github.com/digineo/go-ping/monitor"
	log "github.com/sirupsen/logrus"
)

// ipVersion represents the IP protocol version of an address
type ipVersion uint8

type target struct {
	host      string
	addresses []net.IPAddr
	delay     time.Duration
	resolver  *net.Resolver
	mutex     sync.Mutex
	keys      sync.Map
	handle    http.Handler
	flushTime time.Time
}

// var targets map[string]*target
type Targets struct {
	lock     sync.Mutex
	targets  map[string]*target
	resolver *net.Resolver
	cfg      *config.Config
	count    int
}

func (t *Targets) Check(host string) bool {
	t.lock.Lock()
	defer t.lock.Unlock()

	_, ok := t.targets[host]
	return ok
}

func (t *Targets) Add(host string, monitor *mon.Monitor) *target {
	t.lock.Lock()
	defer t.lock.Unlock()

	obj, ok := t.targets[host]
	if ok {
		obj.flushTime = time.Now()
		return obj
	}
	t.count += 1
	tObj := &target{
		host:      host,
		addresses: make([]net.IPAddr, 0),
		delay:     time.Duration(5*t.count) * time.Millisecond,
		resolver:  t.resolver,
		keys:      sync.Map{},
		flushTime: time.Now(),
	}
	err := tObj.addOrUpdateMonitor(monitor, t.cfg.Options.DisableIPv6)
	if err != nil {
		log.Errorln(err)
	}
	t.targets[host] = tObj
	return tObj
}

func (t *Targets) Remove(host string) {
	t.lock.Lock()
	defer t.lock.Unlock()

	delete(t.targets, host)
}

func NewTargets(cfg *config.Config) *Targets {
	resolver := setupResolver(cfg)
	t := Targets{
		lock:     sync.Mutex{},
		targets:  map[string]*target{},
		resolver: resolver,
		cfg:      cfg,
		count:    0,
	}
	return &t
}

var targets *Targets

const (
	ipv4 ipVersion = 4
	ipv6 ipVersion = 6
)

func (t *target) addOrUpdateMonitor(monitor *mon.Monitor, disableIPv6 bool) error {
	t.mutex.Lock()
	defer t.mutex.Unlock()

	addrs, err := t.resolver.LookupIPAddr(context.Background(), t.host)
	if err != nil {
		return fmt.Errorf("error resolving target: %w", err)
	}

	var sanitizedAddrs []net.IPAddr
	if disableIPv6 {
		for _, addr := range addrs {
			if getIPVersion(addr) == ipv6 {
				log.Infof("IPv6 disabled: skipping target for host %s (%v)", t.host, addr)
				continue
			}
			sanitizedAddrs = append(sanitizedAddrs, addr)
		}
	} else {
		sanitizedAddrs = addrs
	}

	for _, addr := range sanitizedAddrs {

		err := t.addIfNew(addr, monitor)
		if err != nil {
			return err
		}
	}

	t.cleanUp(sanitizedAddrs, monitor)
	t.addresses = sanitizedAddrs

	return nil
}

func (t *target) addIfNew(addr net.IPAddr, monitor *mon.Monitor) error {
	if isIPAddrInSlice(addr, t.addresses) {
		return nil
	}

	return t.add(addr, monitor)
}

func (t *target) cleanUp(addr []net.IPAddr, monitor *mon.Monitor) {
	for _, o := range t.addresses {
		if !isIPAddrInSlice(o, addr) {
			name := t.nameForIP(o)
			log.Infof("removing target for host %s (%v)", t.host, o)
			monitor.RemoveTarget(name)
			t.keys.Delete(name)
		}
	}
}

func (t *target) add(addr net.IPAddr, monitor *mon.Monitor) error {
	name := t.nameForIP(addr)
	log.Infof("adding target for host %s (%v)", t.host, addr)
	t.keys.Store(name, time.Now())
	return monitor.AddTargetDelayed(name, addr, t.delay)
}

func (t *target) nameForIP(addr net.IPAddr) string {
	return fmt.Sprintf("%s %s %s", t.host, addr.IP, getIPVersion(addr))
}

func isIPAddrInSlice(ipa net.IPAddr, slice []net.IPAddr) bool {
	for _, x := range slice {
		if x.IP.Equal(ipa.IP) {
			return true
		}
	}

	return false
}

// getIPVersion returns the version of IP protocol used for a given address
func getIPVersion(addr net.IPAddr) ipVersion {
	if addr.IP.To4() == nil {
		return ipv6
	}

	return ipv4
}

// String converts ipVersion to a string represention of the IP version used (i.e. "4" or "6")
func (ipv ipVersion) String() string {
	return strconv.Itoa(int(ipv))
}
