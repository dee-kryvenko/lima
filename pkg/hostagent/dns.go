// This file has been adapted from https://github.com/norouter/norouter/blob/v0.6.4/pkg/agent/dns/dns.go

package hostagent

import (
	"context"
	"errors"
	"fmt"
	"sort"
	"strings"

	"github.com/johnstarich/go/dns/scutil"
	"github.com/miekg/dns"
	"github.com/sirupsen/logrus"
)

type Handler struct {
	domainClientConfigs  map[string][]*dns.ClientConfig
	defaultClientConfigs []*dns.ClientConfig
	clients              []*dns.Client
}

type Server struct {
	udp *dns.Server
	tcp *dns.Server
}

func (s *Server) Shutdown() {
	if s.udp != nil {
		_ = s.udp.Shutdown()
	}
	if s.tcp != nil {
		_ = s.tcp.Shutdown()
	}
}

func newStaticClientConfig(ips []string) (*dns.ClientConfig, error) {
	s := ``
	for _, ip := range ips {
		s += fmt.Sprintf("nameserver %s\n", ip)
	}
	r := strings.NewReader(s)
	return dns.ClientConfigFromReader(r)
}

func newHandler() (dns.Handler, error) {
	h := &Handler{
		domainClientConfigs:  map[string][]*dns.ClientConfig{},
		defaultClientConfigs: []*dns.ClientConfig{},
		clients: []*dns.Client{
			{}, // UDP
			{
				Net: "tcp",
			},
		},
	}

	scConfig, err := scutil.ReadMacOSDNS(context.TODO())
	if err != nil {
		logrus.WithError(err).Warn("failed to detect scutils DNS, falling back to /etc/resolv.conf")
		cc, err := dns.ClientConfigFromFile("/etc/resolv.conf")
		if err != nil {
			fallbackIPs := []string{"8.8.8.8", "1.1.1.1"}
			logrus.WithError(err).Warnf("failed to detect /etc/resolv.conf DNS, falling back to %v", fallbackIPs)
			cc, err = newStaticClientConfig(fallbackIPs)
			if err != nil {
				return nil, err
			}
		}
		h.defaultClientConfigs = []*dns.ClientConfig{cc}
		return h, nil
	}

	var resolvers []scutil.Resolver
	for _, r := range scConfig.Resolvers {
		if !r.Reachable() {
			continue
		}
		resolvers = append(resolvers, r)
	}
	sort.Slice(resolvers, func(i, j int) bool {
		return (resolvers[i].Domain != "" && resolvers[j].Domain == "") ||
			resolvers[i].Order < resolvers[j].Order
	})
	for _, r := range resolvers {
		cc, err := newStaticClientConfig(r.Nameservers)
		if err != nil {
			return nil, err
		}
		if r.Domain == "" {
			h.defaultClientConfigs = append(h.defaultClientConfigs, cc)
		} else {
			if h.domainClientConfigs[r.Domain] == nil {
				h.domainClientConfigs[r.Domain] = []*dns.ClientConfig{}
			}
			h.domainClientConfigs[r.Domain] = append(h.domainClientConfigs[r.Domain], cc)
		}
	}

	return h, nil
}
func (h *Handler) tryWithConfig(w dns.ResponseWriter, req *dns.Msg, clientConfig *dns.ClientConfig) error {
	for _, client := range h.clients {
		for _, srv := range clientConfig.Servers {
			addr := fmt.Sprintf("%s:%s", srv, clientConfig.Port)
			reply, _, err := client.Exchange(req, addr)
			if err != nil {
				logrus.WithError(err).Warnf("Failed to query from %s", addr)
				continue
			}
			_ = w.WriteMsg(reply)
			return nil
		}
	}
	return errors.New("No nameservers found")
}

func (h *Handler) matchDomainConfig(w dns.ResponseWriter, req *dns.Msg, q dns.Question) error {
	for domain, clientConfigs := range h.domainClientConfigs {
		if strings.HasSuffix(strings.ToLower(q.Name), strings.ToLower(domain)+".") {
			for _, clientConfig := range clientConfigs {
				if err := h.tryWithConfig(w, req, clientConfig); err == nil {
					return nil
				}
			}
		}
	}
	return errors.New("No working match found")
}

func (h *Handler) ServeDNS(w dns.ResponseWriter, req *dns.Msg) {
	if req.Opcode == dns.OpcodeQuery || req.Opcode == dns.OpcodeIQuery {
		for _, q := range req.Question {
			if err := h.matchDomainConfig(w, req, q); err == nil {
				return
			}
		}
	}
	for _, clientConfig := range h.defaultClientConfigs {
		if err := h.tryWithConfig(w, req, clientConfig); err == nil {
			return
		}
	}

	_ = w.WriteMsg(&dns.Msg{
		MsgHdr: dns.MsgHdr{
			Id:                 req.Id,
			Response:           true,
			Opcode:             req.Opcode,
			Authoritative:      false,
			Truncated:          false,
			RecursionDesired:   false,
			RecursionAvailable: false,
			Zero:               false,
			AuthenticatedData:  false,
			CheckingDisabled:   false,
			Rcode:              dns.RcodeServerFailure,
		},
	})
}

func (a *HostAgent) StartDNS() (*Server, error) {
	h, err := newHandler()
	if err != nil {
		panic(err)
	}
	server := &Server{}
	if a.udpDNSLocalPort > 0 {
		go func() {
			addr := fmt.Sprintf("127.0.0.1:%d", a.udpDNSLocalPort)
			s := &dns.Server{Net: "udp", Addr: addr, Handler: h}
			server.udp = s
			if e := s.ListenAndServe(); e != nil {
				panic(e)
			}
		}()
	}
	if a.tcpDNSLocalPort > 0 {
		go func() {
			addr := fmt.Sprintf("127.0.0.1:%d", a.tcpDNSLocalPort)
			s := &dns.Server{Net: "tcp", Addr: addr, Handler: h}
			server.tcp = s
			if e := s.ListenAndServe(); e != nil {
				panic(e)
			}
		}()
	}
	return server, nil
}

// FakeDNSServer creates dummy agent pre-configured to run DNS server.
// For debugging.
func FakeDNSServer(udp, tcp int) (*Server, error) {
	a := &HostAgent{
		udpDNSLocalPort: udp,
		tcpDNSLocalPort: tcp,
	}
	return a.StartDNS()
}
