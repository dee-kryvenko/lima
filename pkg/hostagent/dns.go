// This file has been adapted from https://github.com/norouter/norouter/blob/v0.6.4/pkg/agent/dns/dns.go

package hostagent

import (
	"fmt"
	"net"
	"strings"

	"github.com/miekg/dns"
	"github.com/sirupsen/logrus"
)

type Handler struct {
	clientConfig *dns.ClientConfig
	clients      []*dns.Client
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

func newStaticClientConfig(ips []net.IP) (*dns.ClientConfig, error) {
	s := ``
	for _, ip := range ips {
		s += fmt.Sprintf("nameserver %s\n", ip.String())
	}
	r := strings.NewReader(s)
	return dns.ClientConfigFromReader(r)
}

func newHandler() (dns.Handler, error) {
	cc, err := dns.ClientConfigFromFile("/etc/resolv.conf")
	if err != nil {
		fallbackIPs := []net.IP{net.ParseIP("8.8.8.8"), net.ParseIP("1.1.1.1")}
		logrus.WithError(err).Warnf("failed to detect system DNS, falling back to %v", fallbackIPs)
		cc, err = newStaticClientConfig(fallbackIPs)
		if err != nil {
			return nil, err
		}
	}
	clients := []*dns.Client{
		{}, // UDP
		{Net: "tcp"},
	}
	h := &Handler{
		clientConfig: cc,
		clients:      clients,
	}
	return h, nil
}

func (h *Handler) handleQuery(w dns.ResponseWriter, req *dns.Msg) {
	var (
		reply   dns.Msg
		handled bool
	)
	reply.SetReply(req)
	for _, q := range reply.Question {
		switch q.Qtype {
		case dns.TypeA:
			addrs, err := net.LookupIP(q.Name)
			if err == nil && len(addrs) > 0 {
				for _, ip := range addrs {
					if ip.To4() != nil {
						a := &dns.A{
							Hdr: dns.RR_Header{
								Name:   q.Name,
								Rrtype: dns.TypeA,
								Class:  dns.ClassINET,
								Ttl:    5,
							},
							A: ip.To4(),
						}
						reply.Answer = append(reply.Answer, a)
						handled = true
					}
				}
			}
		case dns.TypeAAAA:
			addrs, err := net.LookupIP(q.Name)
			if err == nil && len(addrs) > 0 {
				for _, ip := range addrs {
					if ip.To16() != nil {
						a := &dns.AAAA{
							Hdr: dns.RR_Header{
								Name:   q.Name,
								Rrtype: dns.TypeAAAA,
								Class:  dns.ClassINET,
								Ttl:    5,
							},
							AAAA: ip.To16(),
						}
						reply.Answer = append(reply.Answer, a)
						handled = true
					}
				}
			}
		case dns.TypeCNAME:
			cname, err := net.LookupCNAME(q.Name)
			if err == nil && cname != "" {
				a := &dns.CNAME{
					Hdr: dns.RR_Header{
						Name:   q.Name,
						Rrtype: dns.TypeCNAME,
						Class:  dns.ClassINET,
						Ttl:    5,
					},
					Target: cname,
				}
				reply.Answer = append(reply.Answer, a)
				handled = true
			}
		case dns.TypeTXT:
			txt, err := net.LookupTXT(q.Name)
			if err == nil && len(txt) > 0 {
				a := &dns.TXT{
					Hdr: dns.RR_Header{
						Name:   q.Name,
						Rrtype: dns.TypeTXT,
						Class:  dns.ClassINET,
						Ttl:    5,
					},
					Txt: txt,
				}
				reply.Answer = append(reply.Answer, a)
				handled = true
			}
		case dns.TypeNS:
			ns, err := net.LookupNS(q.Name)
			if err == nil && len(ns) > 0 {
				for _, s := range ns {
					if s.Host != "" {
						a := &dns.NS{
							Hdr: dns.RR_Header{
								Name:   q.Name,
								Rrtype: dns.TypeNS,
								Class:  dns.ClassINET,
								Ttl:    5,
							},
							Ns: s.Host,
						}
						reply.Answer = append(reply.Answer, a)
						handled = true
					}
				}
			}
		}
	}
	if handled {
		_ = w.WriteMsg(&reply)
		return
	}
	h.handleDefault(w, req)
}

func (h *Handler) handleDefault(w dns.ResponseWriter, req *dns.Msg) {
	for _, client := range h.clients {
		for _, srv := range h.clientConfig.Servers {
			addr := fmt.Sprintf("%s:%s", srv, h.clientConfig.Port)
			reply, _, err := client.Exchange(req, addr)
			if err == nil {
				_ = w.WriteMsg(reply)
				return
			}
		}
	}
	var reply dns.Msg
	reply.SetReply(req)
	_ = w.WriteMsg(&reply)
}

func (h *Handler) ServeDNS(w dns.ResponseWriter, req *dns.Msg) {
	switch req.Opcode {
	case dns.OpcodeQuery:
		h.handleQuery(w, req)
	default:
		h.handleDefault(w, req)
	}
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
