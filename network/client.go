package network

import (
	"net"
	"time"

	"github.com/hashicorp/mdns"
	"github.com/samber/lo"
	log "github.com/sirupsen/logrus"
)

const scanPeriod = 10
const scanTimeout = 2 * time.Second
const scanBufferSize = 256

func (m *Manager) FindPeers() {
	ticker := time.NewTicker(scanPeriod)
	for ; true; <-ticker.C {
		entriesChan := make(chan *mdns.ServiceEntry, scanBufferSize)
		err := mdns.Query(&mdns.QueryParam{
			Service:     serviceName,
			Domain:      "local",
			Timeout:     scanTimeout,
			Entries:     entriesChan,
			DisableIPv6: true,
		})
		if err != nil {
			log.Fatal(err)
		}

		entries, _, _, ok := lo.BufferWithTimeout(entriesChan, scanBufferSize, scanTimeout)
		if !ok {
			log.Error("⛔ issue with buffer timeout")
			continue
		}

		for _, entry := range entries {
			if len(entry.InfoFields) < 2 || entry.InfoFields[0] != serviceName {
				continue // not a node, extra guard against bad mDNS DNS-SD behavior (looking at you roku)
			}
			peerID := entry.InfoFields[1]
			if peerID == m.peerID || m.peerActive(peerID) {
				continue // skip self and active peers
			}

			addr := &net.TCPAddr{IP: entry.AddrV4, Port: entry.Port}
			if !m.connActive(addr) {
				log.Tracef("👀 found peer %s at %s\n", peerID, addr.String())
				go func() {
					conn, err := net.Dial(addr.Network(), addr.String())
					if err != nil {
						log.Error(err)
						return
					}
					m.HandleConn(conn, false)
				}()
			}
		}
	}
}
