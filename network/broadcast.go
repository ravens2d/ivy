package network

import (
	"github.com/hashicorp/mdns"
	log "github.com/sirupsen/logrus"
)

const serviceName = "ivy"

func (m *Manager) Broadcast() error {
	service, err := mdns.NewMDNSService(m.peerID, serviceName, "", "", m.serverAddr.Port, nil, []string{serviceName, m.peerID})
	if err != nil {
		return err
	}

	// kicks off gorotuine in constructor
	server, err := mdns.NewServer(&mdns.Config{Zone: service})
	if err != nil {
		return err
	}
	_ = server // TODO: figure out server shutdown

	log.Infof("📣 broadcasting as peer %s\n", m.peerID)
	return nil
}
