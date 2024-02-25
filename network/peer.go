package network

import (
	"io"
	"net"

	"ivy/wire"

	log "github.com/sirupsen/logrus"
)

type Peer struct {
	ID   string
	Conn net.Conn

	EncryptedConn *wire.EncryptedConn

	isClient bool // if this peer is a client of ours
}

func (m *Manager) HandleConn(c net.Conn, asServer bool) {
	m.addConn(c)
	defer m.removeConn(c)
	defer c.Close()

	encryptedConn, err := wire.NewEncryptedConn(c)
	if err != nil {
		log.Error(err)
		return
	}

	if asServer {
		err = encryptedConn.HandshakeAsServer(m.privateKey)
	} else {
		err = encryptedConn.HandshakeAsClient(m.privateKey)
	}
	if err != nil {
		log.Error(err)
		return
	}

	// create peer
	p := &Peer{
		ID:            encryptedConn.PeerID(),
		Conn:          c,
		EncryptedConn: encryptedConn,
		isClient:      asServer,
	}
	log.Infof("🔓 completed handshake with peer %s\n", p.ID)

	m.addPeer(p)
	defer m.removePeer(p)

	m.HandlePeer(p)
}

func (m *Manager) HandlePeer(p *Peer) {
	readC, readErrC := p.EncryptedConn.ReadMessages()
	for {
		select {
		case err := <-readErrC:
			if err == io.EOF {
				log.Errorf("⛔ peer closed connection %s (%s)\n", p.Conn.RemoteAddr().String(), p.TypeIndicator())
				return
			}
			log.Errorf("⛔ read err: %v\n", err)
			return

		case msg := <-readC:
			log.Tracef("🔗 message %v from %s (%s)\n", msg, p.Conn.RemoteAddr().String(), p.TypeIndicator())
		}
	}
}

func (p *Peer) TypeIndicator() string {
	if p.isClient {
		return "client"
	}
	return "server"
}
