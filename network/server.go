package network

import (
	"net"

	log "github.com/sirupsen/logrus"
)

func (m *Manager) Serve() error {
	lis, err := net.Listen("tcp", ":0")
	if err != nil {
		return err
	}
	m.serverAddr = lis.Addr().(*net.TCPAddr)

	log.Infof("🌱 server listening at %v", lis.Addr().String())
	go func() {
		for {
			conn, err := lis.Accept()
			if err != nil {
				log.Fatal(err)
			}
			log.Tracef("🔁 new connection from %v", conn.RemoteAddr().String())
			go func() {
				if m.connActive(conn.RemoteAddr()) { // already established, reject peer
					log.Warn("already has peer", conn.RemoteAddr().String())
					conn.Close()
					return
				}

				m.HandleConn(conn, true)
			}()
		}
	}()

	return nil
}
