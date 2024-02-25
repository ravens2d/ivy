package network

import (
	"crypto/ed25519"
	"encoding/base64"
	"errors"
	"net"
	"sync"
	"time"

	log "github.com/sirupsen/logrus"
)

type Manager struct {
	peerID     string
	publicKey  ed25519.PublicKey
	privateKey ed25519.PrivateKey

	serverAddr *net.TCPAddr // populated by Serve()

	connMutex sync.Mutex
	conns     map[string]net.Conn // ConnID -> Conn

	peerMutex sync.Mutex
	peers     map[string]*Peer // PeerID -> Peer
}

func NewManager(privateKey ed25519.PrivateKey) *Manager {
	publicKey := privateKey.Public().(ed25519.PublicKey)
	peerID := base64.StdEncoding.EncodeToString(publicKey)

	return &Manager{
		peerID:     peerID,
		publicKey:  publicKey,
		privateKey: privateKey,

		conns: make(map[string]net.Conn),
		peers: make(map[string]*Peer),
	}
}

func (m *Manager) addConn(conn net.Conn) {
	m.connMutex.Lock()
	defer m.connMutex.Unlock()
	m.conns[conn.RemoteAddr().String()] = conn
}

func (m *Manager) connActive(a net.Addr) bool {
	m.connMutex.Lock()
	defer m.connMutex.Unlock()
	_, ok := m.conns[a.String()]
	return ok
}

func (m *Manager) removeConn(conn net.Conn) {
	m.connMutex.Lock()
	defer m.connMutex.Unlock()
	delete(m.conns, conn.RemoteAddr().String())
}

func (m *Manager) addPeer(peer *Peer) error {
	m.peerMutex.Lock()
	defer m.peerMutex.Unlock()
	if _, ok := m.peers[peer.ID]; ok {
		log.Errorf("⛔ peer already exists %s at %s (%s)\n", peer.ID, peer.Conn.RemoteAddr().String(), peer.TypeIndicator())
		return errors.New("peer already exists")
	}
	m.peers[peer.ID] = peer
	log.Infof("🤝 added peer %s at %s (%s)\n", peer.ID, peer.Conn.RemoteAddr().String(), peer.TypeIndicator())
	return nil
}

func (m *Manager) peerActive(id string) bool {
	m.peerMutex.Lock()
	defer m.peerMutex.Unlock()
	_, ok := m.peers[id]
	return ok
}

func (m *Manager) removePeer(peer *Peer) {
	m.peerMutex.Lock()
	defer m.peerMutex.Unlock()

	p, ok := m.peers[peer.ID]
	if !ok {
		return // just for logging sake
	}
	if p.Conn.RemoteAddr().String() != peer.Conn.RemoteAddr().String() {
		return // we already have a peer with this ID, but it's a different connection
	}

	delete(m.peers, peer.ID)
	log.Infof("👋 removed peer %s at %s (%s)\n", peer.ID, peer.Conn.RemoteAddr().String(), peer.TypeIndicator())
}

func (m *Manager) PeerDisplayLoop() {
	ticker := time.NewTicker(15 * time.Second)
	for range ticker.C {
		m.peerMutex.Lock()
		log.Info("===")
		for peerID, p := range m.peers {
			log.Infof("👋 peer %s at %s (%s)\n", peerID, p.Conn.RemoteAddr().String(), p.TypeIndicator())
		}
		log.Info("===")
		m.peerMutex.Unlock()
	}
}
