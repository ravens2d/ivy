package wire

import (
	"crypto/cipher"
	"crypto/ecdh"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/base64"
	"errors"
	"net"

	"golang.org/x/crypto/chacha20poly1305"
)

type EncryptedConn struct {
	*Conn

	// our temp keys for transport encryption
	transportPublicKey  *ecdh.PublicKey
	transportPrivateKey *ecdh.PrivateKey

	peerTransportPublicKey *ecdh.PublicKey    // their temp public key for transport encryption
	peerPublicSigningKey   *ed25519.PublicKey // their long term public signing key from the handshake

	// our shared secret
	transportSharedKey []byte
	transportCipher    cipher.AEAD
}

func NewEncryptedConn(conn net.Conn) (*EncryptedConn, error) {
	transportPrivateKey, err := ecdh.X25519().GenerateKey(rand.Reader)
	if err != nil {
		return nil, err
	}

	return &EncryptedConn{
		Conn:                NewConn(conn),
		transportPrivateKey: transportPrivateKey,
		transportPublicKey:  transportPrivateKey.PublicKey(),
	}, nil
}

func (c *EncryptedConn) PeerID() string {
	return base64.StdEncoding.EncodeToString(*c.peerPublicSigningKey)
}

func (c *EncryptedConn) HandshakeAsClient(signingKey ed25519.PrivateKey) error {
	if err := c.Conn.SendMessage(c.buildHandshakeMessage(signingKey)); err != nil {
		return err
	}

	serverHandshake, err := c.Conn.ReadMessage()
	if err != nil {
		return err
	}

	if !c.verifyHandshake(serverHandshake) {
		return errors.New("handshake verification failed")
	}

	err = c.deriveSharedKey()
	if err != nil {
		return err
	}

	return nil
}

func (c *EncryptedConn) HandshakeAsServer(signingKey ed25519.PrivateKey) error {
	clientHandshake, err := c.Conn.ReadMessage()
	if err != nil {
		return err
	}

	if !c.verifyHandshake(clientHandshake) {
		return errors.New("handshake verification failed")
	}

	err = c.Conn.SendMessage(c.buildHandshakeMessage(signingKey))
	if err != nil {
		return err
	}

	err = c.deriveSharedKey()
	if err != nil {
		return err
	}

	return nil
}

func (c *EncryptedConn) buildHandshakeMessage(signingKey ed25519.PrivateKey) *Message {
	sig := ed25519.Sign(signingKey, c.transportPublicKey.Bytes())
	return &Message{Handshake: &Handshake{
		SigningPublicKey:   signingKey.Public().(ed25519.PublicKey),
		TransportPublicKey: c.transportPublicKey.Bytes(),
		Signature:          sig,
	}}
}

// verifyHandshake mutates the conn to include the peer's public keys
func (c *EncryptedConn) verifyHandshake(m *Message) bool {
	if m.Handshake == nil {
		return false
	}

	peerTransportPublicKey, err := ecdh.X25519().NewPublicKey(m.Handshake.TransportPublicKey)
	if err != nil {
		return false
	}

	ok := ed25519.Verify(m.Handshake.SigningPublicKey, m.Handshake.TransportPublicKey, m.Handshake.Signature)
	if ok {
		c.peerTransportPublicKey = peerTransportPublicKey
		c.peerPublicSigningKey = (*ed25519.PublicKey)(&m.Handshake.SigningPublicKey)
	}
	return ok
}

func (c *EncryptedConn) deriveSharedKey() error {
	shared, err := c.transportPrivateKey.ECDH(c.peerTransportPublicKey)
	if err != nil {
		return err
	}
	cypher, err := chacha20poly1305.NewX(shared)
	if err != nil {
		return err
	}
	c.transportSharedKey = shared
	c.transportCipher = cypher

	return nil
}

func (c *EncryptedConn) ReadMessage() (*Message, error) {
	msg, err := c.Conn.ReadMessage()
	if err != nil {
		return nil, err
	}

	if msg.Encrypted == nil {
		return nil, errors.New("message not encrypted")
	}

	rawMsg, err := c.transportCipher.Open(nil, make([]byte, c.transportCipher.NonceSize()), msg.Encrypted.Payload, nil)
	if err != nil {
		return nil, err
	}

	decodedMsg, err := Decode(rawMsg)
	if err != nil {
		return nil, err
	}
	return &decodedMsg, nil
}

func (c *EncryptedConn) SendMessage(m *Message) error {
	rawMsg, err := m.Encode()
	if err != nil {
		return err
	}
	encryptedMsg := c.transportCipher.Seal(nil, make([]byte, c.transportCipher.NonceSize()), rawMsg, nil)

	return c.Conn.SendMessage(&Message{Encrypted: &Encrypted{
		Payload: encryptedMsg,
	}})
}

// ReadMessages continuously reads messages from the connection in a goroutine and returns them on a channel
func (c *EncryptedConn) ReadMessages() (<-chan *Message, <-chan error) {
	resC := make(chan *Message)
	errC := make(chan error)
	go func() {
		for {
			msg, err := c.ReadMessage()
			if err != nil {
				errC <- err
				return
			}
			resC <- msg
		}
	}()
	return resC, errC
}
