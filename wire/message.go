package wire

import (
	"github.com/fxamacker/cbor/v2"
)

type Message struct {
	*Handshake
	*Encrypted
}

type Encrypted struct {
	Payload []byte
}

type Handshake struct {
	SigningPublicKey   []byte
	TransportPublicKey []byte
	Signature          []byte // sig of transport_pubkey by signing_pubkey
}

func (m Message) Encode() ([]byte, error) {
	return cbor.Marshal(m)
}

func Decode(raw []byte) (Message, error) {
	var m Message
	err := cbor.Unmarshal(raw, &m)
	return m, err
}
