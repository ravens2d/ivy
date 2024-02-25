package main

import (
	"crypto/ed25519"
	"crypto/rand"

	"ivy/network"

	log "github.com/sirupsen/logrus"
)

func main() {
	log.SetLevel(log.TraceLevel)

	// TODO: check for file first, command line args, etc
	_, privateKey, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		log.Fatal(err)
	}

	network := network.NewManager(privateKey)
	err = network.Serve()
	if err != nil {
		log.Fatal(err)
	}

	err = network.Broadcast()
	if err != nil {
		log.Fatal(err)
	}

	go network.PeerDisplayLoop()

	network.FindPeers()
}
