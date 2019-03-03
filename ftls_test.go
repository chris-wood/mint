package mint

import (
	"testing"
)

func TestFTLS(t *testing.T) {
	group := X25519
	scheme := Ed25519
	params := cipherSuiteMap[TLS_AES_128_GCM_SHA256]
	clientKeyID := []byte("client")
	serverKeyID := []byte("server")

	clientPriv, err := newSigningKey(scheme)
	assertNotError(t, err, "Failed to generate client signing key")

	serverPriv, err := newSigningKey(scheme)
	assertNotError(t, err, "Failed to generate server signing key")

	client := fClient{
		fConfig: fConfig{
			group:     group,
			scheme:    scheme,
			params:    params,
			myPriv:    clientPriv,
			peerPub:   serverPriv.Public(),
			myKeyID:   clientKeyID,
			peerKeyID: serverKeyID,
		},
	}

	server := fServer{
		fConfig: fConfig{
			group:     group,
			scheme:    scheme,
			params:    params,
			myPriv:    serverPriv,
			peerPub:   clientPriv.Public(),
			myKeyID:   serverKeyID,
			peerKeyID: clientKeyID,
		},
	}

	m1, err := client.NewMessage1()
	assertNotError(t, err, "Failed to generate Message1")

	m2, err := server.HandleMessage1(m1)
	assertNotError(t, err, "Failed to handle Message1")

	m3, err := client.HandleMessage2(m2)
	assertNotError(t, err, "Failed to handle Message2")

	err = server.HandleMessage3(m3)
	assertNotError(t, err, "Failed to handle Message3")

	assertByteEquals(t, client.clientAppSecret, server.clientAppSecret)
	assertByteEquals(t, client.serverAppSecret, server.serverAppSecret)
}
