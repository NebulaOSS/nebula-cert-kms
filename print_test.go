package main

import (
	"crypto/rand"
	"net/netip"
	"time"

	"github.com/slackhq/nebula/cert"
	"golang.org/x/crypto/ed25519"
)

// NewTestCaCert will generate a CA cert
func NewTestCaCert(name string, pubKey, privKey []byte, before, after time.Time, networks, unsafeNetworks []netip.Prefix, groups []string) (cert.Certificate, []byte) {
	var err error
	if pubKey == nil || privKey == nil {
		pubKey, privKey, err = ed25519.GenerateKey(rand.Reader)
		if err != nil {
			panic(err)
		}
	}

	t := &cert.TBSCertificate{
		Version:        cert.Version1,
		Name:           name,
		NotBefore:      time.Unix(before.Unix(), 0),
		NotAfter:       time.Unix(after.Unix(), 0),
		PublicKey:      pubKey,
		Networks:       networks,
		UnsafeNetworks: unsafeNetworks,
		Groups:         groups,
		IsCA:           true,
	}

	c, err := t.Sign(nil, cert.Curve_CURVE25519, privKey)
	if err != nil {
		panic(err)
	}

	return c, privKey
}

func NewTestCert(ca cert.Certificate, signerKey []byte, name string, before, after time.Time, networks, unsafeNetworks []netip.Prefix, groups []string) (cert.Certificate, []byte) {
	if before.IsZero() {
		before = ca.NotBefore()
	}

	if after.IsZero() {
		after = ca.NotAfter()
	}

	if len(networks) == 0 {
		networks = []netip.Prefix{netip.MustParsePrefix("10.0.0.123/8")}
	}

	pub, rawPriv := x25519Keypair()
	nc := &cert.TBSCertificate{
		Version:        cert.Version1,
		Name:           name,
		Networks:       networks,
		UnsafeNetworks: unsafeNetworks,
		Groups:         groups,
		NotBefore:      time.Unix(before.Unix(), 0),
		NotAfter:       time.Unix(after.Unix(), 0),
		PublicKey:      pub,
		IsCA:           false,
	}

	c, err := nc.Sign(ca, ca.Curve(), signerKey)
	if err != nil {
		panic(err)
	}

	return c, rawPriv
}
