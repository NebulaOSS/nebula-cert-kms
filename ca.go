package main

import (
	"crypto/ecdsa"
	"flag"
	"fmt"
	"io"
	"net/netip"
	"os"
	"strings"
	"time"

	"github.com/nebulaoss/nebula-cert-kms/certkms"
	"github.com/slackhq/nebula/cert"
)

type caFlags struct {
	set            *flag.FlagSet
	name           *string
	duration       *time.Duration
	outCertPath    *string
	groups         *string
	networks       *string
	unsafeNetworks *string
	version        *uint

	assumeRole *string
	profile    *string
	region     *string
	arn        *string

	curve *string
}

func newCaFlags() *caFlags {
	cf := caFlags{set: flag.NewFlagSet("ca", flag.ContinueOnError)}
	cf.set.Usage = func() {}
	cf.name = cf.set.String("name", "", "Required: name of the certificate authority")
	cf.version = cf.set.Uint("version", uint(cert.Version2), "Optional: version of the certificate format to use")
	cf.duration = cf.set.Duration("duration", time.Duration(time.Hour*8760), "Optional: amount of time the certificate should be valid for. Valid time units are seconds: \"s\", minutes: \"m\", hours: \"h\"")
	cf.outCertPath = cf.set.String("out-crt", "ca.crt", "Optional: path to write the certificate to")
	cf.groups = cf.set.String("groups", "", "Optional: comma separated list of groups. This will limit which groups subordinate certs can use")
	cf.networks = cf.set.String("networks", "", "Optional: comma separated list of ip address and network in CIDR notation. This will limit which ip addresses and networks subordinate certs can use in networks")
	cf.unsafeNetworks = cf.set.String("unsafe-networks", "", "Optional: comma separated list of ip address and network in CIDR notation. This will limit which ip addresses and networks subordinate certs can use in unsafe networks")
	cf.curve = cf.set.String("curve", "P256", "ECDSA Curve (P256)")

	cf.assumeRole = cf.set.String("assume-role", "", "Optional: AWS AssumeRole")
	cf.profile = cf.set.String("profile", "", "Optional: AWS Profile")
	cf.region = cf.set.String("region", "", "Optional: AWS Region")
	cf.arn = cf.set.String("arn", "", "AWS ARN")

	return &cf
}

func ca(args []string, out io.Writer, errOut io.Writer) error {
	cf := newCaFlags()
	err := cf.set.Parse(args)
	if err != nil {
		return err
	}

	if err := mustFlagString("name", cf.name); err != nil {
		return err
	}
	if err := mustFlagString("out-crt", cf.outCertPath); err != nil {
		return err
	}
	if err := mustFlagString("arn", cf.arn); err != nil {
		return err
	}

	if *cf.duration <= 0 {
		return &helpError{"-duration must be greater than 0"}
	}

	var groups []string
	if *cf.groups != "" {
		for _, rg := range strings.Split(*cf.groups, ",") {
			g := strings.TrimSpace(rg)
			if g != "" {
				groups = append(groups, g)
			}
		}
	}

	version := cert.Version(*cf.version)
	if version != cert.Version1 && version != cert.Version2 {
		return newHelpErrorf("-version must be either %v or %v", cert.Version1, cert.Version2)
	}

	var networks []netip.Prefix

	if *cf.networks != "" {
		for _, rs := range strings.Split(*cf.networks, ",") {
			rs := strings.Trim(rs, " ")
			if rs != "" {
				n, err := netip.ParsePrefix(rs)
				if err != nil {
					return newHelpErrorf("invalid -networks definition: %s", rs)
				}
				if version == cert.Version1 && !n.Addr().Is4() {
					return newHelpErrorf("invalid -networks definition: v1 certificates can only be ipv4, have %s", rs)
				}
				networks = append(networks, n)
			}
		}
	}

	var unsafeNetworks []netip.Prefix

	if *cf.unsafeNetworks != "" {
		for _, rs := range strings.Split(*cf.unsafeNetworks, ",") {
			rs := strings.Trim(rs, " ")
			if rs != "" {
				n, err := netip.ParsePrefix(rs)
				if err != nil {
					return newHelpErrorf("invalid -unsafe-networks definition: %s", rs)
				}
				if version == cert.Version1 && !n.Addr().Is4() {
					return newHelpErrorf("invalid -unsafe-networks definition: v1 certificates can only be ipv4, have %s", rs)
				}
				unsafeNetworks = append(unsafeNetworks, n)
			}
		}
	}

	s, err := certkms.BasicSigner(certkms.AWSConfig{
		AssumeRole: *cf.assumeRole,
		Profile:    *cf.profile,
		Region:     *cf.region,
	}, *cf.arn)
	if err != nil {
		return fmt.Errorf("error creating KMS Signer: %s", err)
	}

	var curve cert.Curve
	var pub []byte
	switch *cf.curve {
	case "P256":
		curve = cert.Curve_P256

		pubkey, ok := s.Public().(*ecdsa.PublicKey)
		if !ok {
			return fmt.Errorf("KMS key type is invalid, expected P256 but got: %T", s.Public())
		}

		// ecdh.Bytes lets us get at the encoded bytes, even though
		// we aren't using ECDH here.
		ePub, err := pubkey.ECDH()
		if err != nil {
			return fmt.Errorf("error while converting ecdsa key: %s", err)
		}
		pub = ePub.Bytes()
	default:
		return fmt.Errorf("invalid curve: %s", *cf.curve)
	}

	t := &cert.TBSCertificate{
		Version:        version,
		Name:           *cf.name,
		Groups:         groups,
		Networks:       networks,
		UnsafeNetworks: unsafeNetworks,
		NotBefore:      time.Now(),
		NotAfter:       time.Now().Add(*cf.duration),
		PublicKey:      pub,
		IsCA:           true,
		Curve:          curve,
	}

	if _, err := os.Stat(*cf.outCertPath); err == nil {
		return fmt.Errorf("refusing to overwrite existing CA cert: %s", *cf.outCertPath)
	}

	c, err := t.SignWith(nil, curve, s.CertSignerLambda())
	if err != nil {
		return fmt.Errorf("error while signing with PKCS#11: %w", err)
	}

	b, err := c.MarshalPEM()
	if err != nil {
		return fmt.Errorf("error while marshalling certificate: %s", err)
	}

	err = os.WriteFile(*cf.outCertPath, b, 0600)
	if err != nil {
		return fmt.Errorf("error while writing out-crt: %s", err)
	}

	return nil
}

func caSummary() string {
	return "ca <flags>: create a self signed certificate authority"
}

func caHelp(out io.Writer) {
	cf := newCaFlags()
	out.Write([]byte("Usage of " + os.Args[0] + " " + caSummary() + "\n"))
	cf.set.SetOutput(out)
	cf.set.PrintDefaults()
}
