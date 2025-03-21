//go:build !windows
// +build !windows

package main

import (
	"bytes"
	"os"
	"testing"
	"time"

	"github.com/slackhq/nebula/cert"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func Test_caSummary(t *testing.T) {
	assert.Equal(t, "ca <flags>: create a self signed certificate authority", caSummary())
}

func Test_caHelp(t *testing.T) {
	ob := &bytes.Buffer{}
	caHelp(ob)
	assert.Equal(
		t,
		"Usage of "+os.Args[0]+" ca <flags>: create a self signed certificate authority\n"+
			"  -arn string\n"+
			"    \tAWS ARN\n"+
			"  -assume-role string\n"+
			"    \tOptional: AWS AssumeRole\n"+
			"  -curve string\n"+
			"    \tECDSA Curve (P256) (default \"P256\")\n"+
			"  -duration duration\n"+
			"    \tOptional: amount of time the certificate should be valid for. Valid time units are seconds: \"s\", minutes: \"m\", hours: \"h\" (default 8760h0m0s)\n"+
			"  -groups string\n"+
			"    \tOptional: comma separated list of groups. This will limit which groups subordinate certs can use\n"+
			"  -name string\n"+
			"    \tRequired: name of the certificate authority\n"+
			"  -networks string\n"+
			"    \tOptional: comma separated list of ip address and network in CIDR notation. This will limit which ip addresses and networks subordinate certs can use in networks\n"+
			"  -out-crt string\n"+
			"    \tOptional: path to write the certificate to (default \"ca.crt\")\n"+
			"  -profile string\n"+
			"    \tOptional: AWS Profile\n"+
			"  -region string\n"+
			"    \tOptional: AWS Region\n"+
			"  -unsafe-networks string\n"+
			"    \tOptional: comma separated list of ip address and network in CIDR notation. This will limit which ip addresses and networks subordinate certs can use in unsafe networks\n"+
			"  -version uint\n"+
			"    \tOptional: version of the certificate format to use (default 2)\n",
		ob.String(),
	)
}

func Test_ca(t *testing.T) {
	ob := &bytes.Buffer{}
	eb := &bytes.Buffer{}

	// required args
	assertHelpError(t, ca(
		[]string{"-version", "1", "-out-crt", "nope", "duration", "100m"}, ob, eb,
	), "-name is required")
	assert.Equal(t, "", ob.String())
	assert.Equal(t, "", eb.String())

	// ipv4 only ips
	assertHelpError(t, ca([]string{"-version", "1", "-name", "ipv6", "-arn", "arn", "-networks", "100::100/100"}, ob, eb), "invalid -networks definition: v1 certificates can only be ipv4, have 100::100/100")
	assert.Equal(t, "", ob.String())
	assert.Equal(t, "", eb.String())

	// ipv4 only subnets
	assertHelpError(t, ca([]string{"-version", "1", "-name", "ipv6", "-arn", "arn", "-unsafe-networks", "100::100/100"}, ob, eb), "invalid -unsafe-networks definition: v1 certificates can only be ipv4, have 100::100/100")
	assert.Equal(t, "", ob.String())
	assert.Equal(t, "", eb.String())

	// TODO
	t.Skip("Need to mock AWS KMS to do the rest of the tests")

	// create temp cert file
	crtF, err := os.CreateTemp("", "test.crt")
	require.NoError(t, err)
	require.NoError(t, os.Remove(crtF.Name()))

	// test proper cert with removed empty groups and subnets
	ob.Reset()
	eb.Reset()
	args := []string{"-version", "1", "-name", "test", "-arn", "arn", "-duration", "100m", "-groups", "1,,   2    ,        ,,,3,4,5", "-out-crt", crtF.Name()}
	require.NoError(t, ca(args, ob, eb))
	assert.Equal(t, "", ob.String())
	assert.Equal(t, "", eb.String())

	// read cert files
	rb, _ := os.ReadFile(crtF.Name())
	lCrt, b, err := cert.UnmarshalCertificateFromPEM(rb)
	assert.Empty(t, b)
	require.NoError(t, err)

	assert.Equal(t, "test", lCrt.Name())
	assert.Empty(t, lCrt.Networks())
	assert.True(t, lCrt.IsCA())
	assert.Equal(t, []string{"1", "2", "3", "4", "5"}, lCrt.Groups())
	assert.Empty(t, lCrt.UnsafeNetworks())
	assert.Len(t, lCrt.PublicKey(), 32)
	assert.Equal(t, time.Duration(time.Minute*100), lCrt.NotAfter().Sub(lCrt.NotBefore()))
	assert.Equal(t, "", lCrt.Issuer())
	assert.True(t, lCrt.CheckSignature(lCrt.PublicKey()))

	// create valid cert/key for overwrite tests
	os.Remove(crtF.Name())
	ob.Reset()
	eb.Reset()
	args = []string{"-version", "1", "-name", "test", "-arn", "arn", "-duration", "100m", "-groups", "1,,   2    ,        ,,,3,4,5", "-out-crt", crtF.Name()}
	require.NoError(t, ca(args, ob, eb))

	// test that we won't overwrite existing certificate file
	ob.Reset()
	eb.Reset()
	args = []string{"-version", "1", "-name", "test", "-arn", "arn", "-duration", "100m", "-groups", "1,,   2    ,        ,,,3,4,5", "-out-crt", crtF.Name()}
	require.EqualError(t, ca(args, ob, eb), "refusing to overwrite existing CA key: "+crtF.Name())
	assert.Equal(t, "", ob.String())
	assert.Equal(t, "", eb.String())
	os.Remove(crtF.Name())
}
