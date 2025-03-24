//go:build !windows
// +build !windows

package main

import (
	"bytes"
	"os"
	"testing"

	"github.com/stretchr/testify/assert"
)

func Test_signSummary(t *testing.T) {
	assert.Equal(t, "sign <flags>: create and sign a certificate", signSummary())
}

func Test_signHelp(t *testing.T) {
	ob := &bytes.Buffer{}
	signHelp(ob)
	assert.Equal(
		t,
		"Usage of "+os.Args[0]+" sign <flags>: create and sign a certificate\n"+
			"  -arn string\n"+
			"    \tAWS ARN\n"+
			"  -assume-role string\n"+
			"    \tOptional: AWS AssumeRole\n"+
			"  -ca-crt string\n"+
			"    \tOptional: path to the signing CA cert (default \"ca.crt\")\n"+
			"  -duration duration\n"+
			"    \tOptional: how long the cert should be valid for. The default is 1 second before the signing cert expires. Valid time units are seconds: \"s\", minutes: \"m\", hours: \"h\"\n"+
			"  -groups string\n"+
			"    \tOptional: comma separated list of groups\n"+
			"  -in-pub string\n"+
			"    \tOptional (if out-key not set): path to read a previously generated public key\n"+
			"  -name string\n"+
			"    \tRequired: name of the cert, usually a hostname\n"+
			"  -networks string\n"+
			"    \tRequired: comma separated list of ip address and network in CIDR notation to assign to this cert\n"+
			"  -out-crt string\n"+
			"    \tOptional: path to write the certificate to\n"+
			"  -out-key string\n"+
			"    \tOptional (if in-pub not set): path to write the private key to\n"+
			"  -out-qr string\n"+
			"    \tOptional: output a qr code image (png) of the certificate\n"+
			"  -profile string\n"+
			"    \tOptional: AWS Profile\n"+
			"  -region string\n"+
			"    \tOptional: AWS Region\n"+
			"  -unsafe-networks string\n"+
			"    \tOptional: comma separated list of ip address and network in CIDR notation. Unsafe networks this cert can route for\n"+
			"  -version uint\n"+
			"    \tOptional: version of the certificate format to use, the default is to create both v1 and v2 certificates.\n",
		ob.String(),
	)
}

func Test_signCert(t *testing.T) {
	ob := &bytes.Buffer{}
	eb := &bytes.Buffer{}

	// required args
	assertHelpError(t, signCert(
		[]string{"-version", "1", "-ca-crt", "./nope", "-arn", "nope", "-networks", "1.1.1.1/24", "-out-key", "nope", "-out-crt", "nope"}, ob, eb,
	), "-name is required")
	assert.Empty(t, ob.String())
	assert.Empty(t, eb.String())

	assertHelpError(t, signCert(
		[]string{"-version", "1", "-ca-crt", "./nope", "-arn", "nope", "-name", "test", "-out-key", "nope", "-out-crt", "nope"}, ob, eb,
	), "-networks is required")
	assert.Empty(t, ob.String())
	assert.Empty(t, eb.String())

	// cannot set -in-pub and -out-key
	assertHelpError(t, signCert(
		[]string{"-version", "1", "-ca-crt", "./nope", "-arn", "nope", "-name", "test", "-in-pub", "nope", "-networks", "1.1.1.1/24", "-out-crt", "nope", "-out-key", "nope"}, ob, eb,
	), "cannot set both -in-pub and -out-key")
	assert.Empty(t, ob.String())
	assert.Empty(t, eb.String())

	// TODO
	t.Skip("Need to mock AWS KMS to do the rest of the tests")
}
