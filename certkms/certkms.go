package certkms

import (
	"context"
	"crypto"

	"github.com/aws/aws-sdk-go-v2/aws"
	awsconfig "github.com/aws/aws-sdk-go-v2/config"
	"github.com/aws/aws-sdk-go-v2/credentials/stscreds"
	"github.com/aws/aws-sdk-go-v2/service/kms"
	"github.com/aws/aws-sdk-go-v2/service/sts"
	"github.com/psanford/kmssigner"
	"github.com/slackhq/nebula/cert"
)

type NebulaSigner interface {
	// Provides Public() and Sign(...) methods
	crypto.Signer

	CertSignerLambda() cert.SignerLambda
}

type nebulaSigner struct {
	crypto.Signer

	signerLambda cert.SignerLambda
}

type AWSConfig struct {
	AssumeRole string
	Profile    string
	Region     string
}

// BasicSigner builds a NebulaSigner from a basic AWS config.
// More complicated uses can use Signer
func BasicSigner(config AWSConfig, arn string) (NebulaSigner, error) {
	var opts []func(*awsconfig.LoadOptions) error
	if config.Region != "" {
		opts = append(opts, awsconfig.WithRegion(config.Region))
	}
	if config.Profile != "" {
		opts = append(opts, awsconfig.WithSharedConfigProfile(config.Profile))
	}

	cfg, err := awsconfig.LoadDefaultConfig(context.TODO(), opts...)
	if err != nil {
		return nil, err
	}

	if config.AssumeRole != "" {
		stsSvc := sts.NewFromConfig(cfg)
		creds := stscreds.NewAssumeRoleProvider(stsSvc, config.AssumeRole)

		cfg.Credentials = aws.NewCredentialsCache(creds)
	}

	kmsClient := kms.NewFromConfig(cfg)
	return Signer(kmsClient, arn)
}

// Signer builds a NebulaSigner using kmssigner and the given kms.Client
func Signer(client *kms.Client, arn string) (NebulaSigner, error) {
	ks, err := kmssigner.New(client, arn)
	if err != nil {
		return nil, err
	}

	return &nebulaSigner{
		Signer:       ks,
		signerLambda: certSignerLambda(ks),
	}, nil
}

func (n *nebulaSigner) CertSignerLambda() cert.SignerLambda {
	return n.signerLambda
}

func certSignerLambda(cs crypto.Signer) cert.SignerLambda {
	const hashFunc = crypto.SHA256

	return func(tbs []byte) ([]byte, error) {
		h := hashFunc.New()
		h.Write(tbs)
		digest := h.Sum(nil)

		signature, err := cs.Sign(nil, digest, hashFunc)
		if err != nil {
			return nil, err
		}

		// Check the signature to ensure the crypto.Signer behaved correctly.
		// if ok := ecdsa.VerifyASN1(cs.Public().(*ecdsa.Publiccs), digest, signature); !ok {
		// 	return nil, fmt.Errorf("certkms: signature returned by signer is invalid")
		// }

		return signature, err
	}

}
