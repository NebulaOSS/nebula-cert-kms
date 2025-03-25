nebula-cert-kms
===============

This utility lets you create a Nebula CA cert this is backed by a private key in AWS KMS. This allows you to sign certificates without the ability for the private key material to leak.

This is only possible with P256 certificates at this time, as AWS KMS does not support Ed25519.

Usage
-----

First, you need to create a new AWS KMS with the following parameters:

- `ECC_NIST_P256`
- `SIGN_VERIFY`

The next step is to self sign a new CA certificate with this key. Example:

    nebula-cert-kms ca \
        -version 1 \
        -out-crt kms-ca.crt \
        -name 'My KMS CA' \
        -region 'us-east-1' \
        -arn 'arn:aws:kms:{... KMS key or alias ARN here ...}'

After you create the CA, you can sign certificates with it. Example:

    nebula-cert-kms sign \
        -ca-crt kms-ca.crt \
        -name 'My Test Host' \
        -networks '192.168.0.1/16' \
        -region 'us-east-1' \
        -arn 'arn:aws:kms:{... KMS key or alias ARN here ...}'

Usage as a Library
------------------

A `certkms` package is provided which gives you a way to create a `cert.SignerLambda` that you can pass to `(cert.Certificate).SignWith` to sign certificates using the KMS key.
