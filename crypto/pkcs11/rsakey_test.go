/*
Copyright (C) BABEC. All rights reserved.
Copyright (C) THL A29 Limited, a Tencent company. All rights reserved.

SPDX-License-Identifier: Apache-2.0
*/

package pkcs11

import (
	"crypto"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"testing"

	"github.com/miekg/pkcs11"

	bccrypto "github.com/xhx/gm-pkg/crypto"
	"github.com/stretchr/testify/assert"
)

func TestNewPrivateKey_RSA(t *testing.T) {
	privKeyId := string(internalRSAKeyLabel)
	bcPriv, err := NewPrivateKey(p11, privKeyId, bccrypto.RSA1024)
	assert.NoError(t, err)

	signer := bcPriv.ToStandardKey().(crypto.Signer)

	sig, err := signer.Sign(rand.Reader, plain, nil)
	assert.NoError(t, err)
	assert.NotNil(t, sig)

	ok, err := bcPriv.PublicKey().VerifyWithOpts(plain, sig, &bccrypto.SignOpts{Hash: bccrypto.HASH_TYPE_SHA256})
	assert.NoError(t, err)
	assert.True(t, ok)
}

func TestP11Handle_InternalRSAKey(t *testing.T) {
	priv, err := p11.findPrivateKeyByLabel(internalRSAKeyLabel)
	assert.NoError(t, err)
	assert.NotNil(t, priv)

	sig, err := p11.Sign(*priv, pkcs11.NewMechanism(pkcs11.CKM_SHA256_RSA_PKCS, nil), plain)
	assert.NoError(t, err)
	assert.NotNil(t, sig)

	pub, err := p11.findPublicKeyByLabel(internalRSAKeyLabel)
	assert.NoError(t, err)
	assert.NotNil(t, pub)

	err = p11.Verify(*pub, pkcs11.NewMechanism(pkcs11.CKM_SHA256_RSA_PKCS, nil), plain, sig)
	assert.NoError(t, err)
}

func TestP11Handle_ExportRSAPublicKey(t *testing.T) {
	priv, err := p11.findPrivateKeyByLabel(internalRSAKeyLabel)
	assert.NoError(t, err)
	assert.NotNil(t, priv)

	sig, err := p11.Sign(*priv, pkcs11.NewMechanism(pkcs11.CKM_SHA256_RSA_PKCS, nil), plain)
	assert.NoError(t, err)
	assert.NotNil(t, sig)

	pub, err := p11.ExportRSAPublicKey(internalRSAKeyLabel)
	assert.NoError(t, err)

	digest := sha256.Sum256(plain)
	err = rsa.VerifyPKCS1v15(pub, crypto.SHA256, digest[:], sig)
	assert.NoError(t, err)
}
