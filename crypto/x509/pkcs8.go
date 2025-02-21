// Copyright 2011 The Go Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package x509

import (
	"crypto/ecdsa"
	"crypto/rsa"
	"crypto/x509/pkix"
	"encoding/asn1"
	"errors"
	"fmt"

	"github.com/tjfoc/gmsm/sm2"
	tjx509 "github.com/tjfoc/gmsm/x509"
)

// pkcs8 reflects an ASN.1, PKCS#8 PrivateKey. See
// ftp://ftp.rsasecurity.com/pub/pkcs/pkcs-8/pkcs-8v1_2.asn
// and RFC 5208.
type pkcs8 struct {
	Version    int
	Algo       pkix.AlgorithmIdentifier
	PrivateKey []byte
	// optional attributes omitted.
}

// ParsePKCS8PrivateKey parses an unencrypted, PKCS#8 private key.
// See RFC 5208.
func ParsePKCS8PrivateKey(der []byte) (key interface{}, err error) {
	var privKey pkcs8
	if _, err := asn1.Unmarshal(der, &privKey); err != nil {
		return nil, err
	}
	switch {
	case privKey.Algo.Algorithm.Equal(oidPublicKeyRSA):
		return parsePKCS8PrivateKeyRSA(&privKey)
	case privKey.Algo.Algorithm.Equal(oidPublicKeyECDSA):
		return parsePKCS8PrivateKeyECDSA(&privKey)
	case privKey.Algo.Algorithm.Equal(oidPublicKeySM2):
		return parsePKCS8PrivateKeySM2(&privKey)
	default:
		return nil, fmt.Errorf(
			"x509: PKCS#8 wrapping contained private key with unknown algorithm: %v",
			privKey.Algo.Algorithm,
		)
	}
}

func parsePKCS8PrivateKeyRSA(privKey *pkcs8) (key interface{}, err error) {
	key, err = ParsePKCS1PrivateKey(privKey.PrivateKey)
	if err != nil {
		return nil, errors.New("x509: failed to parse RSA private key embedded in PKCS#8: " + err.Error())
	}
	return key, nil
}

func parsePKCS8PrivateKeyECDSA(privKey *pkcs8) (key interface{}, err error) {
	bytes := privKey.Algo.Parameters.FullBytes
	namedCurveOID := new(asn1.ObjectIdentifier)
	if _, err = asn1.Unmarshal(bytes, namedCurveOID); err != nil {
		namedCurveOID = nil
	}
	if namedCurveOID != nil && namedCurveOID.Equal(oidNamedCurveSm2) {
		key, err = tjx509.ParseSm2PrivateKey(privKey.PrivateKey)
		if err != nil {
			return nil, errors.New("x509: failed to parse sm2 private key embedded in PKCS#8: " + err.Error())
		}
	} else {
		key, err = parseECPrivateKey(namedCurveOID, privKey.PrivateKey)
		if err != nil {
			return nil, errors.New("x509: failed to parse EC private key embedded in PKCS#8: " + err.Error())
		}
	}
	return key, nil
}

// nolint: ineffassign
func parsePKCS8PrivateKeySM2(privKey *pkcs8) (key interface{}, err error) {
	bytes := privKey.Algo.Parameters.FullBytes
	namedCurveOID := new(asn1.ObjectIdentifier)
	if _, err = asn1.Unmarshal(bytes, namedCurveOID); err != nil {
		namedCurveOID = nil
	}

	key, err = tjx509.ParseSm2PrivateKey(privKey.PrivateKey)
	if err != nil {
		return nil, errors.New("x509: failed to parse sm2 private key embedded in PKCS#8: " + err.Error())
	}
	return key, nil
}

// MarshalPKCS8PrivateKey converts a private key to PKCS#8 encoded form.
// The following key types are supported: *rsa.PrivateKey, *ecdsa.PrivateKey.
// Unsupported key types result in an error.
//
// See RFC 5208.
func MarshalPKCS8PrivateKey(key interface{}) ([]byte, error) {
	var privKey pkcs8

	switch k := key.(type) {
	case *rsa.PrivateKey:
		privKey.Algo = pkix.AlgorithmIdentifier{
			Algorithm:  oidPublicKeyRSA,
			Parameters: asn1.NullRawValue,
		}
		privKey.PrivateKey = MarshalPKCS1PrivateKey(k)

	case *ecdsa.PrivateKey:
		oid, ok := oidFromNamedCurve(k.Curve)
		if !ok {
			return nil, errors.New("x509: unknown curve while marshalling to PKCS#8")
		}

		oidBytes, err := asn1.Marshal(oid)
		if err != nil {
			return nil, errors.New("x509: failed to marshal curve OID: " + err.Error())
		}

		privKey.Algo = pkix.AlgorithmIdentifier{
			Algorithm: oidPublicKeyECDSA,
			Parameters: asn1.RawValue{
				FullBytes: oidBytes,
			},
		}

		if privKey.PrivateKey, err = marshalECPrivateKeyWithOID(k, nil); err != nil {
			return nil, errors.New("x509: failed to marshal EC private key while building PKCS#8: " + err.Error())
		}

	case *sm2.PrivateKey:
		oid, ok := oidFromNamedCurve(k.Curve)
		if !ok {
			return nil, errors.New("x509: unknown curve while marshalling to PKCS#8")
		}

		oidBytes, err := asn1.Marshal(oid)
		if err != nil {
			return nil, errors.New("x509: failed to marshal curve OID: " + err.Error())
		}

		privKey.Algo = pkix.AlgorithmIdentifier{
			Algorithm: oidPublicKeyECDSA,
			Parameters: asn1.RawValue{
				FullBytes: oidBytes,
			},
		}

		if privKey.PrivateKey, err = tjx509.MarshalSm2UnecryptedPrivateKey(k); err != nil {
			return nil, errors.New("x509: failed to marshal EC private key while building PKCS#8: " + err.Error())
		}
	case sm2.PrivateKey:
		oid, ok := oidFromNamedCurve(k.Curve)
		if !ok {
			return nil, errors.New("x509: unknown curve while marshalling to PKCS#8")
		}

		oidBytes, err := asn1.Marshal(oid)
		if err != nil {
			return nil, errors.New("x509: failed to marshal curve OID: " + err.Error())
		}

		privKey.Algo = pkix.AlgorithmIdentifier{
			Algorithm: oidPublicKeyECDSA,
			Parameters: asn1.RawValue{
				FullBytes: oidBytes,
			},
		}

		if privKey.PrivateKey, err = tjx509.MarshalSm2UnecryptedPrivateKey(&k); err != nil {
			return nil, errors.New("x509: failed to marshal EC private key while building PKCS#8: " + err.Error())
		}
	default:
		return nil, fmt.Errorf("x509: unknown key type while marshalling PKCS#8: %T", key)
	}

	return asn1.Marshal(privKey)
}
