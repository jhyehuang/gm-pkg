/*
Copyright (C) BABEC. All rights reserved.
Copyright (C) THL A29 Limited, a Tencent company. All rights reserved.

SPDX-License-Identifier: Apache-2.0
*/
package x509

import (
	"encoding/pem"
	"fmt"
	"github.com/xhx/gm-pkg/crypto/asym"
)

func GetOUFromPEM(certPEM []byte) ([]string, error) {
	pemBlock, _ := pem.Decode(certPEM)
	if pemBlock == nil {
		return nil, fmt.Errorf("fail to parse certificate")
	}
	cert, err := ParseCertificate(pemBlock.Bytes)
	if err != nil {
		return nil, fmt.Errorf("fail to parse certificate: [%v]", err)
	}
	return cert.Subject.OrganizationalUnit, nil
}

func ParsePrivateKeyPEM(rawKey []byte) (key interface{}, err error) {
	block, _ := pem.Decode(rawKey)
	if block == nil {
		return nil, fmt.Errorf("bytes are not PEM encoded")
	}

	//key, err := bcx509.ParsePKCS8PrivateKey(block.Bytes)
	priv, err :=asym.PrivateKeyFromPEM( block.Bytes,nil)
	if err != nil {
		return nil, fmt.Errorf( "pem bytes are not PKCS8 encoded ")
	}


	return &priv, nil
}