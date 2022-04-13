/*
Copyright (C) BABEC. All rights reserved.
Copyright (C) THL A29 Limited, a Tencent company. All rights reserved.

SPDX-License-Identifier: Apache-2.0
*/

package ca

import (
	"crypto/tls"
	"crypto/x509"
	"errors"
	"fmt"
	"io/ioutil"
	"net"

	"golang.org/x/net/http2"
)

func GetTLSConfig(certPemPath, certKeyPath string, caPaths []string) (*tls.Config, error) {
	var certKeyPair *tls.Certificate
	cert, err := ioutil.ReadFile(certPemPath)
	if err != nil {
		return nil, fmt.Errorf("read cert file failed, %s", err.Error())
	}

	key, err := ioutil.ReadFile(certKeyPath)
	if err != nil {
		return nil, fmt.Errorf("read cert key failed, %s", err.Error())
	}

	pair, err := tls.X509KeyPair(cert, key)
	if err != nil {
		return nil, fmt.Errorf("TLS KeyPair failed, %s", err.Error())
	}

	certKeyPair = &pair

	if len(caPaths) > 0 {
		caCerts, err := loadCerts(caPaths)
		if err != nil {
			return nil, fmt.Errorf("load trust certs failed, %s", err.Error())
		}

		if len(caCerts) == 0 {
			return nil, errors.New("trust certs dir is empty")
		}

		certPool := x509.NewCertPool()
		for _, caCert := range caCerts {
			err := addTrust(certPool, caCert)
			if err != nil {
				return nil, err
			}
		}

		// nolint: gosec
		return &tls.Config{
			Certificates: []tls.Certificate{*certKeyPair},
			NextProtos:   []string{http2.NextProtoTLS},
			ClientAuth:   tls.RequireAndVerifyClientCert,
			ClientCAs:    certPool,
		}, nil
	}

	// nolint: gosec
	return &tls.Config{
		Certificates: []tls.Certificate{*certKeyPair},
		NextProtos:   []string{http2.NextProtoTLS},
	}, nil
}

func NewTLSListener(inner net.Listener, config *tls.Config) net.Listener {
	return tls.NewListener(inner, config)
}
