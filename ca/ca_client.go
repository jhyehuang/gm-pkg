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

	cmtls "github.com/xhx/gm-pkg/crypto/tls"
	cmcred "github.com/xhx/gm-pkg/crypto/tls/credentials"
	cmx509 "github.com/xhx/gm-pkg/crypto/x509"
	"github.com/xhx/gm-pkg/log"

	"google.golang.org/grpc/credentials"
)

var (
	ErrTrustCrtsDirEmpty = errors.New("trust certs dir is empty")
)

type CAClient struct {
	ServerName string
	CaPaths    []string
	CaCerts    []string
	CertFile   string
	KeyFile    string
	CertBytes  []byte
	KeyBytes   []byte
	Logger     log.LoggerInterface
}

func (c *CAClient) GetCredentialsByCA() (*credentials.TransportCredentials, error) {
	var (
		cert   tls.Certificate
		gmCert cmtls.Certificate
		err    error
	)

	if c.CertBytes != nil && c.KeyBytes != nil {
		cert, err = tls.X509KeyPair(c.CertBytes, c.KeyBytes)
	} else {
		cert, err = tls.LoadX509KeyPair(c.CertFile, c.KeyFile)
	}
	if err == nil {
		return c.getCredentialsByCA(&cert)
	}

	if c.CertBytes != nil && c.KeyBytes != nil {
		gmCert, err = cmtls.X509KeyPair(c.CertBytes, c.KeyBytes)
	} else {
		gmCert, err = cmtls.LoadX509KeyPair(c.CertFile, c.KeyFile)
	}
	if err == nil {
		return c.getGMCredentialsByCA(&gmCert)
	}

	return nil, fmt.Errorf("load X509 key pair failed, %s", err.Error())
}

// nolint: gosec
func (c *CAClient) getCredentialsByCA(cert *tls.Certificate) (*credentials.TransportCredentials, error) {
	certPool := x509.NewCertPool()
	if len(c.CaCerts) != 0 {
		c.appendCertsToCertPool(certPool)
	} else {
		if err := c.addTrustCertsToCertPool(certPool); err != nil {
			return nil, err
		}
	}

	clientTLS := credentials.NewTLS(&tls.Config{
		Certificates:       []tls.Certificate{*cert},
		ServerName:         c.ServerName,
		RootCAs:            certPool,
		InsecureSkipVerify: false,
	})

	return &clientTLS, nil
}

func (c *CAClient) appendCertsToCertPool(certPool *x509.CertPool) {
	for _, caCert := range c.CaCerts {
		if caCert != "" {
			certPool.AppendCertsFromPEM([]byte(caCert))
		}
	}
}

func (c *CAClient) addTrustCertsToCertPool(certPool *x509.CertPool) error {
	certs, err := loadCerts(c.CaPaths)
	if err != nil {
		errMsg := fmt.Sprintf("load trust certs failed, %s", err.Error())
		return errors.New(errMsg)
	}

	if len(certs) == 0 {
		return ErrTrustCrtsDirEmpty
	}

	for _, cert := range certs {
		err := addTrust(certPool, cert)
		if err != nil {
			c.Logger.Warnf("ignore invalid cert [%s], %s", cert, err.Error())
			continue
		}
	}
	return nil
}

func (c *CAClient) getGMCredentialsByCA(cert *cmtls.Certificate) (*credentials.TransportCredentials, error) {
	certPool := cmx509.NewCertPool()
	if len(c.CaCerts) != 0 {
		c.appendCertsToSM2CertPool(certPool)
	} else {
		if err := c.addTrustCertsToSM2CertPool(certPool); err != nil {
			return nil, err
		}
	}

	clientTLS := cmcred.NewTLS(&cmtls.Config{
		Certificates:       []cmtls.Certificate{*cert},
		ServerName:         c.ServerName,
		RootCAs:            certPool,
		InsecureSkipVerify: false,
	})

	return &clientTLS, nil
}

func (c *CAClient) appendCertsToSM2CertPool(certPool *cmx509.CertPool) {
	for _, caCert := range c.CaCerts {
		if caCert != "" {
			certPool.AppendCertsFromPEM([]byte(caCert))
		}
	}
}

func (c *CAClient) addTrustCertsToSM2CertPool(certPool *cmx509.CertPool) error {
	certs, err := loadCerts(c.CaPaths)
	if err != nil {
		errMsg := fmt.Sprintf("load trust certs failed, %s", err.Error())
		return errors.New(errMsg)
	}

	if len(certs) == 0 {
		return ErrTrustCrtsDirEmpty
	}

	for _, cert := range certs {
		err := addGMTrust(certPool, cert)
		if err != nil {
			c.Logger.Warnf("ignore invalid cert [%s], %s", cert, err.Error())
			continue
		}
	}
	return nil
}
