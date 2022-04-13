package cert

import (
	"fmt"
	"github.com/stretchr/testify/require"
	"github.com/xhx/gm-pkg/crypto"
	"github.com/xhx/gm-pkg/crypto/x509"
	"path/filepath"
	"testing"
)

func TestCertTrans(t *testing.T) {
	testFileName := "test.crt"
	cfg := &CACertificateConfig{}

	key, err := CreatePrivKey(crypto.SM2, "", "", true)

	cfg = &CACertificateConfig{
		PrivKey:      key,
		HashType:     crypto.HASH_TYPE_SM3,
		CertPath:     testFilePath,
		CertFileName: testFileName,
	}
	err = CreateCACertificate(cfg)
	require.NoError(t, err)

	cert, err := ParseCertificate(filepath.Join(testFilePath, testFileName))
	//require.Equal(t, int(cert.PublicKeyAlgorithm), 3)
	//require.Equal(t, int(cert.SignatureAlgorithm), 10)

	fmt.Printf(" %X\n ",cert.Raw)
	bcx509Cert,err := x509.X509CertToChainMakerCert(cert)
	fmt.Printf(" %X\n ",bcx509Cert.Raw)
	x509Cert,err := x509.ChainMakerCertToX509Cert(bcx509Cert)
	fmt.Printf(" %X\n ",x509Cert.Raw)


	require.Equal(t, cert.Raw, x509Cert.Raw)

	fmt.Printf(" %+v\n ",cert.Equal(x509Cert))


}
