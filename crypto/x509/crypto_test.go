/*
Copyright (C) BABEC. All rights reserved.
Copyright (C) THL A29 Limited, a Tencent company. All rights reserved.

SPDX-License-Identifier: Apache-2.0
*/

package x509

import (
	"fmt"
	"github.com/xhx/gm-pkg/crypto"
	"github.com/xhx/gm-pkg/crypto/asym"
	"testing"

	"github.com/stretchr/testify/require"
	//"github.com/xhx/gm-pkg/crypto/asym"
)

const (
	c            = "CN"
	l            = "Beijing"
	p            = "Beijing"
	ou           = "chainmaker.org-OU"
	o            = "chainmaker.org-O"
	cn           = "jasonruan"
	expireYear   = 8
	testFilePath = "./testdata"
)

var (
	sans = []string{"127.0.0.1", "localhost", "chainmaker.org", "8.8.8.8"}
)


func TestCreatePrivKey(t *testing.T) {
	var err error


	key, err := asym.GenerateKeyPair(crypto.SM2)
	keys :=key.(crypto.Signer)
	require.NoError(t, err, "failed to create expired certificate")
	fmt.Println(keys)

}

