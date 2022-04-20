// Unless explicitly stated otherwise all files in this repository are licensed
// under the Apache License Version 2.0.
// This product includes software developed at Datadog (https://www.datadoghq.com/).
// Copyright 2016-present Datadog, Inc.

//go:build !ebpf_bindata
// +build !ebpf_bindata

package bytecode

import (
	"os"
	"path"

	"github.com/pkg/errors"
)

// GetReader returns a new AssetReader for the specified file asset
func GetReader(dir, name string) (AssetReader, error) {
	assetPath := path.Join(dir, path.Base(name))
	err := VerifyAssetIsRootWriteable(assetPath)
	if err != nil {
		return nil, err
	}

	asset, err := os.Open(assetPath)
	if err != nil {
		return nil, errors.Wrap(err, "could not find asset")
	}

	return asset, nil
}
