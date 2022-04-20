// Unless explicitly stated otherwise all files in this repository are licensed
// under the Apache License Version 2.0.
// This product includes software developed at Datadog (https://www.datadoghq.com/).
// Copyright 2016-present Datadog, Inc.

package bytecode

import (
	"fmt"
	"io"
	"os"
	"syscall"
)

// AssetReader describes the combination of both io.Reader and io.ReaderAt
type AssetReader interface {
	io.Reader
	io.ReaderAt
	io.Closer
}

func VerifyAssetIsRootWriteable(assetPath string) error {
	// Enforce that we only load root-writeable object files
	info, err := os.Stat(assetPath)
	if err != nil {
		return fmt.Errorf("error stat-ing asset file %s: %w", assetPath, err)
	}
	stat, ok := info.Sys().(*syscall.Stat_t)
	if !ok {
		return fmt.Errorf("error getting permissions for output file %s: %w", assetPath, err)
	}
	if stat.Uid != 0 || stat.Gid != 0 || info.Mode().Perm() != 0644 {
		return fmt.Errorf("output file has incorrect permissions: user=%v, group=%v, permissions=%v", stat.Uid, stat.Gid, info.Mode().Perm())
	}
	return nil
}
