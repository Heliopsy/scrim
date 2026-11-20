// SPDX-License-Identifier: AGPL-3.0-only

//go:build !embed_dataplane

package dataplane

// embedded is empty in builds without the embed_dataplane tag; such builds
// need dataplane.path.
var embedded []byte
