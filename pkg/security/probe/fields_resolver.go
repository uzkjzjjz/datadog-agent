//go:build linux
// +build linux

// Unless explicitly stated otherwise all files in this repository are licensed
// under the Apache License Version 2.0.
// This product includes software developed at Datadog (https://www.datadoghq.com/).
// Copyright 2022-present Datadog, Inc.
// Code generated - DO NOT EDIT.
package probe

import (
	"github.com/DataDog/datadog-agent/pkg/security/secl/model"
)

// ResolveFields resolves all the fields associate to the event type. Context fields are automatically resolved.
func ResolveFields(ctx *ProbeContext, ev *model.Event) {
	// resolve context fields that are not related to any event type
	_ = ResolveContainerID(ctx, ev, &ev.ContainerContext)
	_ = ResolveContainerTags(ctx, ev, &ev.ContainerContext)
	_ = ResolveNetworkDeviceIfName(ctx, ev, &ev.NetworkContext.Device)
	_ = ResolveProcessArgs(ctx, ev, &ev.ProcessContext.Process)
	_ = ResolveProcessArgsTruncated(ctx, ev, &ev.ProcessContext.Process)
	_ = ResolveProcessArgv(ctx, ev, &ev.ProcessContext.Process)
	_ = ResolveProcessArgv0(ctx, ev, &ev.ProcessContext.Process)
	_ = ResolveProcessCreatedAt(ctx, ev, &ev.ProcessContext.Process)
	_ = ResolveProcessEnvp(ctx, ev, &ev.ProcessContext.Process)
	_ = ResolveProcessEnvs(ctx, ev, &ev.ProcessContext.Process)
	_ = ResolveProcessEnvsTruncated(ctx, ev, &ev.ProcessContext.Process)
	_ = ResolveFileFilesystem(ctx, ev, &ev.ProcessContext.Process.FileEvent)
	_ = ResolveFileFieldsGroup(ctx, ev, &ev.ProcessContext.Process.FileEvent.FileFields)
	_ = ResolveFileFieldsInUpperLayer(ctx, ev, &ev.ProcessContext.Process.FileEvent.FileFields)
	_ = ResolveFileBasename(ctx, ev, &ev.ProcessContext.Process.FileEvent)
	_ = ResolveFilePath(ctx, ev, &ev.ProcessContext.Process.FileEvent)
	_ = ResolveFileFieldsUser(ctx, ev, &ev.ProcessContext.Process.FileEvent.FileFields)
	// resolve event specific fields
	switch ev.GetEventType().String() {
	case "bind":
	case "bpf":
		_ = ResolveHelpers(ctx, ev, &ev.BPF.Program)
	case "capset":
	case "chmod":
		_ = ResolveFileFieldsUser(ctx, ev, &ev.Chmod.File.FileFields)
		_ = ResolveFileFieldsGroup(ctx, ev, &ev.Chmod.File.FileFields)
		_ = ResolveFileFieldsInUpperLayer(ctx, ev, &ev.Chmod.File.FileFields)
		_ = ResolveFilePath(ctx, ev, &ev.Chmod.File)
		_ = ResolveFileBasename(ctx, ev, &ev.Chmod.File)
		_ = ResolveFileFilesystem(ctx, ev, &ev.Chmod.File)
	case "chown":
		_ = ResolveFileFieldsUser(ctx, ev, &ev.Chown.File.FileFields)
		_ = ResolveFileFieldsGroup(ctx, ev, &ev.Chown.File.FileFields)
		_ = ResolveFileFieldsInUpperLayer(ctx, ev, &ev.Chown.File.FileFields)
		_ = ResolveFilePath(ctx, ev, &ev.Chown.File)
		_ = ResolveFileBasename(ctx, ev, &ev.Chown.File)
		_ = ResolveFileFilesystem(ctx, ev, &ev.Chown.File)
		_ = ResolveChownUID(ctx, ev, &ev.Chown)
		_ = ResolveChownGID(ctx, ev, &ev.Chown)
	case "dns":
	case "exec":
		_ = ResolveFileFieldsUser(ctx, ev, &ev.Exec.Process.FileEvent.FileFields)
		_ = ResolveFileFieldsGroup(ctx, ev, &ev.Exec.Process.FileEvent.FileFields)
		_ = ResolveFileFieldsInUpperLayer(ctx, ev, &ev.Exec.Process.FileEvent.FileFields)
		_ = ResolveFilePath(ctx, ev, &ev.Exec.Process.FileEvent)
		_ = ResolveFileBasename(ctx, ev, &ev.Exec.Process.FileEvent)
		_ = ResolveFileFilesystem(ctx, ev, &ev.Exec.Process.FileEvent)
		_ = ResolveProcessCreatedAt(ctx, ev, ev.Exec.Process)
		_ = ResolveProcessArgv0(ctx, ev, ev.Exec.Process)
		_ = ResolveProcessArgs(ctx, ev, ev.Exec.Process)
		_ = ResolveProcessArgv(ctx, ev, ev.Exec.Process)
		_ = ResolveProcessArgsTruncated(ctx, ev, ev.Exec.Process)
		_ = ResolveProcessEnvs(ctx, ev, ev.Exec.Process)
		_ = ResolveProcessEnvp(ctx, ev, ev.Exec.Process)
		_ = ResolveProcessEnvsTruncated(ctx, ev, ev.Exec.Process)
	case "exit":
		_ = ResolveFileFieldsUser(ctx, ev, &ev.Exit.Process.FileEvent.FileFields)
		_ = ResolveFileFieldsGroup(ctx, ev, &ev.Exit.Process.FileEvent.FileFields)
		_ = ResolveFileFieldsInUpperLayer(ctx, ev, &ev.Exit.Process.FileEvent.FileFields)
		_ = ResolveFilePath(ctx, ev, &ev.Exit.Process.FileEvent)
		_ = ResolveFileBasename(ctx, ev, &ev.Exit.Process.FileEvent)
		_ = ResolveFileFilesystem(ctx, ev, &ev.Exit.Process.FileEvent)
		_ = ResolveProcessCreatedAt(ctx, ev, ev.Exit.Process)
		_ = ResolveProcessArgv0(ctx, ev, ev.Exit.Process)
		_ = ResolveProcessArgs(ctx, ev, ev.Exit.Process)
		_ = ResolveProcessArgv(ctx, ev, ev.Exit.Process)
		_ = ResolveProcessArgsTruncated(ctx, ev, ev.Exit.Process)
		_ = ResolveProcessEnvs(ctx, ev, ev.Exit.Process)
		_ = ResolveProcessEnvp(ctx, ev, ev.Exit.Process)
		_ = ResolveProcessEnvsTruncated(ctx, ev, ev.Exit.Process)
	case "link":
		_ = ResolveFileFieldsUser(ctx, ev, &ev.Link.Source.FileFields)
		_ = ResolveFileFieldsGroup(ctx, ev, &ev.Link.Source.FileFields)
		_ = ResolveFileFieldsInUpperLayer(ctx, ev, &ev.Link.Source.FileFields)
		_ = ResolveFilePath(ctx, ev, &ev.Link.Source)
		_ = ResolveFileBasename(ctx, ev, &ev.Link.Source)
		_ = ResolveFileFilesystem(ctx, ev, &ev.Link.Source)
		_ = ResolveFileFieldsUser(ctx, ev, &ev.Link.Target.FileFields)
		_ = ResolveFileFieldsGroup(ctx, ev, &ev.Link.Target.FileFields)
		_ = ResolveFileFieldsInUpperLayer(ctx, ev, &ev.Link.Target.FileFields)
		_ = ResolveFilePath(ctx, ev, &ev.Link.Target)
		_ = ResolveFileBasename(ctx, ev, &ev.Link.Target)
		_ = ResolveFileFilesystem(ctx, ev, &ev.Link.Target)
	case "load_module":
		_ = ResolveFileFieldsUser(ctx, ev, &ev.LoadModule.File.FileFields)
		_ = ResolveFileFieldsGroup(ctx, ev, &ev.LoadModule.File.FileFields)
		_ = ResolveFileFieldsInUpperLayer(ctx, ev, &ev.LoadModule.File.FileFields)
		_ = ResolveFilePath(ctx, ev, &ev.LoadModule.File)
		_ = ResolveFileBasename(ctx, ev, &ev.LoadModule.File)
		_ = ResolveFileFilesystem(ctx, ev, &ev.LoadModule.File)
	case "mkdir":
		_ = ResolveFileFieldsUser(ctx, ev, &ev.Mkdir.File.FileFields)
		_ = ResolveFileFieldsGroup(ctx, ev, &ev.Mkdir.File.FileFields)
		_ = ResolveFileFieldsInUpperLayer(ctx, ev, &ev.Mkdir.File.FileFields)
		_ = ResolveFilePath(ctx, ev, &ev.Mkdir.File)
		_ = ResolveFileBasename(ctx, ev, &ev.Mkdir.File)
		_ = ResolveFileFilesystem(ctx, ev, &ev.Mkdir.File)
	case "mmap":
		_ = ResolveFileFieldsUser(ctx, ev, &ev.MMap.File.FileFields)
		_ = ResolveFileFieldsGroup(ctx, ev, &ev.MMap.File.FileFields)
		_ = ResolveFileFieldsInUpperLayer(ctx, ev, &ev.MMap.File.FileFields)
		_ = ResolveFilePath(ctx, ev, &ev.MMap.File)
		_ = ResolveFileBasename(ctx, ev, &ev.MMap.File)
		_ = ResolveFileFilesystem(ctx, ev, &ev.MMap.File)
	case "mprotect":
	case "open":
		_ = ResolveFileFieldsUser(ctx, ev, &ev.Open.File.FileFields)
		_ = ResolveFileFieldsGroup(ctx, ev, &ev.Open.File.FileFields)
		_ = ResolveFileFieldsInUpperLayer(ctx, ev, &ev.Open.File.FileFields)
		_ = ResolveFilePath(ctx, ev, &ev.Open.File)
		_ = ResolveFileBasename(ctx, ev, &ev.Open.File)
		_ = ResolveFileFilesystem(ctx, ev, &ev.Open.File)
	case "ptrace":
		_ = ResolveFileFieldsUser(ctx, ev, &ev.PTrace.Tracee.Process.FileEvent.FileFields)
		_ = ResolveFileFieldsGroup(ctx, ev, &ev.PTrace.Tracee.Process.FileEvent.FileFields)
		_ = ResolveFileFieldsInUpperLayer(ctx, ev, &ev.PTrace.Tracee.Process.FileEvent.FileFields)
		_ = ResolveFilePath(ctx, ev, &ev.PTrace.Tracee.Process.FileEvent)
		_ = ResolveFileBasename(ctx, ev, &ev.PTrace.Tracee.Process.FileEvent)
		_ = ResolveFileFilesystem(ctx, ev, &ev.PTrace.Tracee.Process.FileEvent)
		_ = ResolveProcessCreatedAt(ctx, ev, &ev.PTrace.Tracee.Process)
		_ = ResolveProcessArgv0(ctx, ev, &ev.PTrace.Tracee.Process)
		_ = ResolveProcessArgs(ctx, ev, &ev.PTrace.Tracee.Process)
		_ = ResolveProcessArgv(ctx, ev, &ev.PTrace.Tracee.Process)
		_ = ResolveProcessArgsTruncated(ctx, ev, &ev.PTrace.Tracee.Process)
		_ = ResolveProcessEnvs(ctx, ev, &ev.PTrace.Tracee.Process)
		_ = ResolveProcessEnvp(ctx, ev, &ev.PTrace.Tracee.Process)
		_ = ResolveProcessEnvsTruncated(ctx, ev, &ev.PTrace.Tracee.Process)
	case "removexattr":
		_ = ResolveFileFieldsUser(ctx, ev, &ev.RemoveXAttr.File.FileFields)
		_ = ResolveFileFieldsGroup(ctx, ev, &ev.RemoveXAttr.File.FileFields)
		_ = ResolveFileFieldsInUpperLayer(ctx, ev, &ev.RemoveXAttr.File.FileFields)
		_ = ResolveFilePath(ctx, ev, &ev.RemoveXAttr.File)
		_ = ResolveFileBasename(ctx, ev, &ev.RemoveXAttr.File)
		_ = ResolveFileFilesystem(ctx, ev, &ev.RemoveXAttr.File)
		_ = ResolveXAttrNamespace(ctx, ev, &ev.RemoveXAttr)
		_ = ResolveXAttrName(ctx, ev, &ev.RemoveXAttr)
	case "rename":
		_ = ResolveFileFieldsUser(ctx, ev, &ev.Rename.Old.FileFields)
		_ = ResolveFileFieldsGroup(ctx, ev, &ev.Rename.Old.FileFields)
		_ = ResolveFileFieldsInUpperLayer(ctx, ev, &ev.Rename.Old.FileFields)
		_ = ResolveFilePath(ctx, ev, &ev.Rename.Old)
		_ = ResolveFileBasename(ctx, ev, &ev.Rename.Old)
		_ = ResolveFileFilesystem(ctx, ev, &ev.Rename.Old)
		_ = ResolveFileFieldsUser(ctx, ev, &ev.Rename.New.FileFields)
		_ = ResolveFileFieldsGroup(ctx, ev, &ev.Rename.New.FileFields)
		_ = ResolveFileFieldsInUpperLayer(ctx, ev, &ev.Rename.New.FileFields)
		_ = ResolveFilePath(ctx, ev, &ev.Rename.New)
		_ = ResolveFileBasename(ctx, ev, &ev.Rename.New)
		_ = ResolveFileFilesystem(ctx, ev, &ev.Rename.New)
	case "rmdir":
		_ = ResolveFileFieldsUser(ctx, ev, &ev.Rmdir.File.FileFields)
		_ = ResolveFileFieldsGroup(ctx, ev, &ev.Rmdir.File.FileFields)
		_ = ResolveFileFieldsInUpperLayer(ctx, ev, &ev.Rmdir.File.FileFields)
		_ = ResolveFilePath(ctx, ev, &ev.Rmdir.File)
		_ = ResolveFileBasename(ctx, ev, &ev.Rmdir.File)
		_ = ResolveFileFilesystem(ctx, ev, &ev.Rmdir.File)
	case "selinux":
		_ = ResolveSELinuxBoolName(ctx, ev, &ev.SELinux)
	case "setgid":
		_ = ResolveSetgidGroup(ctx, ev, &ev.SetGID)
		_ = ResolveSetgidEGroup(ctx, ev, &ev.SetGID)
		_ = ResolveSetgidFSGroup(ctx, ev, &ev.SetGID)
	case "setuid":
		_ = ResolveSetuidUser(ctx, ev, &ev.SetUID)
		_ = ResolveSetuidEUser(ctx, ev, &ev.SetUID)
		_ = ResolveSetuidFSUser(ctx, ev, &ev.SetUID)
	case "setxattr":
		_ = ResolveFileFieldsUser(ctx, ev, &ev.SetXAttr.File.FileFields)
		_ = ResolveFileFieldsGroup(ctx, ev, &ev.SetXAttr.File.FileFields)
		_ = ResolveFileFieldsInUpperLayer(ctx, ev, &ev.SetXAttr.File.FileFields)
		_ = ResolveFilePath(ctx, ev, &ev.SetXAttr.File)
		_ = ResolveFileBasename(ctx, ev, &ev.SetXAttr.File)
		_ = ResolveFileFilesystem(ctx, ev, &ev.SetXAttr.File)
		_ = ResolveXAttrNamespace(ctx, ev, &ev.SetXAttr)
		_ = ResolveXAttrName(ctx, ev, &ev.SetXAttr)
	case "signal":
		_ = ResolveFileFieldsUser(ctx, ev, &ev.Signal.Target.Process.FileEvent.FileFields)
		_ = ResolveFileFieldsGroup(ctx, ev, &ev.Signal.Target.Process.FileEvent.FileFields)
		_ = ResolveFileFieldsInUpperLayer(ctx, ev, &ev.Signal.Target.Process.FileEvent.FileFields)
		_ = ResolveFilePath(ctx, ev, &ev.Signal.Target.Process.FileEvent)
		_ = ResolveFileBasename(ctx, ev, &ev.Signal.Target.Process.FileEvent)
		_ = ResolveFileFilesystem(ctx, ev, &ev.Signal.Target.Process.FileEvent)
		_ = ResolveProcessCreatedAt(ctx, ev, &ev.Signal.Target.Process)
		_ = ResolveProcessArgv0(ctx, ev, &ev.Signal.Target.Process)
		_ = ResolveProcessArgs(ctx, ev, &ev.Signal.Target.Process)
		_ = ResolveProcessArgv(ctx, ev, &ev.Signal.Target.Process)
		_ = ResolveProcessArgsTruncated(ctx, ev, &ev.Signal.Target.Process)
		_ = ResolveProcessEnvs(ctx, ev, &ev.Signal.Target.Process)
		_ = ResolveProcessEnvp(ctx, ev, &ev.Signal.Target.Process)
		_ = ResolveProcessEnvsTruncated(ctx, ev, &ev.Signal.Target.Process)
	case "splice":
		_ = ResolveFileFieldsUser(ctx, ev, &ev.Splice.File.FileFields)
		_ = ResolveFileFieldsGroup(ctx, ev, &ev.Splice.File.FileFields)
		_ = ResolveFileFieldsInUpperLayer(ctx, ev, &ev.Splice.File.FileFields)
		_ = ResolveFilePath(ctx, ev, &ev.Splice.File)
		_ = ResolveFileBasename(ctx, ev, &ev.Splice.File)
		_ = ResolveFileFilesystem(ctx, ev, &ev.Splice.File)
	case "unlink":
		_ = ResolveFileFieldsUser(ctx, ev, &ev.Unlink.File.FileFields)
		_ = ResolveFileFieldsGroup(ctx, ev, &ev.Unlink.File.FileFields)
		_ = ResolveFileFieldsInUpperLayer(ctx, ev, &ev.Unlink.File.FileFields)
		_ = ResolveFilePath(ctx, ev, &ev.Unlink.File)
		_ = ResolveFileBasename(ctx, ev, &ev.Unlink.File)
		_ = ResolveFileFilesystem(ctx, ev, &ev.Unlink.File)
	case "unload_module":
	case "utimes":
		_ = ResolveFileFieldsUser(ctx, ev, &ev.Utimes.File.FileFields)
		_ = ResolveFileFieldsGroup(ctx, ev, &ev.Utimes.File.FileFields)
		_ = ResolveFileFieldsInUpperLayer(ctx, ev, &ev.Utimes.File.FileFields)
		_ = ResolveFilePath(ctx, ev, &ev.Utimes.File)
		_ = ResolveFileBasename(ctx, ev, &ev.Utimes.File)
		_ = ResolveFileFilesystem(ctx, ev, &ev.Utimes.File)
	}
}
