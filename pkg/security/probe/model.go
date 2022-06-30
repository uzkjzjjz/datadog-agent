// Unless explicitly stated otherwise all files in this repository are licensed
// under the Apache License Version 2.0.
// This product includes software developed at Datadog (https://www.datadoghq.com/).
// Copyright 2016-present Datadog, Inc.

//go:build linux
// +build linux

package probe

import (
	"fmt"
	"path"
	"strings"
	"syscall"
	"time"

	manager "github.com/DataDog/ebpf-manager"
	"github.com/cilium/ebpf/perf"
	"github.com/mailru/easyjson/jwriter"

	"github.com/DataDog/datadog-agent/pkg/security/probe/constantfetch"
	"github.com/DataDog/datadog-agent/pkg/security/secl/compiler/eval"
	"github.com/DataDog/datadog-agent/pkg/security/secl/model"
)

const (
	// ServiceEnvVar environment variable used to report service
	ServiceEnvVar = "DD_SERVICE"
)

var eventZero model.Event

// Model describes the data model for the runtime security agent probe events
type Model struct {
	model.Model
	probe *Probe
}

// ValidateField validates the value of a field
func (m *Model) ValidateField(field eval.Field, fieldValue eval.FieldValue) error {
	if err := m.Model.ValidateField(field, fieldValue); err != nil {
		return err
	}

	switch field {
	case "bpf.map.name":
		if offset, found := m.probe.constantOffsets["bpf_map_name_offset"]; !found || offset == constantfetch.ErrorSentinel {
			return fmt.Errorf("%s is not available on this kernel version", field)
		}

	case "bpf.prog.name":
		if offset, found := m.probe.constantOffsets["bpf_prog_aux_name_offset"]; !found || offset == constantfetch.ErrorSentinel {
			return fmt.Errorf("%s is not available on this kernel version", field)
		}
	}

	return nil
}

// NewEvent returns a new Event
func (m *Model) NewEvent() eval.Event {
	return &model.Event{}
}

// NetDeviceKey is used to uniquely identify a network device
type NetDeviceKey struct {
	IfIndex          uint32
	NetNS            uint32
	NetworkDirection manager.TrafficType
}

// ResolveFilePath resolves the inode to a full path
func ResolveFilePath(ctx *ProbeContext, ev *model.Event, f *model.FileEvent) string {
	if !f.IsPathnameStrResolved && len(f.PathnameStr) == 0 {
		path, err := ctx.Resolvers.resolveFileFieldsPath(&f.FileFields)
		if err != nil {
			switch err.(type) {
			case ErrDentryPathKeyNotFound:
				// this error is the only one we don't care about
			default:
				f.PathResolutionError = err
				ev.PathResolutionError = err
			}
		}
		f.SetPathnameStr(path)
	}
	return f.PathnameStr
}

// ResolveFileBasename resolves the inode to a full path
func ResolveFileBasename(ctx *ProbeContext, ev *model.Event, f *model.FileEvent) string {
	if !f.IsBasenameStrResolved && len(f.BasenameStr) == 0 {
		if f.PathnameStr != "" {
			f.SetBasenameStr(path.Base(f.PathnameStr))
		} else {
			f.SetBasenameStr(ctx.Resolvers.resolveBasename(&f.FileFields))
		}
	}
	return f.BasenameStr
}

// ResolveFileFilesystem resolves the filesystem a file resides in
func ResolveFileFilesystem(ctx *ProbeContext, ev *model.Event, f *model.FileEvent) string {
	return ctx.Resolvers.MountResolver.GetFilesystem(f.FileFields.MountID)
}

// ResolveFileFieldsInUpperLayer resolves whether the file is in an upper layer
func ResolveFileFieldsInUpperLayer(ctx *ProbeContext, ev *model.Event, f *model.FileFields) bool {
	return f.GetInUpperLayer()
}

// ResolveXAttrName returns the string representation of the extended attribute name
func ResolveXAttrName(ctx *ProbeContext, ev *model.Event, e *model.SetXAttrEvent) string {
	if len(e.Name) == 0 {
		e.Name, _ = model.UnmarshalString(e.NameRaw[:], 200)
	}
	return e.Name
}

// ResolveHelpers returns the list of eBPF helpers used by the current program
func ResolveHelpers(ctx *ProbeContext, ev *model.Event, e *model.BPFProgram) []uint32 {
	return e.Helpers
}

// ResolveXAttrNamespace returns the string representation of the extended attribute namespace
func ResolveXAttrNamespace(ctx *ProbeContext, ev *model.Event, e *model.SetXAttrEvent) string {
	if len(e.Namespace) == 0 {
		fragments := strings.Split(ResolveXAttrName(ctx, ev, e), ".")
		if len(fragments) > 0 {
			e.Namespace = fragments[0]
		}
	}
	return e.Namespace
}

// SetMountPoint set the mount point information
func SetMountPoint(ctx *ProbeContext, ev *model.Event, e *model.MountEvent) {
	e.MountPointStr, e.MountPointPathResolutionError = ctx.Resolvers.DentryResolver.Resolve(e.ParentMountID, e.ParentInode, 0, true)
}

// ResolveMountPoint resolves the mountpoint to a full path
func ResolveMountPoint(ctx *ProbeContext, ev *model.Event, e *model.MountEvent) string {
	if len(e.MountPointStr) == 0 {
		SetMountPoint(ctx, ev, e)
	}
	return e.MountPointStr
}

// SetMountRoot set the mount point information
func SetMountRoot(ctx *ProbeContext, ev *model.Event, e *model.MountEvent) {
	e.RootStr, e.RootPathResolutionError = ctx.Resolvers.DentryResolver.Resolve(e.RootMountID, e.RootInode, 0, true)
}

// ResolveMountRoot resolves the mountpoint to a full path
func ResolveMountRoot(ctx *ProbeContext, ev *model.Event, e *model.MountEvent) string {
	if len(e.RootStr) == 0 {
		SetMountRoot(ctx, ev, e)
	}
	return e.RootStr
}

// ResolveContainerID resolves the container ID of the event
func ResolveContainerID(ctx *ProbeContext, ev *model.Event, e *model.ContainerContext) string {
	if len(e.ID) == 0 {
		if entry := ResolveProcessCacheEntry(ctx, ev); entry != nil {
			e.ID = entry.ContainerID
		}
	}
	return e.ID
}

// ResolveContainerTags resolves the container tags of the event
func ResolveContainerTags(ctx *ProbeContext, ev *model.Event, e *model.ContainerContext) []string {
	if len(e.Tags) == 0 && e.ID != "" {
		e.Tags = ctx.Resolvers.TagsResolver.Resolve(e.ID)
	}
	return e.Tags
}

// UnmarshalProcessCacheEntry unmarshal a Process
func UnmarshalProcessCacheEntry(ctx *ProbeContext, ev *model.Event, data []byte) (int, error) {
	entry := ctx.Resolvers.ProcessResolver.NewProcessCacheEntry(ev.PIDContext)

	n, err := entry.Process.UnmarshalBinary(data)
	if err != nil {
		return n, err
	}
	entry.Process.ContainerID = ev.ContainerContext.ID

	ev.ProcessCacheEntry = entry

	return n, nil
}

// ResolveFileFieldsUser resolves the user id of the file to a username
func ResolveFileFieldsUser(ctx *ProbeContext, ev *model.Event, e *model.FileFields) string {
	if len(e.User) == 0 {
		e.User, _ = ctx.Resolvers.UserGroupResolver.ResolveUser(int(e.UID))
	}
	return e.User
}

// ResolveFileFieldsGroup resolves the group id of the file to a group name
func ResolveFileFieldsGroup(ctx *ProbeContext, ev *model.Event, e *model.FileFields) string {
	if len(e.Group) == 0 {
		e.Group, _ = ctx.Resolvers.UserGroupResolver.ResolveGroup(int(e.GID))
	}
	return e.Group
}

// ResolveRights resolves the rights of a file
func ResolveRights(ctx *ProbeContext, ev *model.Event, e *model.FileFields) int {
	return int(e.Mode) & (syscall.S_ISUID | syscall.S_ISGID | syscall.S_ISVTX | syscall.S_IRWXU | syscall.S_IRWXG | syscall.S_IRWXO)
}

// ResolveChownUID resolves the user id of a chown event to a username
func ResolveChownUID(ctx *ProbeContext, ev *model.Event, e *model.ChownEvent) string {
	if len(e.User) == 0 {
		e.User, _ = ctx.Resolvers.UserGroupResolver.ResolveUser(int(e.UID))
	}
	return e.User
}

// ResolveChownGID resolves the group id of a chown event to a group name
func ResolveChownGID(ctx *ProbeContext, ev *model.Event, e *model.ChownEvent) string {
	if len(e.Group) == 0 {
		e.Group, _ = ctx.Resolvers.UserGroupResolver.ResolveGroup(int(e.GID))
	}
	return e.Group
}

// ResolveProcessCreatedAt resolves process creation time
func ResolveProcessCreatedAt(ctx *ProbeContext, ev *model.Event, e *model.Process) uint64 {
	return uint64(e.ExecTime.UnixNano())
}

// ResolveProcessArgv0 resolves the first arg of the event
func ResolveProcessArgv0(ctx *ProbeContext, ev *model.Event, process *model.Process) string {
	arg0, _ := ctx.Resolvers.ProcessResolver.GetProcessArgv0(process)
	return arg0
}

// ResolveProcessArgs resolves the args of the event
func ResolveProcessArgs(ctx *ProbeContext, ev *model.Event, process *model.Process) string {
	return strings.Join(ResolveProcessArgv(ctx, ev, process), " ")
}

// ResolveProcessArgv resolves the args of the event as an array
func ResolveProcessArgv(ctx *ProbeContext, ev *model.Event, process *model.Process) []string {
	argv, _ := ctx.Resolvers.ProcessResolver.GetProcessArgv(process)
	return argv
}

// ResolveProcessEnvp resolves the envp of the event as an array
func ResolveProcessEnvp(ctx *ProbeContext, ev *model.Event, process *model.Process) []string {
	envp, _ := ctx.Resolvers.ProcessResolver.GetProcessEnvp(process)
	return envp
}

// ResolveProcessArgsTruncated returns whether the args are truncated
func ResolveProcessArgsTruncated(ctx *ProbeContext, ev *model.Event, process *model.Process) bool {
	_, truncated := ctx.Resolvers.ProcessResolver.GetProcessArgv(process)
	return truncated
}

// ResolveProcessArgsFlags resolves the arguments flags of the event
func ResolveProcessArgsFlags(ctx *ProbeContext, ev *model.Event, process *model.Process) (flags []string) {
	for _, arg := range ResolveProcessArgv(ctx, ev, process) {
		if len(arg) > 1 && arg[0] == '-' {
			isFlag := true
			name := arg[1:]
			if len(name) >= 1 && name[0] == '-' {
				name = name[1:]
				isFlag = false
			}

			isOption := false
			for _, r := range name {
				isFlag = isFlag && model.IsAlphaNumeric(r)
				isOption = isOption || r == '='
			}

			if len(name) > 0 {
				if isFlag {
					for _, r := range name {
						flags = append(flags, string(r))
					}
				}
				if !isOption && len(name) > 1 {
					flags = append(flags, name)
				}
			}
		}
	}
	return
}

// ResolveProcessArgsOptions resolves the arguments options of the event
func ResolveProcessArgsOptions(ctx *ProbeContext, ev *model.Event, process *model.Process) (options []string) {
	args := ResolveProcessArgv(ctx, ev, process)
	for i := 0; i < len(args); i++ {
		arg := args[i]
		if len(arg) > 1 && arg[0] == '-' {
			name := arg[1:]
			if len(name) >= 1 && name[0] == '-' {
				name = name[1:]
			}
			if len(name) > 0 && model.IsAlphaNumeric(rune(name[0])) {
				if index := strings.IndexRune(name, '='); index == -1 {
					if i < len(args)-1 && (len(args[i+1]) == 0 || args[i+1][0] != '-') {
						options = append(options, name+"="+args[i+1])
						i++
					}
				} else {
					options = append(options, name)
				}
			}
		}
	}
	return
}

// ResolveProcessEnvsTruncated returns whether the envs are truncated
func ResolveProcessEnvsTruncated(ctx *ProbeContext, ev *model.Event, process *model.Process) bool {
	_, truncated := ctx.Resolvers.ProcessResolver.GetProcessEnvs(process)
	return truncated
}

// ResolveProcessEnvs resolves the envs of the event
func ResolveProcessEnvs(ctx *ProbeContext, ev *model.Event, process *model.Process) []string {
	envs, _ := ctx.Resolvers.ProcessResolver.GetProcessEnvs(process)
	return envs
}

// ResolveSetuidUser resolves the user of the Setuid event
func ResolveSetuidUser(ctx *ProbeContext, ev *model.Event, e *model.SetuidEvent) string {
	if len(e.User) == 0 && ev != nil {
		e.User, _ = ctx.Resolvers.UserGroupResolver.ResolveUser(int(e.UID))
	}
	return e.User
}

// ResolveSetuidEUser resolves the effective user of the Setuid event
func ResolveSetuidEUser(ctx *ProbeContext, ev *model.Event, e *model.SetuidEvent) string {
	if len(e.EUser) == 0 && ev != nil {
		e.EUser, _ = ctx.Resolvers.UserGroupResolver.ResolveUser(int(e.EUID))
	}
	return e.EUser
}

// ResolveSetuidFSUser resolves the file-system user of the Setuid event
func ResolveSetuidFSUser(ctx *ProbeContext, ev *model.Event, e *model.SetuidEvent) string {
	if len(e.FSUser) == 0 && ev != nil {
		e.FSUser, _ = ctx.Resolvers.UserGroupResolver.ResolveUser(int(e.FSUID))
	}
	return e.FSUser
}

// ResolveSetgidGroup resolves the group of the Setgid event
func ResolveSetgidGroup(ctx *ProbeContext, ev *model.Event, e *model.SetgidEvent) string {
	if len(e.Group) == 0 && ev != nil {
		e.Group, _ = ctx.Resolvers.UserGroupResolver.ResolveUser(int(e.GID))
	}
	return e.Group
}

// ResolveSetgidEGroup resolves the effective group of the Setgid event
func ResolveSetgidEGroup(ctx *ProbeContext, ev *model.Event, e *model.SetgidEvent) string {
	if len(e.EGroup) == 0 && ev != nil {
		e.EGroup, _ = ctx.Resolvers.UserGroupResolver.ResolveUser(int(e.EGID))
	}
	return e.EGroup
}

// ResolveSetgidFSGroup resolves the file-system group of the Setgid event
func ResolveSetgidFSGroup(ctx *ProbeContext, ev *model.Event, e *model.SetgidEvent) string {
	if len(e.FSGroup) == 0 && ev != nil {
		e.FSGroup, _ = ctx.Resolvers.UserGroupResolver.ResolveUser(int(e.FSGID))
	}
	return e.FSGroup
}

// ResolveSELinuxBoolName resolves the boolean name of the SELinux event
func ResolveSELinuxBoolName(ctx *ProbeContext, ev *model.Event, e *model.SELinuxEvent) string {
	if e.EventKind != model.SELinuxBoolChangeEventKind {
		return ""
	}

	if len(ev.SELinux.BoolName) == 0 {
		ev.SELinux.BoolName = ctx.Resolvers.resolveBasename(&e.File.FileFields)
	}
	return ev.SELinux.BoolName
}

// EventToString returns string representation of the event
func EventToString(ctx *ProbeContext, ev *model.Event) string {
	d, err := MarshalJSONEvent(ctx, ev)
	if err != nil {
		return err.Error()
	}
	return string(d)
}

// MarshalJSON returns the JSON encoding of the event
func MarshalJSONEvent(ctx *ProbeContext, ev *model.Event) ([]byte, error) {
	s := NewEventSerializer(ctx, ev)
	w := &jwriter.Writer{
		Flags: jwriter.NilSliceAsEmpty | jwriter.NilMapAsEmpty,
	}
	s.MarshalEasyJSON(w)
	return w.BuildBytes()
}

// ExtractEventInfo extracts cpu and timestamp from the raw data event
func ExtractEventInfo(record *perf.Record) (uint64, uint64, error) {
	if len(record.RawSample) < 16 {
		return 0, 0, model.ErrNotEnoughData
	}

	return model.ByteOrder.Uint64(record.RawSample[0:8]), model.ByteOrder.Uint64(record.RawSample[8:16]), nil
}

// ResolveEventTimestamp resolves the monolitic kernel event timestamp to an absolute time
func ResolveEventTimestamp(ctx *ProbeContext, ev *model.Event) time.Time {
	if ev.Timestamp.IsZero() {
		ev.Timestamp = ctx.Resolvers.TimeResolver.ResolveMonotonicTimestamp(ev.TimestampRaw)
		if ev.Timestamp.IsZero() {
			ev.Timestamp = time.Now()
		}
	}
	return ev.Timestamp
}

// ResolveProcessCacheEntry queries the ProcessResolver to retrieve the ProcessContext of the event
func ResolveProcessCacheEntry(ctx *ProbeContext, ev *model.Event) *model.ProcessCacheEntry {
	if ev.ProcessCacheEntry == nil {
		ev.ProcessCacheEntry = ctx.Resolvers.ProcessResolver.Resolve(ev.PIDContext.Pid, ev.PIDContext.Tid)
	}

	if ev.ProcessCacheEntry == nil {
		// keep the original PIDContext
		ev.ProcessCacheEntry = model.NewProcessCacheEntry(nil)
		ev.ProcessCacheEntry.PIDContext = ev.PIDContext

		ev.ProcessCacheEntry.FileEvent.SetPathnameStr("")
		ev.ProcessCacheEntry.FileEvent.SetBasenameStr("")
	}

	return ev.ProcessCacheEntry
}

// GetProcessServiceTag returns the service tag based on the process context
func GetProcessServiceTag(ctx *ProbeContext, ev *model.Event) string {
	entry := ResolveProcessCacheEntry(ctx, ev)
	if entry == nil {
		return ""
	}

	// first search in the process context itself
	if entry.EnvsEntry != nil {
		if service := entry.EnvsEntry.Get(ServiceEnvVar); service != "" {
			return service
		}
	}

	inContainer := entry.ContainerID != ""

	// while in container check for each ancestor
	for ancestor := entry.Ancestor; ancestor != nil; ancestor = ancestor.Ancestor {
		if inContainer && ancestor.ContainerID == "" {
			break
		}

		if ancestor.EnvsEntry != nil {
			if service := ancestor.EnvsEntry.Get(ServiceEnvVar); service != "" {
				return service
			}
		}
	}

	return ""
}

// ResolveNetworkDeviceIfName returns the network iterface name from the network context
func ResolveNetworkDeviceIfName(ctx *ProbeContext, ev *model.Event, device *model.NetworkDeviceContext) string {
	// TODO(safchain) restore
	return ""
	/*if len(device.IfName) == 0 && ev.probe != nil {
		key := NetDeviceKey{
			NetNS:            device.NetNS,
			IfIndex:          device.IfIndex,
			NetworkDirection: manager.Egress,
		}

		ev.probe.tcProgramsLock.RLock()
		defer ev.probe.tcProgramsLock.RUnlock()

		tcProbe, ok := ev.probe.tcPrograms[key]
		if !ok {
			key.NetworkDirection = manager.Ingress
			tcProbe = ev.probe.tcPrograms[key]
		}

		if tcProbe != nil {
			device.IfName = tcProbe.IfName
		}
	}

	return device.IfName*/
}
