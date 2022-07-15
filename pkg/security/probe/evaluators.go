//go:build linux
// +build linux

// Code generated - DO NOT EDIT.
package probe

import (
	"github.com/DataDog/datadog-agent/pkg/security/secl/compiler/eval"
	"github.com/DataDog/datadog-agent/pkg/security/secl/model"
	"net"
	"unsafe"
)

// suppress unused package warning
var (
	_ *unsafe.Pointer
)

func GetEvaluator(field eval.Field, regID eval.RegisterID) (eval.Evaluator, error) {
	switch field {
	case "async":
		return &eval.BoolEvaluator{
			EvalFnc: func(ctx *eval.Context) bool {
				event := GetEvent(ctx)
				return event.Async
			},
			Field:  field,
			Weight: eval.FunctionWeight,
		}, nil
	case "bind.addr.family":
		return &eval.IntEvaluator{
			EvalFnc: func(ctx *eval.Context) int {
				event := GetEvent(ctx)
				return int(event.Bind.AddrFamily)
			},
			Field:  field,
			Weight: eval.FunctionWeight,
		}, nil
	case "bind.addr.ip":
		return &eval.CIDREvaluator{
			EvalFnc: func(ctx *eval.Context) net.IPNet {
				event := GetEvent(ctx)
				return event.Bind.Addr.IPNet
			},
			Field:  field,
			Weight: eval.FunctionWeight,
		}, nil
	case "bind.addr.port":
		return &eval.IntEvaluator{
			EvalFnc: func(ctx *eval.Context) int {
				event := GetEvent(ctx)
				return int(event.Bind.Addr.Port)
			},
			Field:  field,
			Weight: eval.FunctionWeight,
		}, nil
	case "bind.retval":
		return &eval.IntEvaluator{
			EvalFnc: func(ctx *eval.Context) int {
				event := GetEvent(ctx)
				return int(event.Bind.SyscallEvent.Retval)
			},
			Field:  field,
			Weight: eval.FunctionWeight,
		}, nil
	case "bpf.cmd":
		return &eval.IntEvaluator{
			EvalFnc: func(ctx *eval.Context) int {
				event := GetEvent(ctx)
				return int(event.BPF.Cmd)
			},
			Field:  field,
			Weight: eval.FunctionWeight,
		}, nil
	case "bpf.map.name":
		return &eval.StringEvaluator{
			EvalFnc: func(ctx *eval.Context) string {
				event := GetEvent(ctx)
				return event.BPF.Map.Name
			},
			Field:  field,
			Weight: eval.FunctionWeight,
		}, nil
	case "bpf.map.type":
		return &eval.IntEvaluator{
			EvalFnc: func(ctx *eval.Context) int {
				event := GetEvent(ctx)
				return int(event.BPF.Map.Type)
			},
			Field:  field,
			Weight: eval.FunctionWeight,
		}, nil
	case "bpf.prog.attach_type":
		return &eval.IntEvaluator{
			EvalFnc: func(ctx *eval.Context) int {
				event := GetEvent(ctx)
				return int(event.BPF.Program.AttachType)
			},
			Field:  field,
			Weight: eval.FunctionWeight,
		}, nil
	case "bpf.prog.helpers":
		return &eval.IntArrayEvaluator{
			EvalFnc: func(ctx *eval.Context) []int {
				event := GetEvent(ctx)
				result := make([]int, len(event.ResolveHelpers(&event.BPF.Program)))
				for i, v := range event.ResolveHelpers(&event.BPF.Program) {
					result[i] = int(v)
				}
				return result
			},
			Field:  field,
			Weight: eval.HandlerWeight,
		}, nil
	case "bpf.prog.name":
		return &eval.StringEvaluator{
			EvalFnc: func(ctx *eval.Context) string {
				event := GetEvent(ctx)
				return event.BPF.Program.Name
			},
			Field:  field,
			Weight: eval.FunctionWeight,
		}, nil
	case "bpf.prog.tag":
		return &eval.StringEvaluator{
			EvalFnc: func(ctx *eval.Context) string {
				event := GetEvent(ctx)
				return event.BPF.Program.Tag
			},
			Field:  field,
			Weight: eval.FunctionWeight,
		}, nil
	case "bpf.prog.type":
		return &eval.IntEvaluator{
			EvalFnc: func(ctx *eval.Context) int {
				event := GetEvent(ctx)
				return int(event.BPF.Program.Type)
			},
			Field:  field,
			Weight: eval.FunctionWeight,
		}, nil
	case "bpf.retval":
		return &eval.IntEvaluator{
			EvalFnc: func(ctx *eval.Context) int {
				event := GetEvent(ctx)
				return int(event.BPF.SyscallEvent.Retval)
			},
			Field:  field,
			Weight: eval.FunctionWeight,
		}, nil
	case "capset.cap_effective":
		return &eval.IntEvaluator{
			EvalFnc: func(ctx *eval.Context) int {
				event := GetEvent(ctx)
				return int(event.Capset.CapEffective)
			},
			Field:  field,
			Weight: eval.FunctionWeight,
		}, nil
	case "capset.cap_permitted":
		return &eval.IntEvaluator{
			EvalFnc: func(ctx *eval.Context) int {
				event := GetEvent(ctx)
				return int(event.Capset.CapPermitted)
			},
			Field:  field,
			Weight: eval.FunctionWeight,
		}, nil
	case "chmod.file.change_time":
		return &eval.IntEvaluator{
			EvalFnc: func(ctx *eval.Context) int {
				event := GetEvent(ctx)
				return int(event.Chmod.File.FileFields.CTime)
			},
			Field:  field,
			Weight: eval.FunctionWeight,
		}, nil
	case "chmod.file.destination.mode":
		return &eval.IntEvaluator{
			EvalFnc: func(ctx *eval.Context) int {
				event := GetEvent(ctx)
				return int(event.Chmod.Mode)
			},
			Field:  field,
			Weight: eval.FunctionWeight,
		}, nil
	case "chmod.file.destination.rights":
		return &eval.IntEvaluator{
			EvalFnc: func(ctx *eval.Context) int {
				event := GetEvent(ctx)
				return int(event.Chmod.Mode)
			},
			Field:  field,
			Weight: eval.FunctionWeight,
		}, nil
	case "chmod.file.filesystem":
		return &eval.StringEvaluator{
			EvalFnc: func(ctx *eval.Context) string {
				event := GetEvent(ctx)
				return event.ResolveFileFilesystem(&event.Chmod.File)
			},
			Field:  field,
			Weight: eval.HandlerWeight,
		}, nil
	case "chmod.file.gid":
		return &eval.IntEvaluator{
			EvalFnc: func(ctx *eval.Context) int {
				event := GetEvent(ctx)
				return int(event.Chmod.File.FileFields.GID)
			},
			Field:  field,
			Weight: eval.FunctionWeight,
		}, nil
	case "chmod.file.group":
		return &eval.StringEvaluator{
			EvalFnc: func(ctx *eval.Context) string {
				event := GetEvent(ctx)
				return event.ResolveFileFieldsGroup(&event.Chmod.File.FileFields)
			},
			Field:  field,
			Weight: eval.HandlerWeight,
		}, nil
	case "chmod.file.in_upper_layer":
		return &eval.BoolEvaluator{
			EvalFnc: func(ctx *eval.Context) bool {
				event := GetEvent(ctx)
				return event.ResolveFileFieldsInUpperLayer(&event.Chmod.File.FileFields)
			},
			Field:  field,
			Weight: eval.HandlerWeight,
		}, nil
	case "chmod.file.inode":
		return &eval.IntEvaluator{
			EvalFnc: func(ctx *eval.Context) int {
				event := GetEvent(ctx)
				return int(event.Chmod.File.FileFields.Inode)
			},
			Field:  field,
			Weight: eval.FunctionWeight,
		}, nil
	case "chmod.file.mode":
		return &eval.IntEvaluator{
			EvalFnc: func(ctx *eval.Context) int {
				event := GetEvent(ctx)
				return int(event.Chmod.File.FileFields.Mode)
			},
			Field:  field,
			Weight: eval.FunctionWeight,
		}, nil
	case "chmod.file.modification_time":
		return &eval.IntEvaluator{
			EvalFnc: func(ctx *eval.Context) int {
				event := GetEvent(ctx)
				return int(event.Chmod.File.FileFields.MTime)
			},
			Field:  field,
			Weight: eval.FunctionWeight,
		}, nil
	case "chmod.file.mount_id":
		return &eval.IntEvaluator{
			EvalFnc: func(ctx *eval.Context) int {
				event := GetEvent(ctx)
				return int(event.Chmod.File.FileFields.MountID)
			},
			Field:  field,
			Weight: eval.FunctionWeight,
		}, nil
	case "chmod.file.name":
		return &eval.StringEvaluator{
			OpOverrides: model.ProcessSymlinkBasename,
			EvalFnc: func(ctx *eval.Context) string {
				event := GetEvent(ctx)
				return event.ResolveFileBasename(&event.Chmod.File)
			},
			Field:  field,
			Weight: eval.HandlerWeight,
		}, nil
	case "chmod.file.path":
		return &eval.StringEvaluator{
			OpOverrides: model.ProcessSymlinkPathname,
			EvalFnc: func(ctx *eval.Context) string {
				event := GetEvent(ctx)
				return event.ResolveFilePath(&event.Chmod.File)
			},
			Field:  field,
			Weight: eval.HandlerWeight,
		}, nil
	case "chmod.file.rights":
		return &eval.IntEvaluator{
			EvalFnc: func(ctx *eval.Context) int {
				event := GetEvent(ctx)
				return int(event.ResolveRights(&event.Chmod.File.FileFields))
			},
			Field:  field,
			Weight: eval.HandlerWeight,
		}, nil
	case "chmod.file.uid":
		return &eval.IntEvaluator{
			EvalFnc: func(ctx *eval.Context) int {
				event := GetEvent(ctx)
				return int(event.Chmod.File.FileFields.UID)
			},
			Field:  field,
			Weight: eval.FunctionWeight,
		}, nil
	case "chmod.file.user":
		return &eval.StringEvaluator{
			EvalFnc: func(ctx *eval.Context) string {
				event := GetEvent(ctx)
				return event.ResolveFileFieldsUser(&event.Chmod.File.FileFields)
			},
			Field:  field,
			Weight: eval.HandlerWeight,
		}, nil
	case "chmod.retval":
		return &eval.IntEvaluator{
			EvalFnc: func(ctx *eval.Context) int {
				event := GetEvent(ctx)
				return int(event.Chmod.SyscallEvent.Retval)
			},
			Field:  field,
			Weight: eval.FunctionWeight,
		}, nil
	case "chown.file.change_time":
		return &eval.IntEvaluator{
			EvalFnc: func(ctx *eval.Context) int {
				event := GetEvent(ctx)
				return int(event.Chown.File.FileFields.CTime)
			},
			Field:  field,
			Weight: eval.FunctionWeight,
		}, nil
	case "chown.file.destination.gid":
		return &eval.IntEvaluator{
			EvalFnc: func(ctx *eval.Context) int {
				event := GetEvent(ctx)
				return int(event.Chown.GID)
			},
			Field:  field,
			Weight: eval.FunctionWeight,
		}, nil
	case "chown.file.destination.group":
		return &eval.StringEvaluator{
			EvalFnc: func(ctx *eval.Context) string {
				event := GetEvent(ctx)
				return event.ResolveChownGID(&event.Chown)
			},
			Field:  field,
			Weight: eval.HandlerWeight,
		}, nil
	case "chown.file.destination.uid":
		return &eval.IntEvaluator{
			EvalFnc: func(ctx *eval.Context) int {
				event := GetEvent(ctx)
				return int(event.Chown.UID)
			},
			Field:  field,
			Weight: eval.FunctionWeight,
		}, nil
	case "chown.file.destination.user":
		return &eval.StringEvaluator{
			EvalFnc: func(ctx *eval.Context) string {
				event := GetEvent(ctx)
				return event.ResolveChownUID(&event.Chown)
			},
			Field:  field,
			Weight: eval.HandlerWeight,
		}, nil
	case "chown.file.filesystem":
		return &eval.StringEvaluator{
			EvalFnc: func(ctx *eval.Context) string {
				event := GetEvent(ctx)
				return event.ResolveFileFilesystem(&event.Chown.File)
			},
			Field:  field,
			Weight: eval.HandlerWeight,
		}, nil
	case "chown.file.gid":
		return &eval.IntEvaluator{
			EvalFnc: func(ctx *eval.Context) int {
				event := GetEvent(ctx)
				return int(event.Chown.File.FileFields.GID)
			},
			Field:  field,
			Weight: eval.FunctionWeight,
		}, nil
	case "chown.file.group":
		return &eval.StringEvaluator{
			EvalFnc: func(ctx *eval.Context) string {
				event := GetEvent(ctx)
				return event.ResolveFileFieldsGroup(&event.Chown.File.FileFields)
			},
			Field:  field,
			Weight: eval.HandlerWeight,
		}, nil
	case "chown.file.in_upper_layer":
		return &eval.BoolEvaluator{
			EvalFnc: func(ctx *eval.Context) bool {
				event := GetEvent(ctx)
				return event.ResolveFileFieldsInUpperLayer(&event.Chown.File.FileFields)
			},
			Field:  field,
			Weight: eval.HandlerWeight,
		}, nil
	case "chown.file.inode":
		return &eval.IntEvaluator{
			EvalFnc: func(ctx *eval.Context) int {
				event := GetEvent(ctx)
				return int(event.Chown.File.FileFields.Inode)
			},
			Field:  field,
			Weight: eval.FunctionWeight,
		}, nil
	case "chown.file.mode":
		return &eval.IntEvaluator{
			EvalFnc: func(ctx *eval.Context) int {
				event := GetEvent(ctx)
				return int(event.Chown.File.FileFields.Mode)
			},
			Field:  field,
			Weight: eval.FunctionWeight,
		}, nil
	case "chown.file.modification_time":
		return &eval.IntEvaluator{
			EvalFnc: func(ctx *eval.Context) int {
				event := GetEvent(ctx)
				return int(event.Chown.File.FileFields.MTime)
			},
			Field:  field,
			Weight: eval.FunctionWeight,
		}, nil
	case "chown.file.mount_id":
		return &eval.IntEvaluator{
			EvalFnc: func(ctx *eval.Context) int {
				event := GetEvent(ctx)
				return int(event.Chown.File.FileFields.MountID)
			},
			Field:  field,
			Weight: eval.FunctionWeight,
		}, nil
	case "chown.file.name":
		return &eval.StringEvaluator{
			OpOverrides: model.ProcessSymlinkBasename,
			EvalFnc: func(ctx *eval.Context) string {
				event := GetEvent(ctx)
				return event.ResolveFileBasename(&event.Chown.File)
			},
			Field:  field,
			Weight: eval.HandlerWeight,
		}, nil
	case "chown.file.path":
		return &eval.StringEvaluator{
			OpOverrides: model.ProcessSymlinkPathname,
			EvalFnc: func(ctx *eval.Context) string {
				event := GetEvent(ctx)
				return event.ResolveFilePath(&event.Chown.File)
			},
			Field:  field,
			Weight: eval.HandlerWeight,
		}, nil
	case "chown.file.rights":
		return &eval.IntEvaluator{
			EvalFnc: func(ctx *eval.Context) int {
				event := GetEvent(ctx)
				return int(event.ResolveRights(&event.Chown.File.FileFields))
			},
			Field:  field,
			Weight: eval.HandlerWeight,
		}, nil
	case "chown.file.uid":
		return &eval.IntEvaluator{
			EvalFnc: func(ctx *eval.Context) int {
				event := GetEvent(ctx)
				return int(event.Chown.File.FileFields.UID)
			},
			Field:  field,
			Weight: eval.FunctionWeight,
		}, nil
	case "chown.file.user":
		return &eval.StringEvaluator{
			EvalFnc: func(ctx *eval.Context) string {
				event := GetEvent(ctx)
				return event.ResolveFileFieldsUser(&event.Chown.File.FileFields)
			},
			Field:  field,
			Weight: eval.HandlerWeight,
		}, nil
	case "chown.retval":
		return &eval.IntEvaluator{
			EvalFnc: func(ctx *eval.Context) int {
				event := GetEvent(ctx)
				return int(event.Chown.SyscallEvent.Retval)
			},
			Field:  field,
			Weight: eval.FunctionWeight,
		}, nil
	case "container.id":
		return &eval.StringEvaluator{
			EvalFnc: func(ctx *eval.Context) string {
				event := GetEvent(ctx)
				return event.ResolveContainerID(&event.ContainerContext)
			},
			Field:  field,
			Weight: eval.HandlerWeight,
		}, nil
	case "container.tags":
		return &eval.StringArrayEvaluator{
			EvalFnc: func(ctx *eval.Context) []string {
				event := GetEvent(ctx)
				return event.ResolveContainerTags(&event.ContainerContext)
			},
			Field:  field,
			Weight: 9999 * eval.HandlerWeight,
		}, nil
	case "dns.question.class":
		return &eval.IntEvaluator{
			EvalFnc: func(ctx *eval.Context) int {
				event := GetEvent(ctx)
				return int(event.DNS.Class)
			},
			Field:  field,
			Weight: eval.FunctionWeight,
		}, nil
	case "dns.question.count":
		return &eval.IntEvaluator{
			EvalFnc: func(ctx *eval.Context) int {
				event := GetEvent(ctx)
				return int(event.DNS.Count)
			},
			Field:  field,
			Weight: eval.FunctionWeight,
		}, nil
	case "dns.question.name":
		return &eval.StringEvaluator{
			OpOverrides: eval.DNSNameCmp,
			EvalFnc: func(ctx *eval.Context) string {
				event := GetEvent(ctx)
				return event.DNS.Name
			},
			Field:  field,
			Weight: eval.FunctionWeight,
		}, nil
	case "dns.question.size":
		return &eval.IntEvaluator{
			EvalFnc: func(ctx *eval.Context) int {
				event := GetEvent(ctx)
				return int(event.DNS.Size)
			},
			Field:  field,
			Weight: eval.FunctionWeight,
		}, nil
	case "dns.question.type":
		return &eval.IntEvaluator{
			EvalFnc: func(ctx *eval.Context) int {
				event := GetEvent(ctx)
				return int(event.DNS.Type)
			},
			Field:  field,
			Weight: eval.FunctionWeight,
		}, nil
	case "exec.args":
		return &eval.StringEvaluator{
			EvalFnc: func(ctx *eval.Context) string {
				event := GetEvent(ctx)
				return event.ResolveProcessArgs(event.Exec.Process)
			},
			Field:  field,
			Weight: 100 * eval.HandlerWeight,
		}, nil
	case "exec.args_flags":
		return &eval.StringArrayEvaluator{
			EvalFnc: func(ctx *eval.Context) []string {
				event := GetEvent(ctx)
				return event.ResolveProcessArgsFlags(event.Exec.Process)
			},
			Field:  field,
			Weight: eval.HandlerWeight,
		}, nil
	case "exec.args_options":
		return &eval.StringArrayEvaluator{
			EvalFnc: func(ctx *eval.Context) []string {
				event := GetEvent(ctx)
				return event.ResolveProcessArgsOptions(event.Exec.Process)
			},
			Field:  field,
			Weight: eval.HandlerWeight,
		}, nil
	case "exec.args_truncated":
		return &eval.BoolEvaluator{
			EvalFnc: func(ctx *eval.Context) bool {
				event := GetEvent(ctx)
				return event.ResolveProcessArgsTruncated(event.Exec.Process)
			},
			Field:  field,
			Weight: eval.HandlerWeight,
		}, nil
	case "exec.argv":
		return &eval.StringArrayEvaluator{
			EvalFnc: func(ctx *eval.Context) []string {
				event := GetEvent(ctx)
				return event.ResolveProcessArgv(event.Exec.Process)
			},
			Field:  field,
			Weight: 100 * eval.HandlerWeight,
		}, nil
	case "exec.argv0":
		return &eval.StringEvaluator{
			EvalFnc: func(ctx *eval.Context) string {
				event := GetEvent(ctx)
				return event.ResolveProcessArgv0(event.Exec.Process)
			},
			Field:  field,
			Weight: 100 * eval.HandlerWeight,
		}, nil
	case "exec.cap_effective":
		return &eval.IntEvaluator{
			EvalFnc: func(ctx *eval.Context) int {
				event := GetEvent(ctx)
				return int(event.Exec.Process.Credentials.CapEffective)
			},
			Field:  field,
			Weight: eval.FunctionWeight,
		}, nil
	case "exec.cap_permitted":
		return &eval.IntEvaluator{
			EvalFnc: func(ctx *eval.Context) int {
				event := GetEvent(ctx)
				return int(event.Exec.Process.Credentials.CapPermitted)
			},
			Field:  field,
			Weight: eval.FunctionWeight,
		}, nil
	case "exec.comm":
		return &eval.StringEvaluator{
			EvalFnc: func(ctx *eval.Context) string {
				event := GetEvent(ctx)
				return event.Exec.Process.Comm
			},
			Field:  field,
			Weight: eval.FunctionWeight,
		}, nil
	case "exec.container.id":
		return &eval.StringEvaluator{
			EvalFnc: func(ctx *eval.Context) string {
				event := GetEvent(ctx)
				return event.Exec.Process.ContainerID
			},
			Field:  field,
			Weight: eval.FunctionWeight,
		}, nil
	case "exec.cookie":
		return &eval.IntEvaluator{
			EvalFnc: func(ctx *eval.Context) int {
				event := GetEvent(ctx)
				return int(event.Exec.Process.Cookie)
			},
			Field:  field,
			Weight: eval.FunctionWeight,
		}, nil
	case "exec.created_at":
		return &eval.IntEvaluator{
			EvalFnc: func(ctx *eval.Context) int {
				event := GetEvent(ctx)
				return int(event.ResolveProcessCreatedAt(event.Exec.Process))
			},
			Field:  field,
			Weight: eval.HandlerWeight,
		}, nil
	case "exec.egid":
		return &eval.IntEvaluator{
			EvalFnc: func(ctx *eval.Context) int {
				event := GetEvent(ctx)
				return int(event.Exec.Process.Credentials.EGID)
			},
			Field:  field,
			Weight: eval.FunctionWeight,
		}, nil
	case "exec.egroup":
		return &eval.StringEvaluator{
			EvalFnc: func(ctx *eval.Context) string {
				event := GetEvent(ctx)
				return event.Exec.Process.Credentials.EGroup
			},
			Field:  field,
			Weight: eval.FunctionWeight,
		}, nil
	case "exec.envp":
		return &eval.StringArrayEvaluator{
			EvalFnc: func(ctx *eval.Context) []string {
				event := GetEvent(ctx)
				return event.ResolveProcessEnvp(event.Exec.Process)
			},
			Field:  field,
			Weight: eval.HandlerWeight,
		}, nil
	case "exec.envs":
		return &eval.StringArrayEvaluator{
			EvalFnc: func(ctx *eval.Context) []string {
				event := GetEvent(ctx)
				return event.ResolveProcessEnvs(event.Exec.Process)
			},
			Field:  field,
			Weight: eval.HandlerWeight,
		}, nil
	case "exec.envs_truncated":
		return &eval.BoolEvaluator{
			EvalFnc: func(ctx *eval.Context) bool {
				event := GetEvent(ctx)
				return event.ResolveProcessEnvsTruncated(event.Exec.Process)
			},
			Field:  field,
			Weight: eval.HandlerWeight,
		}, nil
	case "exec.euid":
		return &eval.IntEvaluator{
			EvalFnc: func(ctx *eval.Context) int {
				event := GetEvent(ctx)
				return int(event.Exec.Process.Credentials.EUID)
			},
			Field:  field,
			Weight: eval.FunctionWeight,
		}, nil
	case "exec.euser":
		return &eval.StringEvaluator{
			EvalFnc: func(ctx *eval.Context) string {
				event := GetEvent(ctx)
				return event.Exec.Process.Credentials.EUser
			},
			Field:  field,
			Weight: eval.FunctionWeight,
		}, nil
	case "exec.file.change_time":
		return &eval.IntEvaluator{
			EvalFnc: func(ctx *eval.Context) int {
				event := GetEvent(ctx)
				return int(event.Exec.Process.FileEvent.FileFields.CTime)
			},
			Field:  field,
			Weight: eval.FunctionWeight,
		}, nil
	case "exec.file.filesystem":
		return &eval.StringEvaluator{
			EvalFnc: func(ctx *eval.Context) string {
				event := GetEvent(ctx)
				return event.ResolveFileFilesystem(&event.Exec.Process.FileEvent)
			},
			Field:  field,
			Weight: eval.HandlerWeight,
		}, nil
	case "exec.file.gid":
		return &eval.IntEvaluator{
			EvalFnc: func(ctx *eval.Context) int {
				event := GetEvent(ctx)
				return int(event.Exec.Process.FileEvent.FileFields.GID)
			},
			Field:  field,
			Weight: eval.FunctionWeight,
		}, nil
	case "exec.file.group":
		return &eval.StringEvaluator{
			EvalFnc: func(ctx *eval.Context) string {
				event := GetEvent(ctx)
				return event.ResolveFileFieldsGroup(&event.Exec.Process.FileEvent.FileFields)
			},
			Field:  field,
			Weight: eval.HandlerWeight,
		}, nil
	case "exec.file.in_upper_layer":
		return &eval.BoolEvaluator{
			EvalFnc: func(ctx *eval.Context) bool {
				event := GetEvent(ctx)
				return event.ResolveFileFieldsInUpperLayer(&event.Exec.Process.FileEvent.FileFields)
			},
			Field:  field,
			Weight: eval.HandlerWeight,
		}, nil
	case "exec.file.inode":
		return &eval.IntEvaluator{
			EvalFnc: func(ctx *eval.Context) int {
				event := GetEvent(ctx)
				return int(event.Exec.Process.FileEvent.FileFields.Inode)
			},
			Field:  field,
			Weight: eval.FunctionWeight,
		}, nil
	case "exec.file.mode":
		return &eval.IntEvaluator{
			EvalFnc: func(ctx *eval.Context) int {
				event := GetEvent(ctx)
				return int(event.Exec.Process.FileEvent.FileFields.Mode)
			},
			Field:  field,
			Weight: eval.FunctionWeight,
		}, nil
	case "exec.file.modification_time":
		return &eval.IntEvaluator{
			EvalFnc: func(ctx *eval.Context) int {
				event := GetEvent(ctx)
				return int(event.Exec.Process.FileEvent.FileFields.MTime)
			},
			Field:  field,
			Weight: eval.FunctionWeight,
		}, nil
	case "exec.file.mount_id":
		return &eval.IntEvaluator{
			EvalFnc: func(ctx *eval.Context) int {
				event := GetEvent(ctx)
				return int(event.Exec.Process.FileEvent.FileFields.MountID)
			},
			Field:  field,
			Weight: eval.FunctionWeight,
		}, nil
	case "exec.file.name":
		return &eval.StringEvaluator{
			OpOverrides: model.ProcessSymlinkBasename,
			EvalFnc: func(ctx *eval.Context) string {
				event := GetEvent(ctx)
				return event.ResolveFileBasename(&event.Exec.Process.FileEvent)
			},
			Field:  field,
			Weight: eval.HandlerWeight,
		}, nil
	case "exec.file.path":
		return &eval.StringEvaluator{
			OpOverrides: model.ProcessSymlinkPathname,
			EvalFnc: func(ctx *eval.Context) string {
				event := GetEvent(ctx)
				return event.ResolveFilePath(&event.Exec.Process.FileEvent)
			},
			Field:  field,
			Weight: eval.HandlerWeight,
		}, nil
	case "exec.file.rights":
		return &eval.IntEvaluator{
			EvalFnc: func(ctx *eval.Context) int {
				event := GetEvent(ctx)
				return int(event.ResolveRights(&event.Exec.Process.FileEvent.FileFields))
			},
			Field:  field,
			Weight: eval.HandlerWeight,
		}, nil
	case "exec.file.uid":
		return &eval.IntEvaluator{
			EvalFnc: func(ctx *eval.Context) int {
				event := GetEvent(ctx)
				return int(event.Exec.Process.FileEvent.FileFields.UID)
			},
			Field:  field,
			Weight: eval.FunctionWeight,
		}, nil
	case "exec.file.user":
		return &eval.StringEvaluator{
			EvalFnc: func(ctx *eval.Context) string {
				event := GetEvent(ctx)
				return event.ResolveFileFieldsUser(&event.Exec.Process.FileEvent.FileFields)
			},
			Field:  field,
			Weight: eval.HandlerWeight,
		}, nil
	case "exec.fsgid":
		return &eval.IntEvaluator{
			EvalFnc: func(ctx *eval.Context) int {
				event := GetEvent(ctx)
				return int(event.Exec.Process.Credentials.FSGID)
			},
			Field:  field,
			Weight: eval.FunctionWeight,
		}, nil
	case "exec.fsgroup":
		return &eval.StringEvaluator{
			EvalFnc: func(ctx *eval.Context) string {
				event := GetEvent(ctx)
				return event.Exec.Process.Credentials.FSGroup
			},
			Field:  field,
			Weight: eval.FunctionWeight,
		}, nil
	case "exec.fsuid":
		return &eval.IntEvaluator{
			EvalFnc: func(ctx *eval.Context) int {
				event := GetEvent(ctx)
				return int(event.Exec.Process.Credentials.FSUID)
			},
			Field:  field,
			Weight: eval.FunctionWeight,
		}, nil
	case "exec.fsuser":
		return &eval.StringEvaluator{
			EvalFnc: func(ctx *eval.Context) string {
				event := GetEvent(ctx)
				return event.Exec.Process.Credentials.FSUser
			},
			Field:  field,
			Weight: eval.FunctionWeight,
		}, nil
	case "exec.gid":
		return &eval.IntEvaluator{
			EvalFnc: func(ctx *eval.Context) int {
				event := GetEvent(ctx)
				return int(event.Exec.Process.Credentials.GID)
			},
			Field:  field,
			Weight: eval.FunctionWeight,
		}, nil
	case "exec.group":
		return &eval.StringEvaluator{
			EvalFnc: func(ctx *eval.Context) string {
				event := GetEvent(ctx)
				return event.Exec.Process.Credentials.Group
			},
			Field:  field,
			Weight: eval.FunctionWeight,
		}, nil
	case "exec.is_thread":
		return &eval.BoolEvaluator{
			EvalFnc: func(ctx *eval.Context) bool {
				event := GetEvent(ctx)
				return event.Exec.Process.IsThread
			},
			Field:  field,
			Weight: eval.FunctionWeight,
		}, nil
	case "exec.pid":
		return &eval.IntEvaluator{
			EvalFnc: func(ctx *eval.Context) int {
				event := GetEvent(ctx)
				return int(event.Exec.Process.PIDContext.Pid)
			},
			Field:  field,
			Weight: eval.FunctionWeight,
		}, nil
	case "exec.ppid":
		return &eval.IntEvaluator{
			EvalFnc: func(ctx *eval.Context) int {
				event := GetEvent(ctx)
				return int(event.Exec.Process.PPid)
			},
			Field:  field,
			Weight: eval.FunctionWeight,
		}, nil
	case "exec.tid":
		return &eval.IntEvaluator{
			EvalFnc: func(ctx *eval.Context) int {
				event := GetEvent(ctx)
				return int(event.Exec.Process.PIDContext.Tid)
			},
			Field:  field,
			Weight: eval.FunctionWeight,
		}, nil
	case "exec.tty_name":
		return &eval.StringEvaluator{
			EvalFnc: func(ctx *eval.Context) string {
				event := GetEvent(ctx)
				return event.Exec.Process.TTYName
			},
			Field:  field,
			Weight: eval.FunctionWeight,
		}, nil
	case "exec.uid":
		return &eval.IntEvaluator{
			EvalFnc: func(ctx *eval.Context) int {
				event := GetEvent(ctx)
				return int(event.Exec.Process.Credentials.UID)
			},
			Field:  field,
			Weight: eval.FunctionWeight,
		}, nil
	case "exec.user":
		return &eval.StringEvaluator{
			EvalFnc: func(ctx *eval.Context) string {
				event := GetEvent(ctx)
				return event.Exec.Process.Credentials.User
			},
			Field:  field,
			Weight: eval.FunctionWeight,
		}, nil
	case "exit.args":
		return &eval.StringEvaluator{
			EvalFnc: func(ctx *eval.Context) string {
				event := GetEvent(ctx)
				return event.ResolveProcessArgs(event.Exit.Process)
			},
			Field:  field,
			Weight: 100 * eval.HandlerWeight,
		}, nil
	case "exit.args_flags":
		return &eval.StringArrayEvaluator{
			EvalFnc: func(ctx *eval.Context) []string {
				event := GetEvent(ctx)
				return event.ResolveProcessArgsFlags(event.Exit.Process)
			},
			Field:  field,
			Weight: eval.HandlerWeight,
		}, nil
	case "exit.args_options":
		return &eval.StringArrayEvaluator{
			EvalFnc: func(ctx *eval.Context) []string {
				event := GetEvent(ctx)
				return event.ResolveProcessArgsOptions(event.Exit.Process)
			},
			Field:  field,
			Weight: eval.HandlerWeight,
		}, nil
	case "exit.args_truncated":
		return &eval.BoolEvaluator{
			EvalFnc: func(ctx *eval.Context) bool {
				event := GetEvent(ctx)
				return event.ResolveProcessArgsTruncated(event.Exit.Process)
			},
			Field:  field,
			Weight: eval.HandlerWeight,
		}, nil
	case "exit.argv":
		return &eval.StringArrayEvaluator{
			EvalFnc: func(ctx *eval.Context) []string {
				event := GetEvent(ctx)
				return event.ResolveProcessArgv(event.Exit.Process)
			},
			Field:  field,
			Weight: 100 * eval.HandlerWeight,
		}, nil
	case "exit.argv0":
		return &eval.StringEvaluator{
			EvalFnc: func(ctx *eval.Context) string {
				event := GetEvent(ctx)
				return event.ResolveProcessArgv0(event.Exit.Process)
			},
			Field:  field,
			Weight: 100 * eval.HandlerWeight,
		}, nil
	case "exit.cap_effective":
		return &eval.IntEvaluator{
			EvalFnc: func(ctx *eval.Context) int {
				event := GetEvent(ctx)
				return int(event.Exit.Process.Credentials.CapEffective)
			},
			Field:  field,
			Weight: eval.FunctionWeight,
		}, nil
	case "exit.cap_permitted":
		return &eval.IntEvaluator{
			EvalFnc: func(ctx *eval.Context) int {
				event := GetEvent(ctx)
				return int(event.Exit.Process.Credentials.CapPermitted)
			},
			Field:  field,
			Weight: eval.FunctionWeight,
		}, nil
	case "exit.cause":
		return &eval.IntEvaluator{
			EvalFnc: func(ctx *eval.Context) int {
				event := GetEvent(ctx)
				return int(event.Exit.Cause)
			},
			Field:  field,
			Weight: eval.FunctionWeight,
		}, nil
	case "exit.code":
		return &eval.IntEvaluator{
			EvalFnc: func(ctx *eval.Context) int {
				event := GetEvent(ctx)
				return int(event.Exit.Code)
			},
			Field:  field,
			Weight: eval.FunctionWeight,
		}, nil
	case "exit.comm":
		return &eval.StringEvaluator{
			EvalFnc: func(ctx *eval.Context) string {
				event := GetEvent(ctx)
				return event.Exit.Process.Comm
			},
			Field:  field,
			Weight: eval.FunctionWeight,
		}, nil
	case "exit.container.id":
		return &eval.StringEvaluator{
			EvalFnc: func(ctx *eval.Context) string {
				event := GetEvent(ctx)
				return event.Exit.Process.ContainerID
			},
			Field:  field,
			Weight: eval.FunctionWeight,
		}, nil
	case "exit.cookie":
		return &eval.IntEvaluator{
			EvalFnc: func(ctx *eval.Context) int {
				event := GetEvent(ctx)
				return int(event.Exit.Process.Cookie)
			},
			Field:  field,
			Weight: eval.FunctionWeight,
		}, nil
	case "exit.created_at":
		return &eval.IntEvaluator{
			EvalFnc: func(ctx *eval.Context) int {
				event := GetEvent(ctx)
				return int(event.ResolveProcessCreatedAt(event.Exit.Process))
			},
			Field:  field,
			Weight: eval.HandlerWeight,
		}, nil
	case "exit.egid":
		return &eval.IntEvaluator{
			EvalFnc: func(ctx *eval.Context) int {
				event := GetEvent(ctx)
				return int(event.Exit.Process.Credentials.EGID)
			},
			Field:  field,
			Weight: eval.FunctionWeight,
		}, nil
	case "exit.egroup":
		return &eval.StringEvaluator{
			EvalFnc: func(ctx *eval.Context) string {
				event := GetEvent(ctx)
				return event.Exit.Process.Credentials.EGroup
			},
			Field:  field,
			Weight: eval.FunctionWeight,
		}, nil
	case "exit.envp":
		return &eval.StringArrayEvaluator{
			EvalFnc: func(ctx *eval.Context) []string {
				event := GetEvent(ctx)
				return event.ResolveProcessEnvp(event.Exit.Process)
			},
			Field:  field,
			Weight: eval.HandlerWeight,
		}, nil
	case "exit.envs":
		return &eval.StringArrayEvaluator{
			EvalFnc: func(ctx *eval.Context) []string {
				event := GetEvent(ctx)
				return event.ResolveProcessEnvs(event.Exit.Process)
			},
			Field:  field,
			Weight: eval.HandlerWeight,
		}, nil
	case "exit.envs_truncated":
		return &eval.BoolEvaluator{
			EvalFnc: func(ctx *eval.Context) bool {
				event := GetEvent(ctx)
				return event.ResolveProcessEnvsTruncated(event.Exit.Process)
			},
			Field:  field,
			Weight: eval.HandlerWeight,
		}, nil
	case "exit.euid":
		return &eval.IntEvaluator{
			EvalFnc: func(ctx *eval.Context) int {
				event := GetEvent(ctx)
				return int(event.Exit.Process.Credentials.EUID)
			},
			Field:  field,
			Weight: eval.FunctionWeight,
		}, nil
	case "exit.euser":
		return &eval.StringEvaluator{
			EvalFnc: func(ctx *eval.Context) string {
				event := GetEvent(ctx)
				return event.Exit.Process.Credentials.EUser
			},
			Field:  field,
			Weight: eval.FunctionWeight,
		}, nil
	case "exit.file.change_time":
		return &eval.IntEvaluator{
			EvalFnc: func(ctx *eval.Context) int {
				event := GetEvent(ctx)
				return int(event.Exit.Process.FileEvent.FileFields.CTime)
			},
			Field:  field,
			Weight: eval.FunctionWeight,
		}, nil
	case "exit.file.filesystem":
		return &eval.StringEvaluator{
			EvalFnc: func(ctx *eval.Context) string {
				event := GetEvent(ctx)
				return event.ResolveFileFilesystem(&event.Exit.Process.FileEvent)
			},
			Field:  field,
			Weight: eval.HandlerWeight,
		}, nil
	case "exit.file.gid":
		return &eval.IntEvaluator{
			EvalFnc: func(ctx *eval.Context) int {
				event := GetEvent(ctx)
				return int(event.Exit.Process.FileEvent.FileFields.GID)
			},
			Field:  field,
			Weight: eval.FunctionWeight,
		}, nil
	case "exit.file.group":
		return &eval.StringEvaluator{
			EvalFnc: func(ctx *eval.Context) string {
				event := GetEvent(ctx)
				return event.ResolveFileFieldsGroup(&event.Exit.Process.FileEvent.FileFields)
			},
			Field:  field,
			Weight: eval.HandlerWeight,
		}, nil
	case "exit.file.in_upper_layer":
		return &eval.BoolEvaluator{
			EvalFnc: func(ctx *eval.Context) bool {
				event := GetEvent(ctx)
				return event.ResolveFileFieldsInUpperLayer(&event.Exit.Process.FileEvent.FileFields)
			},
			Field:  field,
			Weight: eval.HandlerWeight,
		}, nil
	case "exit.file.inode":
		return &eval.IntEvaluator{
			EvalFnc: func(ctx *eval.Context) int {
				event := GetEvent(ctx)
				return int(event.Exit.Process.FileEvent.FileFields.Inode)
			},
			Field:  field,
			Weight: eval.FunctionWeight,
		}, nil
	case "exit.file.mode":
		return &eval.IntEvaluator{
			EvalFnc: func(ctx *eval.Context) int {
				event := GetEvent(ctx)
				return int(event.Exit.Process.FileEvent.FileFields.Mode)
			},
			Field:  field,
			Weight: eval.FunctionWeight,
		}, nil
	case "exit.file.modification_time":
		return &eval.IntEvaluator{
			EvalFnc: func(ctx *eval.Context) int {
				event := GetEvent(ctx)
				return int(event.Exit.Process.FileEvent.FileFields.MTime)
			},
			Field:  field,
			Weight: eval.FunctionWeight,
		}, nil
	case "exit.file.mount_id":
		return &eval.IntEvaluator{
			EvalFnc: func(ctx *eval.Context) int {
				event := GetEvent(ctx)
				return int(event.Exit.Process.FileEvent.FileFields.MountID)
			},
			Field:  field,
			Weight: eval.FunctionWeight,
		}, nil
	case "exit.file.name":
		return &eval.StringEvaluator{
			OpOverrides: model.ProcessSymlinkBasename,
			EvalFnc: func(ctx *eval.Context) string {
				event := GetEvent(ctx)
				return event.ResolveFileBasename(&event.Exit.Process.FileEvent)
			},
			Field:  field,
			Weight: eval.HandlerWeight,
		}, nil
	case "exit.file.path":
		return &eval.StringEvaluator{
			OpOverrides: model.ProcessSymlinkPathname,
			EvalFnc: func(ctx *eval.Context) string {
				event := GetEvent(ctx)
				return event.ResolveFilePath(&event.Exit.Process.FileEvent)
			},
			Field:  field,
			Weight: eval.HandlerWeight,
		}, nil
	case "exit.file.rights":
		return &eval.IntEvaluator{
			EvalFnc: func(ctx *eval.Context) int {
				event := GetEvent(ctx)
				return int(event.ResolveRights(&event.Exit.Process.FileEvent.FileFields))
			},
			Field:  field,
			Weight: eval.HandlerWeight,
		}, nil
	case "exit.file.uid":
		return &eval.IntEvaluator{
			EvalFnc: func(ctx *eval.Context) int {
				event := GetEvent(ctx)
				return int(event.Exit.Process.FileEvent.FileFields.UID)
			},
			Field:  field,
			Weight: eval.FunctionWeight,
		}, nil
	case "exit.file.user":
		return &eval.StringEvaluator{
			EvalFnc: func(ctx *eval.Context) string {
				event := GetEvent(ctx)
				return event.ResolveFileFieldsUser(&event.Exit.Process.FileEvent.FileFields)
			},
			Field:  field,
			Weight: eval.HandlerWeight,
		}, nil
	case "exit.fsgid":
		return &eval.IntEvaluator{
			EvalFnc: func(ctx *eval.Context) int {
				event := GetEvent(ctx)
				return int(event.Exit.Process.Credentials.FSGID)
			},
			Field:  field,
			Weight: eval.FunctionWeight,
		}, nil
	case "exit.fsgroup":
		return &eval.StringEvaluator{
			EvalFnc: func(ctx *eval.Context) string {
				event := GetEvent(ctx)
				return event.Exit.Process.Credentials.FSGroup
			},
			Field:  field,
			Weight: eval.FunctionWeight,
		}, nil
	case "exit.fsuid":
		return &eval.IntEvaluator{
			EvalFnc: func(ctx *eval.Context) int {
				event := GetEvent(ctx)
				return int(event.Exit.Process.Credentials.FSUID)
			},
			Field:  field,
			Weight: eval.FunctionWeight,
		}, nil
	case "exit.fsuser":
		return &eval.StringEvaluator{
			EvalFnc: func(ctx *eval.Context) string {
				event := GetEvent(ctx)
				return event.Exit.Process.Credentials.FSUser
			},
			Field:  field,
			Weight: eval.FunctionWeight,
		}, nil
	case "exit.gid":
		return &eval.IntEvaluator{
			EvalFnc: func(ctx *eval.Context) int {
				event := GetEvent(ctx)
				return int(event.Exit.Process.Credentials.GID)
			},
			Field:  field,
			Weight: eval.FunctionWeight,
		}, nil
	case "exit.group":
		return &eval.StringEvaluator{
			EvalFnc: func(ctx *eval.Context) string {
				event := GetEvent(ctx)
				return event.Exit.Process.Credentials.Group
			},
			Field:  field,
			Weight: eval.FunctionWeight,
		}, nil
	case "exit.is_thread":
		return &eval.BoolEvaluator{
			EvalFnc: func(ctx *eval.Context) bool {
				event := GetEvent(ctx)
				return event.Exit.Process.IsThread
			},
			Field:  field,
			Weight: eval.FunctionWeight,
		}, nil
	case "exit.pid":
		return &eval.IntEvaluator{
			EvalFnc: func(ctx *eval.Context) int {
				event := GetEvent(ctx)
				return int(event.Exit.Process.PIDContext.Pid)
			},
			Field:  field,
			Weight: eval.FunctionWeight,
		}, nil
	case "exit.ppid":
		return &eval.IntEvaluator{
			EvalFnc: func(ctx *eval.Context) int {
				event := GetEvent(ctx)
				return int(event.Exit.Process.PPid)
			},
			Field:  field,
			Weight: eval.FunctionWeight,
		}, nil
	case "exit.tid":
		return &eval.IntEvaluator{
			EvalFnc: func(ctx *eval.Context) int {
				event := GetEvent(ctx)
				return int(event.Exit.Process.PIDContext.Tid)
			},
			Field:  field,
			Weight: eval.FunctionWeight,
		}, nil
	case "exit.tty_name":
		return &eval.StringEvaluator{
			EvalFnc: func(ctx *eval.Context) string {
				event := GetEvent(ctx)
				return event.Exit.Process.TTYName
			},
			Field:  field,
			Weight: eval.FunctionWeight,
		}, nil
	case "exit.uid":
		return &eval.IntEvaluator{
			EvalFnc: func(ctx *eval.Context) int {
				event := GetEvent(ctx)
				return int(event.Exit.Process.Credentials.UID)
			},
			Field:  field,
			Weight: eval.FunctionWeight,
		}, nil
	case "exit.user":
		return &eval.StringEvaluator{
			EvalFnc: func(ctx *eval.Context) string {
				event := GetEvent(ctx)
				return event.Exit.Process.Credentials.User
			},
			Field:  field,
			Weight: eval.FunctionWeight,
		}, nil
	case "link.file.change_time":
		return &eval.IntEvaluator{
			EvalFnc: func(ctx *eval.Context) int {
				event := GetEvent(ctx)
				return int(event.Link.Source.FileFields.CTime)
			},
			Field:  field,
			Weight: eval.FunctionWeight,
		}, nil
	case "link.file.destination.change_time":
		return &eval.IntEvaluator{
			EvalFnc: func(ctx *eval.Context) int {
				event := GetEvent(ctx)
				return int(event.Link.Target.FileFields.CTime)
			},
			Field:  field,
			Weight: eval.FunctionWeight,
		}, nil
	case "link.file.destination.filesystem":
		return &eval.StringEvaluator{
			EvalFnc: func(ctx *eval.Context) string {
				event := GetEvent(ctx)
				return event.ResolveFileFilesystem(&event.Link.Target)
			},
			Field:  field,
			Weight: eval.HandlerWeight,
		}, nil
	case "link.file.destination.gid":
		return &eval.IntEvaluator{
			EvalFnc: func(ctx *eval.Context) int {
				event := GetEvent(ctx)
				return int(event.Link.Target.FileFields.GID)
			},
			Field:  field,
			Weight: eval.FunctionWeight,
		}, nil
	case "link.file.destination.group":
		return &eval.StringEvaluator{
			EvalFnc: func(ctx *eval.Context) string {
				event := GetEvent(ctx)
				return event.ResolveFileFieldsGroup(&event.Link.Target.FileFields)
			},
			Field:  field,
			Weight: eval.HandlerWeight,
		}, nil
	case "link.file.destination.in_upper_layer":
		return &eval.BoolEvaluator{
			EvalFnc: func(ctx *eval.Context) bool {
				event := GetEvent(ctx)
				return event.ResolveFileFieldsInUpperLayer(&event.Link.Target.FileFields)
			},
			Field:  field,
			Weight: eval.HandlerWeight,
		}, nil
	case "link.file.destination.inode":
		return &eval.IntEvaluator{
			EvalFnc: func(ctx *eval.Context) int {
				event := GetEvent(ctx)
				return int(event.Link.Target.FileFields.Inode)
			},
			Field:  field,
			Weight: eval.FunctionWeight,
		}, nil
	case "link.file.destination.mode":
		return &eval.IntEvaluator{
			EvalFnc: func(ctx *eval.Context) int {
				event := GetEvent(ctx)
				return int(event.Link.Target.FileFields.Mode)
			},
			Field:  field,
			Weight: eval.FunctionWeight,
		}, nil
	case "link.file.destination.modification_time":
		return &eval.IntEvaluator{
			EvalFnc: func(ctx *eval.Context) int {
				event := GetEvent(ctx)
				return int(event.Link.Target.FileFields.MTime)
			},
			Field:  field,
			Weight: eval.FunctionWeight,
		}, nil
	case "link.file.destination.mount_id":
		return &eval.IntEvaluator{
			EvalFnc: func(ctx *eval.Context) int {
				event := GetEvent(ctx)
				return int(event.Link.Target.FileFields.MountID)
			},
			Field:  field,
			Weight: eval.FunctionWeight,
		}, nil
	case "link.file.destination.name":
		return &eval.StringEvaluator{
			OpOverrides: model.ProcessSymlinkBasename,
			EvalFnc: func(ctx *eval.Context) string {
				event := GetEvent(ctx)
				return event.ResolveFileBasename(&event.Link.Target)
			},
			Field:  field,
			Weight: eval.HandlerWeight,
		}, nil
	case "link.file.destination.path":
		return &eval.StringEvaluator{
			OpOverrides: model.ProcessSymlinkPathname,
			EvalFnc: func(ctx *eval.Context) string {
				event := GetEvent(ctx)
				return event.ResolveFilePath(&event.Link.Target)
			},
			Field:  field,
			Weight: eval.HandlerWeight,
		}, nil
	case "link.file.destination.rights":
		return &eval.IntEvaluator{
			EvalFnc: func(ctx *eval.Context) int {
				event := GetEvent(ctx)
				return int(event.ResolveRights(&event.Link.Target.FileFields))
			},
			Field:  field,
			Weight: eval.HandlerWeight,
		}, nil
	case "link.file.destination.uid":
		return &eval.IntEvaluator{
			EvalFnc: func(ctx *eval.Context) int {
				event := GetEvent(ctx)
				return int(event.Link.Target.FileFields.UID)
			},
			Field:  field,
			Weight: eval.FunctionWeight,
		}, nil
	case "link.file.destination.user":
		return &eval.StringEvaluator{
			EvalFnc: func(ctx *eval.Context) string {
				event := GetEvent(ctx)
				return event.ResolveFileFieldsUser(&event.Link.Target.FileFields)
			},
			Field:  field,
			Weight: eval.HandlerWeight,
		}, nil
	case "link.file.filesystem":
		return &eval.StringEvaluator{
			EvalFnc: func(ctx *eval.Context) string {
				event := GetEvent(ctx)
				return event.ResolveFileFilesystem(&event.Link.Source)
			},
			Field:  field,
			Weight: eval.HandlerWeight,
		}, nil
	case "link.file.gid":
		return &eval.IntEvaluator{
			EvalFnc: func(ctx *eval.Context) int {
				event := GetEvent(ctx)
				return int(event.Link.Source.FileFields.GID)
			},
			Field:  field,
			Weight: eval.FunctionWeight,
		}, nil
	case "link.file.group":
		return &eval.StringEvaluator{
			EvalFnc: func(ctx *eval.Context) string {
				event := GetEvent(ctx)
				return event.ResolveFileFieldsGroup(&event.Link.Source.FileFields)
			},
			Field:  field,
			Weight: eval.HandlerWeight,
		}, nil
	case "link.file.in_upper_layer":
		return &eval.BoolEvaluator{
			EvalFnc: func(ctx *eval.Context) bool {
				event := GetEvent(ctx)
				return event.ResolveFileFieldsInUpperLayer(&event.Link.Source.FileFields)
			},
			Field:  field,
			Weight: eval.HandlerWeight,
		}, nil
	case "link.file.inode":
		return &eval.IntEvaluator{
			EvalFnc: func(ctx *eval.Context) int {
				event := GetEvent(ctx)
				return int(event.Link.Source.FileFields.Inode)
			},
			Field:  field,
			Weight: eval.FunctionWeight,
		}, nil
	case "link.file.mode":
		return &eval.IntEvaluator{
			EvalFnc: func(ctx *eval.Context) int {
				event := GetEvent(ctx)
				return int(event.Link.Source.FileFields.Mode)
			},
			Field:  field,
			Weight: eval.FunctionWeight,
		}, nil
	case "link.file.modification_time":
		return &eval.IntEvaluator{
			EvalFnc: func(ctx *eval.Context) int {
				event := GetEvent(ctx)
				return int(event.Link.Source.FileFields.MTime)
			},
			Field:  field,
			Weight: eval.FunctionWeight,
		}, nil
	case "link.file.mount_id":
		return &eval.IntEvaluator{
			EvalFnc: func(ctx *eval.Context) int {
				event := GetEvent(ctx)
				return int(event.Link.Source.FileFields.MountID)
			},
			Field:  field,
			Weight: eval.FunctionWeight,
		}, nil
	case "link.file.name":
		return &eval.StringEvaluator{
			OpOverrides: model.ProcessSymlinkBasename,
			EvalFnc: func(ctx *eval.Context) string {
				event := GetEvent(ctx)
				return event.ResolveFileBasename(&event.Link.Source)
			},
			Field:  field,
			Weight: eval.HandlerWeight,
		}, nil
	case "link.file.path":
		return &eval.StringEvaluator{
			OpOverrides: model.ProcessSymlinkPathname,
			EvalFnc: func(ctx *eval.Context) string {
				event := GetEvent(ctx)
				return event.ResolveFilePath(&event.Link.Source)
			},
			Field:  field,
			Weight: eval.HandlerWeight,
		}, nil
	case "link.file.rights":
		return &eval.IntEvaluator{
			EvalFnc: func(ctx *eval.Context) int {
				event := GetEvent(ctx)
				return int(event.ResolveRights(&event.Link.Source.FileFields))
			},
			Field:  field,
			Weight: eval.HandlerWeight,
		}, nil
	case "link.file.uid":
		return &eval.IntEvaluator{
			EvalFnc: func(ctx *eval.Context) int {
				event := GetEvent(ctx)
				return int(event.Link.Source.FileFields.UID)
			},
			Field:  field,
			Weight: eval.FunctionWeight,
		}, nil
	case "link.file.user":
		return &eval.StringEvaluator{
			EvalFnc: func(ctx *eval.Context) string {
				event := GetEvent(ctx)
				return event.ResolveFileFieldsUser(&event.Link.Source.FileFields)
			},
			Field:  field,
			Weight: eval.HandlerWeight,
		}, nil
	case "link.retval":
		return &eval.IntEvaluator{
			EvalFnc: func(ctx *eval.Context) int {
				event := GetEvent(ctx)
				return int(event.Link.SyscallEvent.Retval)
			},
			Field:  field,
			Weight: eval.FunctionWeight,
		}, nil
	case "load_module.file.change_time":
		return &eval.IntEvaluator{
			EvalFnc: func(ctx *eval.Context) int {
				event := GetEvent(ctx)
				return int(event.LoadModule.File.FileFields.CTime)
			},
			Field:  field,
			Weight: eval.FunctionWeight,
		}, nil
	case "load_module.file.filesystem":
		return &eval.StringEvaluator{
			EvalFnc: func(ctx *eval.Context) string {
				event := GetEvent(ctx)
				return event.ResolveFileFilesystem(&event.LoadModule.File)
			},
			Field:  field,
			Weight: eval.HandlerWeight,
		}, nil
	case "load_module.file.gid":
		return &eval.IntEvaluator{
			EvalFnc: func(ctx *eval.Context) int {
				event := GetEvent(ctx)
				return int(event.LoadModule.File.FileFields.GID)
			},
			Field:  field,
			Weight: eval.FunctionWeight,
		}, nil
	case "load_module.file.group":
		return &eval.StringEvaluator{
			EvalFnc: func(ctx *eval.Context) string {
				event := GetEvent(ctx)
				return event.ResolveFileFieldsGroup(&event.LoadModule.File.FileFields)
			},
			Field:  field,
			Weight: eval.HandlerWeight,
		}, nil
	case "load_module.file.in_upper_layer":
		return &eval.BoolEvaluator{
			EvalFnc: func(ctx *eval.Context) bool {
				event := GetEvent(ctx)
				return event.ResolveFileFieldsInUpperLayer(&event.LoadModule.File.FileFields)
			},
			Field:  field,
			Weight: eval.HandlerWeight,
		}, nil
	case "load_module.file.inode":
		return &eval.IntEvaluator{
			EvalFnc: func(ctx *eval.Context) int {
				event := GetEvent(ctx)
				return int(event.LoadModule.File.FileFields.Inode)
			},
			Field:  field,
			Weight: eval.FunctionWeight,
		}, nil
	case "load_module.file.mode":
		return &eval.IntEvaluator{
			EvalFnc: func(ctx *eval.Context) int {
				event := GetEvent(ctx)
				return int(event.LoadModule.File.FileFields.Mode)
			},
			Field:  field,
			Weight: eval.FunctionWeight,
		}, nil
	case "load_module.file.modification_time":
		return &eval.IntEvaluator{
			EvalFnc: func(ctx *eval.Context) int {
				event := GetEvent(ctx)
				return int(event.LoadModule.File.FileFields.MTime)
			},
			Field:  field,
			Weight: eval.FunctionWeight,
		}, nil
	case "load_module.file.mount_id":
		return &eval.IntEvaluator{
			EvalFnc: func(ctx *eval.Context) int {
				event := GetEvent(ctx)
				return int(event.LoadModule.File.FileFields.MountID)
			},
			Field:  field,
			Weight: eval.FunctionWeight,
		}, nil
	case "load_module.file.name":
		return &eval.StringEvaluator{
			OpOverrides: model.ProcessSymlinkBasename,
			EvalFnc: func(ctx *eval.Context) string {
				event := GetEvent(ctx)
				return event.ResolveFileBasename(&event.LoadModule.File)
			},
			Field:  field,
			Weight: eval.HandlerWeight,
		}, nil
	case "load_module.file.path":
		return &eval.StringEvaluator{
			OpOverrides: model.ProcessSymlinkPathname,
			EvalFnc: func(ctx *eval.Context) string {
				event := GetEvent(ctx)
				return event.ResolveFilePath(&event.LoadModule.File)
			},
			Field:  field,
			Weight: eval.HandlerWeight,
		}, nil
	case "load_module.file.rights":
		return &eval.IntEvaluator{
			EvalFnc: func(ctx *eval.Context) int {
				event := GetEvent(ctx)
				return int(event.ResolveRights(&event.LoadModule.File.FileFields))
			},
			Field:  field,
			Weight: eval.HandlerWeight,
		}, nil
	case "load_module.file.uid":
		return &eval.IntEvaluator{
			EvalFnc: func(ctx *eval.Context) int {
				event := GetEvent(ctx)
				return int(event.LoadModule.File.FileFields.UID)
			},
			Field:  field,
			Weight: eval.FunctionWeight,
		}, nil
	case "load_module.file.user":
		return &eval.StringEvaluator{
			EvalFnc: func(ctx *eval.Context) string {
				event := GetEvent(ctx)
				return event.ResolveFileFieldsUser(&event.LoadModule.File.FileFields)
			},
			Field:  field,
			Weight: eval.HandlerWeight,
		}, nil
	case "load_module.loaded_from_memory":
		return &eval.BoolEvaluator{
			EvalFnc: func(ctx *eval.Context) bool {
				event := GetEvent(ctx)
				return event.LoadModule.LoadedFromMemory
			},
			Field:  field,
			Weight: eval.FunctionWeight,
		}, nil
	case "load_module.name":
		return &eval.StringEvaluator{
			EvalFnc: func(ctx *eval.Context) string {
				event := GetEvent(ctx)
				return event.LoadModule.Name
			},
			Field:  field,
			Weight: eval.FunctionWeight,
		}, nil
	case "load_module.retval":
		return &eval.IntEvaluator{
			EvalFnc: func(ctx *eval.Context) int {
				event := GetEvent(ctx)
				return int(event.LoadModule.SyscallEvent.Retval)
			},
			Field:  field,
			Weight: eval.FunctionWeight,
		}, nil
	case "mkdir.file.change_time":
		return &eval.IntEvaluator{
			EvalFnc: func(ctx *eval.Context) int {
				event := GetEvent(ctx)
				return int(event.Mkdir.File.FileFields.CTime)
			},
			Field:  field,
			Weight: eval.FunctionWeight,
		}, nil
	case "mkdir.file.destination.mode":
		return &eval.IntEvaluator{
			EvalFnc: func(ctx *eval.Context) int {
				event := GetEvent(ctx)
				return int(event.Mkdir.Mode)
			},
			Field:  field,
			Weight: eval.FunctionWeight,
		}, nil
	case "mkdir.file.destination.rights":
		return &eval.IntEvaluator{
			EvalFnc: func(ctx *eval.Context) int {
				event := GetEvent(ctx)
				return int(event.Mkdir.Mode)
			},
			Field:  field,
			Weight: eval.FunctionWeight,
		}, nil
	case "mkdir.file.filesystem":
		return &eval.StringEvaluator{
			EvalFnc: func(ctx *eval.Context) string {
				event := GetEvent(ctx)
				return event.ResolveFileFilesystem(&event.Mkdir.File)
			},
			Field:  field,
			Weight: eval.HandlerWeight,
		}, nil
	case "mkdir.file.gid":
		return &eval.IntEvaluator{
			EvalFnc: func(ctx *eval.Context) int {
				event := GetEvent(ctx)
				return int(event.Mkdir.File.FileFields.GID)
			},
			Field:  field,
			Weight: eval.FunctionWeight,
		}, nil
	case "mkdir.file.group":
		return &eval.StringEvaluator{
			EvalFnc: func(ctx *eval.Context) string {
				event := GetEvent(ctx)
				return event.ResolveFileFieldsGroup(&event.Mkdir.File.FileFields)
			},
			Field:  field,
			Weight: eval.HandlerWeight,
		}, nil
	case "mkdir.file.in_upper_layer":
		return &eval.BoolEvaluator{
			EvalFnc: func(ctx *eval.Context) bool {
				event := GetEvent(ctx)
				return event.ResolveFileFieldsInUpperLayer(&event.Mkdir.File.FileFields)
			},
			Field:  field,
			Weight: eval.HandlerWeight,
		}, nil
	case "mkdir.file.inode":
		return &eval.IntEvaluator{
			EvalFnc: func(ctx *eval.Context) int {
				event := GetEvent(ctx)
				return int(event.Mkdir.File.FileFields.Inode)
			},
			Field:  field,
			Weight: eval.FunctionWeight,
		}, nil
	case "mkdir.file.mode":
		return &eval.IntEvaluator{
			EvalFnc: func(ctx *eval.Context) int {
				event := GetEvent(ctx)
				return int(event.Mkdir.File.FileFields.Mode)
			},
			Field:  field,
			Weight: eval.FunctionWeight,
		}, nil
	case "mkdir.file.modification_time":
		return &eval.IntEvaluator{
			EvalFnc: func(ctx *eval.Context) int {
				event := GetEvent(ctx)
				return int(event.Mkdir.File.FileFields.MTime)
			},
			Field:  field,
			Weight: eval.FunctionWeight,
		}, nil
	case "mkdir.file.mount_id":
		return &eval.IntEvaluator{
			EvalFnc: func(ctx *eval.Context) int {
				event := GetEvent(ctx)
				return int(event.Mkdir.File.FileFields.MountID)
			},
			Field:  field,
			Weight: eval.FunctionWeight,
		}, nil
	case "mkdir.file.name":
		return &eval.StringEvaluator{
			OpOverrides: model.ProcessSymlinkBasename,
			EvalFnc: func(ctx *eval.Context) string {
				event := GetEvent(ctx)
				return event.ResolveFileBasename(&event.Mkdir.File)
			},
			Field:  field,
			Weight: eval.HandlerWeight,
		}, nil
	case "mkdir.file.path":
		return &eval.StringEvaluator{
			OpOverrides: model.ProcessSymlinkPathname,
			EvalFnc: func(ctx *eval.Context) string {
				event := GetEvent(ctx)
				return event.ResolveFilePath(&event.Mkdir.File)
			},
			Field:  field,
			Weight: eval.HandlerWeight,
		}, nil
	case "mkdir.file.rights":
		return &eval.IntEvaluator{
			EvalFnc: func(ctx *eval.Context) int {
				event := GetEvent(ctx)
				return int(event.ResolveRights(&event.Mkdir.File.FileFields))
			},
			Field:  field,
			Weight: eval.HandlerWeight,
		}, nil
	case "mkdir.file.uid":
		return &eval.IntEvaluator{
			EvalFnc: func(ctx *eval.Context) int {
				event := GetEvent(ctx)
				return int(event.Mkdir.File.FileFields.UID)
			},
			Field:  field,
			Weight: eval.FunctionWeight,
		}, nil
	case "mkdir.file.user":
		return &eval.StringEvaluator{
			EvalFnc: func(ctx *eval.Context) string {
				event := GetEvent(ctx)
				return event.ResolveFileFieldsUser(&event.Mkdir.File.FileFields)
			},
			Field:  field,
			Weight: eval.HandlerWeight,
		}, nil
	case "mkdir.retval":
		return &eval.IntEvaluator{
			EvalFnc: func(ctx *eval.Context) int {
				event := GetEvent(ctx)
				return int(event.Mkdir.SyscallEvent.Retval)
			},
			Field:  field,
			Weight: eval.FunctionWeight,
		}, nil
	case "mmap.file.change_time":
		return &eval.IntEvaluator{
			EvalFnc: func(ctx *eval.Context) int {
				event := GetEvent(ctx)
				return int(event.MMap.File.FileFields.CTime)
			},
			Field:  field,
			Weight: eval.FunctionWeight,
		}, nil
	case "mmap.file.filesystem":
		return &eval.StringEvaluator{
			EvalFnc: func(ctx *eval.Context) string {
				event := GetEvent(ctx)
				return event.ResolveFileFilesystem(&event.MMap.File)
			},
			Field:  field,
			Weight: eval.HandlerWeight,
		}, nil
	case "mmap.file.gid":
		return &eval.IntEvaluator{
			EvalFnc: func(ctx *eval.Context) int {
				event := GetEvent(ctx)
				return int(event.MMap.File.FileFields.GID)
			},
			Field:  field,
			Weight: eval.FunctionWeight,
		}, nil
	case "mmap.file.group":
		return &eval.StringEvaluator{
			EvalFnc: func(ctx *eval.Context) string {
				event := GetEvent(ctx)
				return event.ResolveFileFieldsGroup(&event.MMap.File.FileFields)
			},
			Field:  field,
			Weight: eval.HandlerWeight,
		}, nil
	case "mmap.file.in_upper_layer":
		return &eval.BoolEvaluator{
			EvalFnc: func(ctx *eval.Context) bool {
				event := GetEvent(ctx)
				return event.ResolveFileFieldsInUpperLayer(&event.MMap.File.FileFields)
			},
			Field:  field,
			Weight: eval.HandlerWeight,
		}, nil
	case "mmap.file.inode":
		return &eval.IntEvaluator{
			EvalFnc: func(ctx *eval.Context) int {
				event := GetEvent(ctx)
				return int(event.MMap.File.FileFields.Inode)
			},
			Field:  field,
			Weight: eval.FunctionWeight,
		}, nil
	case "mmap.file.mode":
		return &eval.IntEvaluator{
			EvalFnc: func(ctx *eval.Context) int {
				event := GetEvent(ctx)
				return int(event.MMap.File.FileFields.Mode)
			},
			Field:  field,
			Weight: eval.FunctionWeight,
		}, nil
	case "mmap.file.modification_time":
		return &eval.IntEvaluator{
			EvalFnc: func(ctx *eval.Context) int {
				event := GetEvent(ctx)
				return int(event.MMap.File.FileFields.MTime)
			},
			Field:  field,
			Weight: eval.FunctionWeight,
		}, nil
	case "mmap.file.mount_id":
		return &eval.IntEvaluator{
			EvalFnc: func(ctx *eval.Context) int {
				event := GetEvent(ctx)
				return int(event.MMap.File.FileFields.MountID)
			},
			Field:  field,
			Weight: eval.FunctionWeight,
		}, nil
	case "mmap.file.name":
		return &eval.StringEvaluator{
			OpOverrides: model.ProcessSymlinkBasename,
			EvalFnc: func(ctx *eval.Context) string {
				event := GetEvent(ctx)
				return event.ResolveFileBasename(&event.MMap.File)
			},
			Field:  field,
			Weight: eval.HandlerWeight,
		}, nil
	case "mmap.file.path":
		return &eval.StringEvaluator{
			OpOverrides: model.ProcessSymlinkPathname,
			EvalFnc: func(ctx *eval.Context) string {
				event := GetEvent(ctx)
				return event.ResolveFilePath(&event.MMap.File)
			},
			Field:  field,
			Weight: eval.HandlerWeight,
		}, nil
	case "mmap.file.rights":
		return &eval.IntEvaluator{
			EvalFnc: func(ctx *eval.Context) int {
				event := GetEvent(ctx)
				return int(event.ResolveRights(&event.MMap.File.FileFields))
			},
			Field:  field,
			Weight: eval.HandlerWeight,
		}, nil
	case "mmap.file.uid":
		return &eval.IntEvaluator{
			EvalFnc: func(ctx *eval.Context) int {
				event := GetEvent(ctx)
				return int(event.MMap.File.FileFields.UID)
			},
			Field:  field,
			Weight: eval.FunctionWeight,
		}, nil
	case "mmap.file.user":
		return &eval.StringEvaluator{
			EvalFnc: func(ctx *eval.Context) string {
				event := GetEvent(ctx)
				return event.ResolveFileFieldsUser(&event.MMap.File.FileFields)
			},
			Field:  field,
			Weight: eval.HandlerWeight,
		}, nil
	case "mmap.flags":
		return &eval.IntEvaluator{
			EvalFnc: func(ctx *eval.Context) int {
				event := GetEvent(ctx)
				return event.MMap.Flags
			},
			Field:  field,
			Weight: eval.FunctionWeight,
		}, nil
	case "mmap.protection":
		return &eval.IntEvaluator{
			EvalFnc: func(ctx *eval.Context) int {
				event := GetEvent(ctx)
				return event.MMap.Protection
			},
			Field:  field,
			Weight: eval.FunctionWeight,
		}, nil
	case "mmap.retval":
		return &eval.IntEvaluator{
			EvalFnc: func(ctx *eval.Context) int {
				event := GetEvent(ctx)
				return int(event.MMap.SyscallEvent.Retval)
			},
			Field:  field,
			Weight: eval.FunctionWeight,
		}, nil
	case "mprotect.req_protection":
		return &eval.IntEvaluator{
			EvalFnc: func(ctx *eval.Context) int {
				event := GetEvent(ctx)
				return event.MProtect.ReqProtection
			},
			Field:  field,
			Weight: eval.FunctionWeight,
		}, nil
	case "mprotect.retval":
		return &eval.IntEvaluator{
			EvalFnc: func(ctx *eval.Context) int {
				event := GetEvent(ctx)
				return int(event.MProtect.SyscallEvent.Retval)
			},
			Field:  field,
			Weight: eval.FunctionWeight,
		}, nil
	case "mprotect.vm_protection":
		return &eval.IntEvaluator{
			EvalFnc: func(ctx *eval.Context) int {
				event := GetEvent(ctx)
				return event.MProtect.VMProtection
			},
			Field:  field,
			Weight: eval.FunctionWeight,
		}, nil
	case "network.destination.ip":
		return &eval.CIDREvaluator{
			EvalFnc: func(ctx *eval.Context) net.IPNet {
				event := GetEvent(ctx)
				return event.NetworkContext.Destination.IPNet
			},
			Field:  field,
			Weight: eval.FunctionWeight,
		}, nil
	case "network.destination.port":
		return &eval.IntEvaluator{
			EvalFnc: func(ctx *eval.Context) int {
				event := GetEvent(ctx)
				return int(event.NetworkContext.Destination.Port)
			},
			Field:  field,
			Weight: eval.FunctionWeight,
		}, nil
	case "network.device.ifindex":
		return &eval.IntEvaluator{
			EvalFnc: func(ctx *eval.Context) int {
				event := GetEvent(ctx)
				return int(event.NetworkContext.Device.IfIndex)
			},
			Field:  field,
			Weight: eval.FunctionWeight,
		}, nil
	case "network.device.ifname":
		return &eval.StringEvaluator{
			EvalFnc: func(ctx *eval.Context) string {
				event := GetEvent(ctx)
				return event.ResolveNetworkDeviceIfName(&event.NetworkContext.Device)
			},
			Field:  field,
			Weight: eval.HandlerWeight,
		}, nil
	case "network.l3_protocol":
		return &eval.IntEvaluator{
			EvalFnc: func(ctx *eval.Context) int {
				event := GetEvent(ctx)
				return int(event.NetworkContext.L3Protocol)
			},
			Field:  field,
			Weight: eval.FunctionWeight,
		}, nil
	case "network.l4_protocol":
		return &eval.IntEvaluator{
			EvalFnc: func(ctx *eval.Context) int {
				event := GetEvent(ctx)
				return int(event.NetworkContext.L4Protocol)
			},
			Field:  field,
			Weight: eval.FunctionWeight,
		}, nil
	case "network.size":
		return &eval.IntEvaluator{
			EvalFnc: func(ctx *eval.Context) int {
				event := GetEvent(ctx)
				return int(event.NetworkContext.Size)
			},
			Field:  field,
			Weight: eval.FunctionWeight,
		}, nil
	case "network.source.ip":
		return &eval.CIDREvaluator{
			EvalFnc: func(ctx *eval.Context) net.IPNet {
				event := GetEvent(ctx)
				return event.NetworkContext.Source.IPNet
			},
			Field:  field,
			Weight: eval.FunctionWeight,
		}, nil
	case "network.source.port":
		return &eval.IntEvaluator{
			EvalFnc: func(ctx *eval.Context) int {
				event := GetEvent(ctx)
				return int(event.NetworkContext.Source.Port)
			},
			Field:  field,
			Weight: eval.FunctionWeight,
		}, nil
	case "open.file.change_time":
		return &eval.IntEvaluator{
			EvalFnc: func(ctx *eval.Context) int {
				event := GetEvent(ctx)
				return int(event.Open.File.FileFields.CTime)
			},
			Field:  field,
			Weight: eval.FunctionWeight,
		}, nil
	case "open.file.destination.mode":
		return &eval.IntEvaluator{
			EvalFnc: func(ctx *eval.Context) int {
				event := GetEvent(ctx)
				return int(event.Open.Mode)
			},
			Field:  field,
			Weight: eval.FunctionWeight,
		}, nil
	case "open.file.filesystem":
		return &eval.StringEvaluator{
			EvalFnc: func(ctx *eval.Context) string {
				event := GetEvent(ctx)
				return event.ResolveFileFilesystem(&event.Open.File)
			},
			Field:  field,
			Weight: eval.HandlerWeight,
		}, nil
	case "open.file.gid":
		return &eval.IntEvaluator{
			EvalFnc: func(ctx *eval.Context) int {
				event := GetEvent(ctx)
				return int(event.Open.File.FileFields.GID)
			},
			Field:  field,
			Weight: eval.FunctionWeight,
		}, nil
	case "open.file.group":
		return &eval.StringEvaluator{
			EvalFnc: func(ctx *eval.Context) string {
				event := GetEvent(ctx)
				return event.ResolveFileFieldsGroup(&event.Open.File.FileFields)
			},
			Field:  field,
			Weight: eval.HandlerWeight,
		}, nil
	case "open.file.in_upper_layer":
		return &eval.BoolEvaluator{
			EvalFnc: func(ctx *eval.Context) bool {
				event := GetEvent(ctx)
				return event.ResolveFileFieldsInUpperLayer(&event.Open.File.FileFields)
			},
			Field:  field,
			Weight: eval.HandlerWeight,
		}, nil
	case "open.file.inode":
		return &eval.IntEvaluator{
			EvalFnc: func(ctx *eval.Context) int {
				event := GetEvent(ctx)
				return int(event.Open.File.FileFields.Inode)
			},
			Field:  field,
			Weight: eval.FunctionWeight,
		}, nil
	case "open.file.mode":
		return &eval.IntEvaluator{
			EvalFnc: func(ctx *eval.Context) int {
				event := GetEvent(ctx)
				return int(event.Open.File.FileFields.Mode)
			},
			Field:  field,
			Weight: eval.FunctionWeight,
		}, nil
	case "open.file.modification_time":
		return &eval.IntEvaluator{
			EvalFnc: func(ctx *eval.Context) int {
				event := GetEvent(ctx)
				return int(event.Open.File.FileFields.MTime)
			},
			Field:  field,
			Weight: eval.FunctionWeight,
		}, nil
	case "open.file.mount_id":
		return &eval.IntEvaluator{
			EvalFnc: func(ctx *eval.Context) int {
				event := GetEvent(ctx)
				return int(event.Open.File.FileFields.MountID)
			},
			Field:  field,
			Weight: eval.FunctionWeight,
		}, nil
	case "open.file.name":
		return &eval.StringEvaluator{
			OpOverrides: model.ProcessSymlinkBasename,
			EvalFnc: func(ctx *eval.Context) string {
				event := GetEvent(ctx)
				return event.ResolveFileBasename(&event.Open.File)
			},
			Field:  field,
			Weight: eval.HandlerWeight,
		}, nil
	case "open.file.path":
		return &eval.StringEvaluator{
			OpOverrides: model.ProcessSymlinkPathname,
			EvalFnc: func(ctx *eval.Context) string {
				event := GetEvent(ctx)
				return event.ResolveFilePath(&event.Open.File)
			},
			Field:  field,
			Weight: eval.HandlerWeight,
		}, nil
	case "open.file.rights":
		return &eval.IntEvaluator{
			EvalFnc: func(ctx *eval.Context) int {
				event := GetEvent(ctx)
				return int(event.ResolveRights(&event.Open.File.FileFields))
			},
			Field:  field,
			Weight: eval.HandlerWeight,
		}, nil
	case "open.file.uid":
		return &eval.IntEvaluator{
			EvalFnc: func(ctx *eval.Context) int {
				event := GetEvent(ctx)
				return int(event.Open.File.FileFields.UID)
			},
			Field:  field,
			Weight: eval.FunctionWeight,
		}, nil
	case "open.file.user":
		return &eval.StringEvaluator{
			EvalFnc: func(ctx *eval.Context) string {
				event := GetEvent(ctx)
				return event.ResolveFileFieldsUser(&event.Open.File.FileFields)
			},
			Field:  field,
			Weight: eval.HandlerWeight,
		}, nil
	case "open.flags":
		return &eval.IntEvaluator{
			EvalFnc: func(ctx *eval.Context) int {
				event := GetEvent(ctx)
				return int(event.Open.Flags)
			},
			Field:  field,
			Weight: eval.FunctionWeight,
		}, nil
	case "open.retval":
		return &eval.IntEvaluator{
			EvalFnc: func(ctx *eval.Context) int {
				event := GetEvent(ctx)
				return int(event.Open.SyscallEvent.Retval)
			},
			Field:  field,
			Weight: eval.FunctionWeight,
		}, nil
	case "process.ancestors.args":
		return &eval.StringArrayEvaluator{
			EvalFnc: func(ctx *eval.Context) []string {
				if ptr := ctx.Cache[field]; ptr != nil {
					if result := (*[]string)(ptr); result != nil {
						return *result
					}
				}
				var results []string
				iterator := &model.ProcessAncestorsIterator{}
				value := iterator.Front(ctx)
				for value != nil {
					element := (*model.ProcessCacheEntry)(value)
					event := GetEvent(ctx)
					result := event.ResolveProcessArgs(&element.ProcessContext.Process)
					results = append(results, result)
					value = iterator.Next()
				}
				ctx.Cache[field] = unsafe.Pointer(&results)
				return results
			}, Field: field,
			Weight: 100 * eval.IteratorWeight,
		}, nil
	case "process.ancestors.args_flags":
		return &eval.StringArrayEvaluator{
			EvalFnc: func(ctx *eval.Context) []string {
				if ptr := ctx.Cache[field]; ptr != nil {
					if result := (*[]string)(ptr); result != nil {
						return *result
					}
				}
				var results []string
				iterator := &model.ProcessAncestorsIterator{}
				value := iterator.Front(ctx)
				for value != nil {
					element := (*model.ProcessCacheEntry)(value)
					event := GetEvent(ctx)
					result := event.ResolveProcessArgsFlags(&element.ProcessContext.Process)
					results = append(results, result...)
					value = iterator.Next()
				}
				ctx.Cache[field] = unsafe.Pointer(&results)
				return results
			}, Field: field,
			Weight: eval.IteratorWeight,
		}, nil
	case "process.ancestors.args_options":
		return &eval.StringArrayEvaluator{
			EvalFnc: func(ctx *eval.Context) []string {
				if ptr := ctx.Cache[field]; ptr != nil {
					if result := (*[]string)(ptr); result != nil {
						return *result
					}
				}
				var results []string
				iterator := &model.ProcessAncestorsIterator{}
				value := iterator.Front(ctx)
				for value != nil {
					element := (*model.ProcessCacheEntry)(value)
					event := GetEvent(ctx)
					result := event.ResolveProcessArgsOptions(&element.ProcessContext.Process)
					results = append(results, result...)
					value = iterator.Next()
				}
				ctx.Cache[field] = unsafe.Pointer(&results)
				return results
			}, Field: field,
			Weight: eval.IteratorWeight,
		}, nil
	case "process.ancestors.args_truncated":
		return &eval.BoolArrayEvaluator{
			EvalFnc: func(ctx *eval.Context) []bool {
				if ptr := ctx.Cache[field]; ptr != nil {
					if result := (*[]bool)(ptr); result != nil {
						return *result
					}
				}
				var results []bool
				iterator := &model.ProcessAncestorsIterator{}
				value := iterator.Front(ctx)
				for value != nil {
					element := (*model.ProcessCacheEntry)(value)
					event := GetEvent(ctx)
					result := event.ResolveProcessArgsTruncated(&element.ProcessContext.Process)
					results = append(results, result)
					value = iterator.Next()
				}
				ctx.Cache[field] = unsafe.Pointer(&results)
				return results
			}, Field: field,
			Weight: eval.IteratorWeight,
		}, nil
	case "process.ancestors.argv":
		return &eval.StringArrayEvaluator{
			EvalFnc: func(ctx *eval.Context) []string {
				if ptr := ctx.Cache[field]; ptr != nil {
					if result := (*[]string)(ptr); result != nil {
						return *result
					}
				}
				var results []string
				iterator := &model.ProcessAncestorsIterator{}
				value := iterator.Front(ctx)
				for value != nil {
					element := (*model.ProcessCacheEntry)(value)
					event := GetEvent(ctx)
					result := event.ResolveProcessArgv(&element.ProcessContext.Process)
					results = append(results, result...)
					value = iterator.Next()
				}
				ctx.Cache[field] = unsafe.Pointer(&results)
				return results
			}, Field: field,
			Weight: 100 * eval.IteratorWeight,
		}, nil
	case "process.ancestors.argv0":
		return &eval.StringArrayEvaluator{
			EvalFnc: func(ctx *eval.Context) []string {
				if ptr := ctx.Cache[field]; ptr != nil {
					if result := (*[]string)(ptr); result != nil {
						return *result
					}
				}
				var results []string
				iterator := &model.ProcessAncestorsIterator{}
				value := iterator.Front(ctx)
				for value != nil {
					element := (*model.ProcessCacheEntry)(value)
					event := GetEvent(ctx)
					result := event.ResolveProcessArgv0(&element.ProcessContext.Process)
					results = append(results, result)
					value = iterator.Next()
				}
				ctx.Cache[field] = unsafe.Pointer(&results)
				return results
			}, Field: field,
			Weight: 100 * eval.IteratorWeight,
		}, nil
	case "process.ancestors.cap_effective":
		return &eval.IntArrayEvaluator{
			EvalFnc: func(ctx *eval.Context) []int {
				if ptr := ctx.Cache[field]; ptr != nil {
					if result := (*[]int)(ptr); result != nil {
						return *result
					}
				}
				var results []int
				iterator := &model.ProcessAncestorsIterator{}
				value := iterator.Front(ctx)
				for value != nil {
					element := (*model.ProcessCacheEntry)(value)
					result := int(element.ProcessContext.Process.Credentials.CapEffective)
					results = append(results, result)
					value = iterator.Next()
				}
				ctx.Cache[field] = unsafe.Pointer(&results)
				return results
			}, Field: field,
			Weight: eval.IteratorWeight,
		}, nil
	case "process.ancestors.cap_permitted":
		return &eval.IntArrayEvaluator{
			EvalFnc: func(ctx *eval.Context) []int {
				if ptr := ctx.Cache[field]; ptr != nil {
					if result := (*[]int)(ptr); result != nil {
						return *result
					}
				}
				var results []int
				iterator := &model.ProcessAncestorsIterator{}
				value := iterator.Front(ctx)
				for value != nil {
					element := (*model.ProcessCacheEntry)(value)
					result := int(element.ProcessContext.Process.Credentials.CapPermitted)
					results = append(results, result)
					value = iterator.Next()
				}
				ctx.Cache[field] = unsafe.Pointer(&results)
				return results
			}, Field: field,
			Weight: eval.IteratorWeight,
		}, nil
	case "process.ancestors.comm":
		return &eval.StringArrayEvaluator{
			EvalFnc: func(ctx *eval.Context) []string {
				if ptr := ctx.Cache[field]; ptr != nil {
					if result := (*[]string)(ptr); result != nil {
						return *result
					}
				}
				var results []string
				iterator := &model.ProcessAncestorsIterator{}
				value := iterator.Front(ctx)
				for value != nil {
					element := (*model.ProcessCacheEntry)(value)
					result := element.ProcessContext.Process.Comm
					results = append(results, result)
					value = iterator.Next()
				}
				ctx.Cache[field] = unsafe.Pointer(&results)
				return results
			}, Field: field,
			Weight: eval.IteratorWeight,
		}, nil
	case "process.ancestors.container.id":
		return &eval.StringArrayEvaluator{
			EvalFnc: func(ctx *eval.Context) []string {
				if ptr := ctx.Cache[field]; ptr != nil {
					if result := (*[]string)(ptr); result != nil {
						return *result
					}
				}
				var results []string
				iterator := &model.ProcessAncestorsIterator{}
				value := iterator.Front(ctx)
				for value != nil {
					element := (*model.ProcessCacheEntry)(value)
					result := element.ProcessContext.Process.ContainerID
					results = append(results, result)
					value = iterator.Next()
				}
				ctx.Cache[field] = unsafe.Pointer(&results)
				return results
			}, Field: field,
			Weight: eval.IteratorWeight,
		}, nil
	case "process.ancestors.cookie":
		return &eval.IntArrayEvaluator{
			EvalFnc: func(ctx *eval.Context) []int {
				if ptr := ctx.Cache[field]; ptr != nil {
					if result := (*[]int)(ptr); result != nil {
						return *result
					}
				}
				var results []int
				iterator := &model.ProcessAncestorsIterator{}
				value := iterator.Front(ctx)
				for value != nil {
					element := (*model.ProcessCacheEntry)(value)
					result := int(element.ProcessContext.Process.Cookie)
					results = append(results, result)
					value = iterator.Next()
				}
				ctx.Cache[field] = unsafe.Pointer(&results)
				return results
			}, Field: field,
			Weight: eval.IteratorWeight,
		}, nil
	case "process.ancestors.created_at":
		return &eval.IntArrayEvaluator{
			EvalFnc: func(ctx *eval.Context) []int {
				if ptr := ctx.Cache[field]; ptr != nil {
					if result := (*[]int)(ptr); result != nil {
						return *result
					}
				}
				var results []int
				iterator := &model.ProcessAncestorsIterator{}
				value := iterator.Front(ctx)
				for value != nil {
					element := (*model.ProcessCacheEntry)(value)
					event := GetEvent(ctx)
					result := int(event.ResolveProcessCreatedAt(&element.ProcessContext.Process))
					results = append(results, result)
					value = iterator.Next()
				}
				ctx.Cache[field] = unsafe.Pointer(&results)
				return results
			}, Field: field,
			Weight: eval.IteratorWeight,
		}, nil
	case "process.ancestors.egid":
		return &eval.IntArrayEvaluator{
			EvalFnc: func(ctx *eval.Context) []int {
				if ptr := ctx.Cache[field]; ptr != nil {
					if result := (*[]int)(ptr); result != nil {
						return *result
					}
				}
				var results []int
				iterator := &model.ProcessAncestorsIterator{}
				value := iterator.Front(ctx)
				for value != nil {
					element := (*model.ProcessCacheEntry)(value)
					result := int(element.ProcessContext.Process.Credentials.EGID)
					results = append(results, result)
					value = iterator.Next()
				}
				ctx.Cache[field] = unsafe.Pointer(&results)
				return results
			}, Field: field,
			Weight: eval.IteratorWeight,
		}, nil
	case "process.ancestors.egroup":
		return &eval.StringArrayEvaluator{
			EvalFnc: func(ctx *eval.Context) []string {
				if ptr := ctx.Cache[field]; ptr != nil {
					if result := (*[]string)(ptr); result != nil {
						return *result
					}
				}
				var results []string
				iterator := &model.ProcessAncestorsIterator{}
				value := iterator.Front(ctx)
				for value != nil {
					element := (*model.ProcessCacheEntry)(value)
					result := element.ProcessContext.Process.Credentials.EGroup
					results = append(results, result)
					value = iterator.Next()
				}
				ctx.Cache[field] = unsafe.Pointer(&results)
				return results
			}, Field: field,
			Weight: eval.IteratorWeight,
		}, nil
	case "process.ancestors.envp":
		return &eval.StringArrayEvaluator{
			EvalFnc: func(ctx *eval.Context) []string {
				if ptr := ctx.Cache[field]; ptr != nil {
					if result := (*[]string)(ptr); result != nil {
						return *result
					}
				}
				var results []string
				iterator := &model.ProcessAncestorsIterator{}
				value := iterator.Front(ctx)
				for value != nil {
					element := (*model.ProcessCacheEntry)(value)
					event := GetEvent(ctx)
					result := event.ResolveProcessEnvp(&element.ProcessContext.Process)
					results = append(results, result...)
					value = iterator.Next()
				}
				ctx.Cache[field] = unsafe.Pointer(&results)
				return results
			}, Field: field,
			Weight: eval.IteratorWeight,
		}, nil
	case "process.ancestors.envs":
		return &eval.StringArrayEvaluator{
			EvalFnc: func(ctx *eval.Context) []string {
				if ptr := ctx.Cache[field]; ptr != nil {
					if result := (*[]string)(ptr); result != nil {
						return *result
					}
				}
				var results []string
				iterator := &model.ProcessAncestorsIterator{}
				value := iterator.Front(ctx)
				for value != nil {
					element := (*model.ProcessCacheEntry)(value)
					event := GetEvent(ctx)
					result := event.ResolveProcessEnvs(&element.ProcessContext.Process)
					results = append(results, result...)
					value = iterator.Next()
				}
				ctx.Cache[field] = unsafe.Pointer(&results)
				return results
			}, Field: field,
			Weight: eval.IteratorWeight,
		}, nil
	case "process.ancestors.envs_truncated":
		return &eval.BoolArrayEvaluator{
			EvalFnc: func(ctx *eval.Context) []bool {
				if ptr := ctx.Cache[field]; ptr != nil {
					if result := (*[]bool)(ptr); result != nil {
						return *result
					}
				}
				var results []bool
				iterator := &model.ProcessAncestorsIterator{}
				value := iterator.Front(ctx)
				for value != nil {
					element := (*model.ProcessCacheEntry)(value)
					event := GetEvent(ctx)
					result := event.ResolveProcessEnvsTruncated(&element.ProcessContext.Process)
					results = append(results, result)
					value = iterator.Next()
				}
				ctx.Cache[field] = unsafe.Pointer(&results)
				return results
			}, Field: field,
			Weight: eval.IteratorWeight,
		}, nil
	case "process.ancestors.euid":
		return &eval.IntArrayEvaluator{
			EvalFnc: func(ctx *eval.Context) []int {
				if ptr := ctx.Cache[field]; ptr != nil {
					if result := (*[]int)(ptr); result != nil {
						return *result
					}
				}
				var results []int
				iterator := &model.ProcessAncestorsIterator{}
				value := iterator.Front(ctx)
				for value != nil {
					element := (*model.ProcessCacheEntry)(value)
					result := int(element.ProcessContext.Process.Credentials.EUID)
					results = append(results, result)
					value = iterator.Next()
				}
				ctx.Cache[field] = unsafe.Pointer(&results)
				return results
			}, Field: field,
			Weight: eval.IteratorWeight,
		}, nil
	case "process.ancestors.euser":
		return &eval.StringArrayEvaluator{
			EvalFnc: func(ctx *eval.Context) []string {
				if ptr := ctx.Cache[field]; ptr != nil {
					if result := (*[]string)(ptr); result != nil {
						return *result
					}
				}
				var results []string
				iterator := &model.ProcessAncestorsIterator{}
				value := iterator.Front(ctx)
				for value != nil {
					element := (*model.ProcessCacheEntry)(value)
					result := element.ProcessContext.Process.Credentials.EUser
					results = append(results, result)
					value = iterator.Next()
				}
				ctx.Cache[field] = unsafe.Pointer(&results)
				return results
			}, Field: field,
			Weight: eval.IteratorWeight,
		}, nil
	case "process.ancestors.file.change_time":
		return &eval.IntArrayEvaluator{
			EvalFnc: func(ctx *eval.Context) []int {
				if ptr := ctx.Cache[field]; ptr != nil {
					if result := (*[]int)(ptr); result != nil {
						return *result
					}
				}
				var results []int
				iterator := &model.ProcessAncestorsIterator{}
				value := iterator.Front(ctx)
				for value != nil {
					element := (*model.ProcessCacheEntry)(value)
					result := int(element.ProcessContext.Process.FileEvent.FileFields.CTime)
					results = append(results, result)
					value = iterator.Next()
				}
				ctx.Cache[field] = unsafe.Pointer(&results)
				return results
			}, Field: field,
			Weight: eval.IteratorWeight,
		}, nil
	case "process.ancestors.file.filesystem":
		return &eval.StringArrayEvaluator{
			EvalFnc: func(ctx *eval.Context) []string {
				if ptr := ctx.Cache[field]; ptr != nil {
					if result := (*[]string)(ptr); result != nil {
						return *result
					}
				}
				var results []string
				iterator := &model.ProcessAncestorsIterator{}
				value := iterator.Front(ctx)
				for value != nil {
					element := (*model.ProcessCacheEntry)(value)
					event := GetEvent(ctx)
					result := event.ResolveFileFilesystem(&element.ProcessContext.Process.FileEvent)
					results = append(results, result)
					value = iterator.Next()
				}
				ctx.Cache[field] = unsafe.Pointer(&results)
				return results
			}, Field: field,
			Weight: eval.IteratorWeight,
		}, nil
	case "process.ancestors.file.gid":
		return &eval.IntArrayEvaluator{
			EvalFnc: func(ctx *eval.Context) []int {
				if ptr := ctx.Cache[field]; ptr != nil {
					if result := (*[]int)(ptr); result != nil {
						return *result
					}
				}
				var results []int
				iterator := &model.ProcessAncestorsIterator{}
				value := iterator.Front(ctx)
				for value != nil {
					element := (*model.ProcessCacheEntry)(value)
					result := int(element.ProcessContext.Process.FileEvent.FileFields.GID)
					results = append(results, result)
					value = iterator.Next()
				}
				ctx.Cache[field] = unsafe.Pointer(&results)
				return results
			}, Field: field,
			Weight: eval.IteratorWeight,
		}, nil
	case "process.ancestors.file.group":
		return &eval.StringArrayEvaluator{
			EvalFnc: func(ctx *eval.Context) []string {
				if ptr := ctx.Cache[field]; ptr != nil {
					if result := (*[]string)(ptr); result != nil {
						return *result
					}
				}
				var results []string
				iterator := &model.ProcessAncestorsIterator{}
				value := iterator.Front(ctx)
				for value != nil {
					element := (*model.ProcessCacheEntry)(value)
					event := GetEvent(ctx)
					result := event.ResolveFileFieldsGroup(&element.ProcessContext.Process.FileEvent.FileFields)
					results = append(results, result)
					value = iterator.Next()
				}
				ctx.Cache[field] = unsafe.Pointer(&results)
				return results
			}, Field: field,
			Weight: eval.IteratorWeight,
		}, nil
	case "process.ancestors.file.in_upper_layer":
		return &eval.BoolArrayEvaluator{
			EvalFnc: func(ctx *eval.Context) []bool {
				if ptr := ctx.Cache[field]; ptr != nil {
					if result := (*[]bool)(ptr); result != nil {
						return *result
					}
				}
				var results []bool
				iterator := &model.ProcessAncestorsIterator{}
				value := iterator.Front(ctx)
				for value != nil {
					element := (*model.ProcessCacheEntry)(value)
					event := GetEvent(ctx)
					result := event.ResolveFileFieldsInUpperLayer(&element.ProcessContext.Process.FileEvent.FileFields)
					results = append(results, result)
					value = iterator.Next()
				}
				ctx.Cache[field] = unsafe.Pointer(&results)
				return results
			}, Field: field,
			Weight: eval.IteratorWeight,
		}, nil
	case "process.ancestors.file.inode":
		return &eval.IntArrayEvaluator{
			EvalFnc: func(ctx *eval.Context) []int {
				if ptr := ctx.Cache[field]; ptr != nil {
					if result := (*[]int)(ptr); result != nil {
						return *result
					}
				}
				var results []int
				iterator := &model.ProcessAncestorsIterator{}
				value := iterator.Front(ctx)
				for value != nil {
					element := (*model.ProcessCacheEntry)(value)
					result := int(element.ProcessContext.Process.FileEvent.FileFields.Inode)
					results = append(results, result)
					value = iterator.Next()
				}
				ctx.Cache[field] = unsafe.Pointer(&results)
				return results
			}, Field: field,
			Weight: eval.IteratorWeight,
		}, nil
	case "process.ancestors.file.mode":
		return &eval.IntArrayEvaluator{
			EvalFnc: func(ctx *eval.Context) []int {
				if ptr := ctx.Cache[field]; ptr != nil {
					if result := (*[]int)(ptr); result != nil {
						return *result
					}
				}
				var results []int
				iterator := &model.ProcessAncestorsIterator{}
				value := iterator.Front(ctx)
				for value != nil {
					element := (*model.ProcessCacheEntry)(value)
					result := int(element.ProcessContext.Process.FileEvent.FileFields.Mode)
					results = append(results, result)
					value = iterator.Next()
				}
				ctx.Cache[field] = unsafe.Pointer(&results)
				return results
			}, Field: field,
			Weight: eval.IteratorWeight,
		}, nil
	case "process.ancestors.file.modification_time":
		return &eval.IntArrayEvaluator{
			EvalFnc: func(ctx *eval.Context) []int {
				if ptr := ctx.Cache[field]; ptr != nil {
					if result := (*[]int)(ptr); result != nil {
						return *result
					}
				}
				var results []int
				iterator := &model.ProcessAncestorsIterator{}
				value := iterator.Front(ctx)
				for value != nil {
					element := (*model.ProcessCacheEntry)(value)
					result := int(element.ProcessContext.Process.FileEvent.FileFields.MTime)
					results = append(results, result)
					value = iterator.Next()
				}
				ctx.Cache[field] = unsafe.Pointer(&results)
				return results
			}, Field: field,
			Weight: eval.IteratorWeight,
		}, nil
	case "process.ancestors.file.mount_id":
		return &eval.IntArrayEvaluator{
			EvalFnc: func(ctx *eval.Context) []int {
				if ptr := ctx.Cache[field]; ptr != nil {
					if result := (*[]int)(ptr); result != nil {
						return *result
					}
				}
				var results []int
				iterator := &model.ProcessAncestorsIterator{}
				value := iterator.Front(ctx)
				for value != nil {
					element := (*model.ProcessCacheEntry)(value)
					result := int(element.ProcessContext.Process.FileEvent.FileFields.MountID)
					results = append(results, result)
					value = iterator.Next()
				}
				ctx.Cache[field] = unsafe.Pointer(&results)
				return results
			}, Field: field,
			Weight: eval.IteratorWeight,
		}, nil
	case "process.ancestors.file.name":
		return &eval.StringArrayEvaluator{
			OpOverrides: model.ProcessSymlinkBasename,
			EvalFnc: func(ctx *eval.Context) []string {
				if ptr := ctx.Cache[field]; ptr != nil {
					if result := (*[]string)(ptr); result != nil {
						return *result
					}
				}
				var results []string
				iterator := &model.ProcessAncestorsIterator{}
				value := iterator.Front(ctx)
				for value != nil {
					element := (*model.ProcessCacheEntry)(value)
					event := GetEvent(ctx)
					result := event.ResolveFileBasename(&element.ProcessContext.Process.FileEvent)
					results = append(results, result)
					value = iterator.Next()
				}
				ctx.Cache[field] = unsafe.Pointer(&results)
				return results
			}, Field: field,
			Weight: eval.IteratorWeight,
		}, nil
	case "process.ancestors.file.path":
		return &eval.StringArrayEvaluator{
			OpOverrides: model.ProcessSymlinkPathname,
			EvalFnc: func(ctx *eval.Context) []string {
				if ptr := ctx.Cache[field]; ptr != nil {
					if result := (*[]string)(ptr); result != nil {
						return *result
					}
				}
				var results []string
				iterator := &model.ProcessAncestorsIterator{}
				value := iterator.Front(ctx)
				for value != nil {
					element := (*model.ProcessCacheEntry)(value)
					event := GetEvent(ctx)
					result := event.ResolveFilePath(&element.ProcessContext.Process.FileEvent)
					results = append(results, result)
					value = iterator.Next()
				}
				ctx.Cache[field] = unsafe.Pointer(&results)
				return results
			}, Field: field,
			Weight: eval.IteratorWeight,
		}, nil
	case "process.ancestors.file.rights":
		return &eval.IntArrayEvaluator{
			EvalFnc: func(ctx *eval.Context) []int {
				if ptr := ctx.Cache[field]; ptr != nil {
					if result := (*[]int)(ptr); result != nil {
						return *result
					}
				}
				var results []int
				iterator := &model.ProcessAncestorsIterator{}
				value := iterator.Front(ctx)
				for value != nil {
					element := (*model.ProcessCacheEntry)(value)
					event := GetEvent(ctx)
					result := int(event.ResolveRights(&element.ProcessContext.Process.FileEvent.FileFields))
					results = append(results, result)
					value = iterator.Next()
				}
				ctx.Cache[field] = unsafe.Pointer(&results)
				return results
			}, Field: field,
			Weight: eval.IteratorWeight,
		}, nil
	case "process.ancestors.file.uid":
		return &eval.IntArrayEvaluator{
			EvalFnc: func(ctx *eval.Context) []int {
				if ptr := ctx.Cache[field]; ptr != nil {
					if result := (*[]int)(ptr); result != nil {
						return *result
					}
				}
				var results []int
				iterator := &model.ProcessAncestorsIterator{}
				value := iterator.Front(ctx)
				for value != nil {
					element := (*model.ProcessCacheEntry)(value)
					result := int(element.ProcessContext.Process.FileEvent.FileFields.UID)
					results = append(results, result)
					value = iterator.Next()
				}
				ctx.Cache[field] = unsafe.Pointer(&results)
				return results
			}, Field: field,
			Weight: eval.IteratorWeight,
		}, nil
	case "process.ancestors.file.user":
		return &eval.StringArrayEvaluator{
			EvalFnc: func(ctx *eval.Context) []string {
				if ptr := ctx.Cache[field]; ptr != nil {
					if result := (*[]string)(ptr); result != nil {
						return *result
					}
				}
				var results []string
				iterator := &model.ProcessAncestorsIterator{}
				value := iterator.Front(ctx)
				for value != nil {
					element := (*model.ProcessCacheEntry)(value)
					event := GetEvent(ctx)
					result := event.ResolveFileFieldsUser(&element.ProcessContext.Process.FileEvent.FileFields)
					results = append(results, result)
					value = iterator.Next()
				}
				ctx.Cache[field] = unsafe.Pointer(&results)
				return results
			}, Field: field,
			Weight: eval.IteratorWeight,
		}, nil
	case "process.ancestors.fsgid":
		return &eval.IntArrayEvaluator{
			EvalFnc: func(ctx *eval.Context) []int {
				if ptr := ctx.Cache[field]; ptr != nil {
					if result := (*[]int)(ptr); result != nil {
						return *result
					}
				}
				var results []int
				iterator := &model.ProcessAncestorsIterator{}
				value := iterator.Front(ctx)
				for value != nil {
					element := (*model.ProcessCacheEntry)(value)
					result := int(element.ProcessContext.Process.Credentials.FSGID)
					results = append(results, result)
					value = iterator.Next()
				}
				ctx.Cache[field] = unsafe.Pointer(&results)
				return results
			}, Field: field,
			Weight: eval.IteratorWeight,
		}, nil
	case "process.ancestors.fsgroup":
		return &eval.StringArrayEvaluator{
			EvalFnc: func(ctx *eval.Context) []string {
				if ptr := ctx.Cache[field]; ptr != nil {
					if result := (*[]string)(ptr); result != nil {
						return *result
					}
				}
				var results []string
				iterator := &model.ProcessAncestorsIterator{}
				value := iterator.Front(ctx)
				for value != nil {
					element := (*model.ProcessCacheEntry)(value)
					result := element.ProcessContext.Process.Credentials.FSGroup
					results = append(results, result)
					value = iterator.Next()
				}
				ctx.Cache[field] = unsafe.Pointer(&results)
				return results
			}, Field: field,
			Weight: eval.IteratorWeight,
		}, nil
	case "process.ancestors.fsuid":
		return &eval.IntArrayEvaluator{
			EvalFnc: func(ctx *eval.Context) []int {
				if ptr := ctx.Cache[field]; ptr != nil {
					if result := (*[]int)(ptr); result != nil {
						return *result
					}
				}
				var results []int
				iterator := &model.ProcessAncestorsIterator{}
				value := iterator.Front(ctx)
				for value != nil {
					element := (*model.ProcessCacheEntry)(value)
					result := int(element.ProcessContext.Process.Credentials.FSUID)
					results = append(results, result)
					value = iterator.Next()
				}
				ctx.Cache[field] = unsafe.Pointer(&results)
				return results
			}, Field: field,
			Weight: eval.IteratorWeight,
		}, nil
	case "process.ancestors.fsuser":
		return &eval.StringArrayEvaluator{
			EvalFnc: func(ctx *eval.Context) []string {
				if ptr := ctx.Cache[field]; ptr != nil {
					if result := (*[]string)(ptr); result != nil {
						return *result
					}
				}
				var results []string
				iterator := &model.ProcessAncestorsIterator{}
				value := iterator.Front(ctx)
				for value != nil {
					element := (*model.ProcessCacheEntry)(value)
					result := element.ProcessContext.Process.Credentials.FSUser
					results = append(results, result)
					value = iterator.Next()
				}
				ctx.Cache[field] = unsafe.Pointer(&results)
				return results
			}, Field: field,
			Weight: eval.IteratorWeight,
		}, nil
	case "process.ancestors.gid":
		return &eval.IntArrayEvaluator{
			EvalFnc: func(ctx *eval.Context) []int {
				if ptr := ctx.Cache[field]; ptr != nil {
					if result := (*[]int)(ptr); result != nil {
						return *result
					}
				}
				var results []int
				iterator := &model.ProcessAncestorsIterator{}
				value := iterator.Front(ctx)
				for value != nil {
					element := (*model.ProcessCacheEntry)(value)
					result := int(element.ProcessContext.Process.Credentials.GID)
					results = append(results, result)
					value = iterator.Next()
				}
				ctx.Cache[field] = unsafe.Pointer(&results)
				return results
			}, Field: field,
			Weight: eval.IteratorWeight,
		}, nil
	case "process.ancestors.group":
		return &eval.StringArrayEvaluator{
			EvalFnc: func(ctx *eval.Context) []string {
				if ptr := ctx.Cache[field]; ptr != nil {
					if result := (*[]string)(ptr); result != nil {
						return *result
					}
				}
				var results []string
				iterator := &model.ProcessAncestorsIterator{}
				value := iterator.Front(ctx)
				for value != nil {
					element := (*model.ProcessCacheEntry)(value)
					result := element.ProcessContext.Process.Credentials.Group
					results = append(results, result)
					value = iterator.Next()
				}
				ctx.Cache[field] = unsafe.Pointer(&results)
				return results
			}, Field: field,
			Weight: eval.IteratorWeight,
		}, nil
	case "process.ancestors.is_thread":
		return &eval.BoolArrayEvaluator{
			EvalFnc: func(ctx *eval.Context) []bool {
				if ptr := ctx.Cache[field]; ptr != nil {
					if result := (*[]bool)(ptr); result != nil {
						return *result
					}
				}
				var results []bool
				iterator := &model.ProcessAncestorsIterator{}
				value := iterator.Front(ctx)
				for value != nil {
					element := (*model.ProcessCacheEntry)(value)
					result := element.ProcessContext.Process.IsThread
					results = append(results, result)
					value = iterator.Next()
				}
				ctx.Cache[field] = unsafe.Pointer(&results)
				return results
			}, Field: field,
			Weight: eval.IteratorWeight,
		}, nil
	case "process.ancestors.pid":
		return &eval.IntArrayEvaluator{
			EvalFnc: func(ctx *eval.Context) []int {
				if ptr := ctx.Cache[field]; ptr != nil {
					if result := (*[]int)(ptr); result != nil {
						return *result
					}
				}
				var results []int
				iterator := &model.ProcessAncestorsIterator{}
				value := iterator.Front(ctx)
				for value != nil {
					element := (*model.ProcessCacheEntry)(value)
					result := int(element.ProcessContext.Process.PIDContext.Pid)
					results = append(results, result)
					value = iterator.Next()
				}
				ctx.Cache[field] = unsafe.Pointer(&results)
				return results
			}, Field: field,
			Weight: eval.IteratorWeight,
		}, nil
	case "process.ancestors.ppid":
		return &eval.IntArrayEvaluator{
			EvalFnc: func(ctx *eval.Context) []int {
				if ptr := ctx.Cache[field]; ptr != nil {
					if result := (*[]int)(ptr); result != nil {
						return *result
					}
				}
				var results []int
				iterator := &model.ProcessAncestorsIterator{}
				value := iterator.Front(ctx)
				for value != nil {
					element := (*model.ProcessCacheEntry)(value)
					result := int(element.ProcessContext.Process.PPid)
					results = append(results, result)
					value = iterator.Next()
				}
				ctx.Cache[field] = unsafe.Pointer(&results)
				return results
			}, Field: field,
			Weight: eval.IteratorWeight,
		}, nil
	case "process.ancestors.tid":
		return &eval.IntArrayEvaluator{
			EvalFnc: func(ctx *eval.Context) []int {
				if ptr := ctx.Cache[field]; ptr != nil {
					if result := (*[]int)(ptr); result != nil {
						return *result
					}
				}
				var results []int
				iterator := &model.ProcessAncestorsIterator{}
				value := iterator.Front(ctx)
				for value != nil {
					element := (*model.ProcessCacheEntry)(value)
					result := int(element.ProcessContext.Process.PIDContext.Tid)
					results = append(results, result)
					value = iterator.Next()
				}
				ctx.Cache[field] = unsafe.Pointer(&results)
				return results
			}, Field: field,
			Weight: eval.IteratorWeight,
		}, nil
	case "process.ancestors.tty_name":
		return &eval.StringArrayEvaluator{
			EvalFnc: func(ctx *eval.Context) []string {
				if ptr := ctx.Cache[field]; ptr != nil {
					if result := (*[]string)(ptr); result != nil {
						return *result
					}
				}
				var results []string
				iterator := &model.ProcessAncestorsIterator{}
				value := iterator.Front(ctx)
				for value != nil {
					element := (*model.ProcessCacheEntry)(value)
					result := element.ProcessContext.Process.TTYName
					results = append(results, result)
					value = iterator.Next()
				}
				ctx.Cache[field] = unsafe.Pointer(&results)
				return results
			}, Field: field,
			Weight: eval.IteratorWeight,
		}, nil
	case "process.ancestors.uid":
		return &eval.IntArrayEvaluator{
			EvalFnc: func(ctx *eval.Context) []int {
				if ptr := ctx.Cache[field]; ptr != nil {
					if result := (*[]int)(ptr); result != nil {
						return *result
					}
				}
				var results []int
				iterator := &model.ProcessAncestorsIterator{}
				value := iterator.Front(ctx)
				for value != nil {
					element := (*model.ProcessCacheEntry)(value)
					result := int(element.ProcessContext.Process.Credentials.UID)
					results = append(results, result)
					value = iterator.Next()
				}
				ctx.Cache[field] = unsafe.Pointer(&results)
				return results
			}, Field: field,
			Weight: eval.IteratorWeight,
		}, nil
	case "process.ancestors.user":
		return &eval.StringArrayEvaluator{
			EvalFnc: func(ctx *eval.Context) []string {
				if ptr := ctx.Cache[field]; ptr != nil {
					if result := (*[]string)(ptr); result != nil {
						return *result
					}
				}
				var results []string
				iterator := &model.ProcessAncestorsIterator{}
				value := iterator.Front(ctx)
				for value != nil {
					element := (*model.ProcessCacheEntry)(value)
					result := element.ProcessContext.Process.Credentials.User
					results = append(results, result)
					value = iterator.Next()
				}
				ctx.Cache[field] = unsafe.Pointer(&results)
				return results
			}, Field: field,
			Weight: eval.IteratorWeight,
		}, nil
	case "process.args":
		return &eval.StringEvaluator{
			EvalFnc: func(ctx *eval.Context) string {
				event := GetEvent(ctx)
				return event.ResolveProcessArgs(&event.ProcessContext.Process)
			},
			Field:  field,
			Weight: 100 * eval.HandlerWeight,
		}, nil
	case "process.args_flags":
		return &eval.StringArrayEvaluator{
			EvalFnc: func(ctx *eval.Context) []string {
				event := GetEvent(ctx)
				return event.ResolveProcessArgsFlags(&event.ProcessContext.Process)
			},
			Field:  field,
			Weight: eval.HandlerWeight,
		}, nil
	case "process.args_options":
		return &eval.StringArrayEvaluator{
			EvalFnc: func(ctx *eval.Context) []string {
				event := GetEvent(ctx)
				return event.ResolveProcessArgsOptions(&event.ProcessContext.Process)
			},
			Field:  field,
			Weight: eval.HandlerWeight,
		}, nil
	case "process.args_truncated":
		return &eval.BoolEvaluator{
			EvalFnc: func(ctx *eval.Context) bool {
				event := GetEvent(ctx)
				return event.ResolveProcessArgsTruncated(&event.ProcessContext.Process)
			},
			Field:  field,
			Weight: eval.HandlerWeight,
		}, nil
	case "process.argv":
		return &eval.StringArrayEvaluator{
			EvalFnc: func(ctx *eval.Context) []string {
				event := GetEvent(ctx)
				return event.ResolveProcessArgv(&event.ProcessContext.Process)
			},
			Field:  field,
			Weight: 100 * eval.HandlerWeight,
		}, nil
	case "process.argv0":
		return &eval.StringEvaluator{
			EvalFnc: func(ctx *eval.Context) string {
				event := GetEvent(ctx)
				return event.ResolveProcessArgv0(&event.ProcessContext.Process)
			},
			Field:  field,
			Weight: 100 * eval.HandlerWeight,
		}, nil
	case "process.cap_effective":
		return &eval.IntEvaluator{
			EvalFnc: func(ctx *eval.Context) int {
				event := GetEvent(ctx)
				return int(event.ProcessContext.Process.Credentials.CapEffective)
			},
			Field:  field,
			Weight: eval.FunctionWeight,
		}, nil
	case "process.cap_permitted":
		return &eval.IntEvaluator{
			EvalFnc: func(ctx *eval.Context) int {
				event := GetEvent(ctx)
				return int(event.ProcessContext.Process.Credentials.CapPermitted)
			},
			Field:  field,
			Weight: eval.FunctionWeight,
		}, nil
	case "process.comm":
		return &eval.StringEvaluator{
			EvalFnc: func(ctx *eval.Context) string {
				event := GetEvent(ctx)
				return event.ProcessContext.Process.Comm
			},
			Field:  field,
			Weight: eval.FunctionWeight,
		}, nil
	case "process.container.id":
		return &eval.StringEvaluator{
			EvalFnc: func(ctx *eval.Context) string {
				event := GetEvent(ctx)
				return event.ProcessContext.Process.ContainerID
			},
			Field:  field,
			Weight: eval.FunctionWeight,
		}, nil
	case "process.cookie":
		return &eval.IntEvaluator{
			EvalFnc: func(ctx *eval.Context) int {
				event := GetEvent(ctx)
				return int(event.ProcessContext.Process.Cookie)
			},
			Field:  field,
			Weight: eval.FunctionWeight,
		}, nil
	case "process.created_at":
		return &eval.IntEvaluator{
			EvalFnc: func(ctx *eval.Context) int {
				event := GetEvent(ctx)
				return int(event.ResolveProcessCreatedAt(&event.ProcessContext.Process))
			},
			Field:  field,
			Weight: eval.HandlerWeight,
		}, nil
	case "process.egid":
		return &eval.IntEvaluator{
			EvalFnc: func(ctx *eval.Context) int {
				event := GetEvent(ctx)
				return int(event.ProcessContext.Process.Credentials.EGID)
			},
			Field:  field,
			Weight: eval.FunctionWeight,
		}, nil
	case "process.egroup":
		return &eval.StringEvaluator{
			EvalFnc: func(ctx *eval.Context) string {
				event := GetEvent(ctx)
				return event.ProcessContext.Process.Credentials.EGroup
			},
			Field:  field,
			Weight: eval.FunctionWeight,
		}, nil
	case "process.envp":
		return &eval.StringArrayEvaluator{
			EvalFnc: func(ctx *eval.Context) []string {
				event := GetEvent(ctx)
				return event.ResolveProcessEnvp(&event.ProcessContext.Process)
			},
			Field:  field,
			Weight: eval.HandlerWeight,
		}, nil
	case "process.envs":
		return &eval.StringArrayEvaluator{
			EvalFnc: func(ctx *eval.Context) []string {
				event := GetEvent(ctx)
				return event.ResolveProcessEnvs(&event.ProcessContext.Process)
			},
			Field:  field,
			Weight: eval.HandlerWeight,
		}, nil
	case "process.envs_truncated":
		return &eval.BoolEvaluator{
			EvalFnc: func(ctx *eval.Context) bool {
				event := GetEvent(ctx)
				return event.ResolveProcessEnvsTruncated(&event.ProcessContext.Process)
			},
			Field:  field,
			Weight: eval.HandlerWeight,
		}, nil
	case "process.euid":
		return &eval.IntEvaluator{
			EvalFnc: func(ctx *eval.Context) int {
				event := GetEvent(ctx)
				return int(event.ProcessContext.Process.Credentials.EUID)
			},
			Field:  field,
			Weight: eval.FunctionWeight,
		}, nil
	case "process.euser":
		return &eval.StringEvaluator{
			EvalFnc: func(ctx *eval.Context) string {
				event := GetEvent(ctx)
				return event.ProcessContext.Process.Credentials.EUser
			},
			Field:  field,
			Weight: eval.FunctionWeight,
		}, nil
	case "process.file.change_time":
		return &eval.IntEvaluator{
			EvalFnc: func(ctx *eval.Context) int {
				event := GetEvent(ctx)
				return int(event.ProcessContext.Process.FileEvent.FileFields.CTime)
			},
			Field:  field,
			Weight: eval.FunctionWeight,
		}, nil
	case "process.file.filesystem":
		return &eval.StringEvaluator{
			EvalFnc: func(ctx *eval.Context) string {
				event := GetEvent(ctx)
				return event.ResolveFileFilesystem(&event.ProcessContext.Process.FileEvent)
			},
			Field:  field,
			Weight: eval.HandlerWeight,
		}, nil
	case "process.file.gid":
		return &eval.IntEvaluator{
			EvalFnc: func(ctx *eval.Context) int {
				event := GetEvent(ctx)
				return int(event.ProcessContext.Process.FileEvent.FileFields.GID)
			},
			Field:  field,
			Weight: eval.FunctionWeight,
		}, nil
	case "process.file.group":
		return &eval.StringEvaluator{
			EvalFnc: func(ctx *eval.Context) string {
				event := GetEvent(ctx)
				return event.ResolveFileFieldsGroup(&event.ProcessContext.Process.FileEvent.FileFields)
			},
			Field:  field,
			Weight: eval.HandlerWeight,
		}, nil
	case "process.file.in_upper_layer":
		return &eval.BoolEvaluator{
			EvalFnc: func(ctx *eval.Context) bool {
				event := GetEvent(ctx)
				return event.ResolveFileFieldsInUpperLayer(&event.ProcessContext.Process.FileEvent.FileFields)
			},
			Field:  field,
			Weight: eval.HandlerWeight,
		}, nil
	case "process.file.inode":
		return &eval.IntEvaluator{
			EvalFnc: func(ctx *eval.Context) int {
				event := GetEvent(ctx)
				return int(event.ProcessContext.Process.FileEvent.FileFields.Inode)
			},
			Field:  field,
			Weight: eval.FunctionWeight,
		}, nil
	case "process.file.mode":
		return &eval.IntEvaluator{
			EvalFnc: func(ctx *eval.Context) int {
				event := GetEvent(ctx)
				return int(event.ProcessContext.Process.FileEvent.FileFields.Mode)
			},
			Field:  field,
			Weight: eval.FunctionWeight,
		}, nil
	case "process.file.modification_time":
		return &eval.IntEvaluator{
			EvalFnc: func(ctx *eval.Context) int {
				event := GetEvent(ctx)
				return int(event.ProcessContext.Process.FileEvent.FileFields.MTime)
			},
			Field:  field,
			Weight: eval.FunctionWeight,
		}, nil
	case "process.file.mount_id":
		return &eval.IntEvaluator{
			EvalFnc: func(ctx *eval.Context) int {
				event := GetEvent(ctx)
				return int(event.ProcessContext.Process.FileEvent.FileFields.MountID)
			},
			Field:  field,
			Weight: eval.FunctionWeight,
		}, nil
	case "process.file.name":
		return &eval.StringEvaluator{
			OpOverrides: model.ProcessSymlinkBasename,
			EvalFnc: func(ctx *eval.Context) string {
				event := GetEvent(ctx)
				return event.ResolveFileBasename(&event.ProcessContext.Process.FileEvent)
			},
			Field:  field,
			Weight: eval.HandlerWeight,
		}, nil
	case "process.file.path":
		return &eval.StringEvaluator{
			OpOverrides: model.ProcessSymlinkPathname,
			EvalFnc: func(ctx *eval.Context) string {
				event := GetEvent(ctx)
				return event.ResolveFilePath(&event.ProcessContext.Process.FileEvent)
			},
			Field:  field,
			Weight: eval.HandlerWeight,
		}, nil
	case "process.file.rights":
		return &eval.IntEvaluator{
			EvalFnc: func(ctx *eval.Context) int {
				event := GetEvent(ctx)
				return int(event.ResolveRights(&event.ProcessContext.Process.FileEvent.FileFields))
			},
			Field:  field,
			Weight: eval.HandlerWeight,
		}, nil
	case "process.file.uid":
		return &eval.IntEvaluator{
			EvalFnc: func(ctx *eval.Context) int {
				event := GetEvent(ctx)
				return int(event.ProcessContext.Process.FileEvent.FileFields.UID)
			},
			Field:  field,
			Weight: eval.FunctionWeight,
		}, nil
	case "process.file.user":
		return &eval.StringEvaluator{
			EvalFnc: func(ctx *eval.Context) string {
				event := GetEvent(ctx)
				return event.ResolveFileFieldsUser(&event.ProcessContext.Process.FileEvent.FileFields)
			},
			Field:  field,
			Weight: eval.HandlerWeight,
		}, nil
	case "process.fsgid":
		return &eval.IntEvaluator{
			EvalFnc: func(ctx *eval.Context) int {
				event := GetEvent(ctx)
				return int(event.ProcessContext.Process.Credentials.FSGID)
			},
			Field:  field,
			Weight: eval.FunctionWeight,
		}, nil
	case "process.fsgroup":
		return &eval.StringEvaluator{
			EvalFnc: func(ctx *eval.Context) string {
				event := GetEvent(ctx)
				return event.ProcessContext.Process.Credentials.FSGroup
			},
			Field:  field,
			Weight: eval.FunctionWeight,
		}, nil
	case "process.fsuid":
		return &eval.IntEvaluator{
			EvalFnc: func(ctx *eval.Context) int {
				event := GetEvent(ctx)
				return int(event.ProcessContext.Process.Credentials.FSUID)
			},
			Field:  field,
			Weight: eval.FunctionWeight,
		}, nil
	case "process.fsuser":
		return &eval.StringEvaluator{
			EvalFnc: func(ctx *eval.Context) string {
				event := GetEvent(ctx)
				return event.ProcessContext.Process.Credentials.FSUser
			},
			Field:  field,
			Weight: eval.FunctionWeight,
		}, nil
	case "process.gid":
		return &eval.IntEvaluator{
			EvalFnc: func(ctx *eval.Context) int {
				event := GetEvent(ctx)
				return int(event.ProcessContext.Process.Credentials.GID)
			},
			Field:  field,
			Weight: eval.FunctionWeight,
		}, nil
	case "process.group":
		return &eval.StringEvaluator{
			EvalFnc: func(ctx *eval.Context) string {
				event := GetEvent(ctx)
				return event.ProcessContext.Process.Credentials.Group
			},
			Field:  field,
			Weight: eval.FunctionWeight,
		}, nil
	case "process.is_thread":
		return &eval.BoolEvaluator{
			EvalFnc: func(ctx *eval.Context) bool {
				event := GetEvent(ctx)
				return event.ProcessContext.Process.IsThread
			},
			Field:  field,
			Weight: eval.FunctionWeight,
		}, nil
	case "process.pid":
		return &eval.IntEvaluator{
			EvalFnc: func(ctx *eval.Context) int {
				event := GetEvent(ctx)
				return int(event.ProcessContext.Process.PIDContext.Pid)
			},
			Field:  field,
			Weight: eval.FunctionWeight,
		}, nil
	case "process.ppid":
		return &eval.IntEvaluator{
			EvalFnc: func(ctx *eval.Context) int {
				event := GetEvent(ctx)
				return int(event.ProcessContext.Process.PPid)
			},
			Field:  field,
			Weight: eval.FunctionWeight,
		}, nil
	case "process.tid":
		return &eval.IntEvaluator{
			EvalFnc: func(ctx *eval.Context) int {
				event := GetEvent(ctx)
				return int(event.ProcessContext.Process.PIDContext.Tid)
			},
			Field:  field,
			Weight: eval.FunctionWeight,
		}, nil
	case "process.tty_name":
		return &eval.StringEvaluator{
			EvalFnc: func(ctx *eval.Context) string {
				event := GetEvent(ctx)
				return event.ProcessContext.Process.TTYName
			},
			Field:  field,
			Weight: eval.FunctionWeight,
		}, nil
	case "process.uid":
		return &eval.IntEvaluator{
			EvalFnc: func(ctx *eval.Context) int {
				event := GetEvent(ctx)
				return int(event.ProcessContext.Process.Credentials.UID)
			},
			Field:  field,
			Weight: eval.FunctionWeight,
		}, nil
	case "process.user":
		return &eval.StringEvaluator{
			EvalFnc: func(ctx *eval.Context) string {
				event := GetEvent(ctx)
				return event.ProcessContext.Process.Credentials.User
			},
			Field:  field,
			Weight: eval.FunctionWeight,
		}, nil
	case "ptrace.request":
		return &eval.IntEvaluator{
			EvalFnc: func(ctx *eval.Context) int {
				event := GetEvent(ctx)
				return int(event.PTrace.Request)
			},
			Field:  field,
			Weight: eval.FunctionWeight,
		}, nil
	case "ptrace.retval":
		return &eval.IntEvaluator{
			EvalFnc: func(ctx *eval.Context) int {
				event := GetEvent(ctx)
				return int(event.PTrace.SyscallEvent.Retval)
			},
			Field:  field,
			Weight: eval.FunctionWeight,
		}, nil
	case "ptrace.tracee.ancestors.args":
		return &eval.StringArrayEvaluator{
			EvalFnc: func(ctx *eval.Context) []string {
				if ptr := ctx.Cache[field]; ptr != nil {
					if result := (*[]string)(ptr); result != nil {
						return *result
					}
				}
				var results []string
				iterator := &model.ProcessAncestorsIterator{}
				value := iterator.Front(ctx)
				for value != nil {
					element := (*model.ProcessCacheEntry)(value)
					event := GetEvent(ctx)
					result := event.ResolveProcessArgs(&element.ProcessContext.Process)
					results = append(results, result)
					value = iterator.Next()
				}
				ctx.Cache[field] = unsafe.Pointer(&results)
				return results
			}, Field: field,
			Weight: 100 * eval.IteratorWeight,
		}, nil
	case "ptrace.tracee.ancestors.args_flags":
		return &eval.StringArrayEvaluator{
			EvalFnc: func(ctx *eval.Context) []string {
				if ptr := ctx.Cache[field]; ptr != nil {
					if result := (*[]string)(ptr); result != nil {
						return *result
					}
				}
				var results []string
				iterator := &model.ProcessAncestorsIterator{}
				value := iterator.Front(ctx)
				for value != nil {
					element := (*model.ProcessCacheEntry)(value)
					event := GetEvent(ctx)
					result := event.ResolveProcessArgsFlags(&element.ProcessContext.Process)
					results = append(results, result...)
					value = iterator.Next()
				}
				ctx.Cache[field] = unsafe.Pointer(&results)
				return results
			}, Field: field,
			Weight: eval.IteratorWeight,
		}, nil
	case "ptrace.tracee.ancestors.args_options":
		return &eval.StringArrayEvaluator{
			EvalFnc: func(ctx *eval.Context) []string {
				if ptr := ctx.Cache[field]; ptr != nil {
					if result := (*[]string)(ptr); result != nil {
						return *result
					}
				}
				var results []string
				iterator := &model.ProcessAncestorsIterator{}
				value := iterator.Front(ctx)
				for value != nil {
					element := (*model.ProcessCacheEntry)(value)
					event := GetEvent(ctx)
					result := event.ResolveProcessArgsOptions(&element.ProcessContext.Process)
					results = append(results, result...)
					value = iterator.Next()
				}
				ctx.Cache[field] = unsafe.Pointer(&results)
				return results
			}, Field: field,
			Weight: eval.IteratorWeight,
		}, nil
	case "ptrace.tracee.ancestors.args_truncated":
		return &eval.BoolArrayEvaluator{
			EvalFnc: func(ctx *eval.Context) []bool {
				if ptr := ctx.Cache[field]; ptr != nil {
					if result := (*[]bool)(ptr); result != nil {
						return *result
					}
				}
				var results []bool
				iterator := &model.ProcessAncestorsIterator{}
				value := iterator.Front(ctx)
				for value != nil {
					element := (*model.ProcessCacheEntry)(value)
					event := GetEvent(ctx)
					result := event.ResolveProcessArgsTruncated(&element.ProcessContext.Process)
					results = append(results, result)
					value = iterator.Next()
				}
				ctx.Cache[field] = unsafe.Pointer(&results)
				return results
			}, Field: field,
			Weight: eval.IteratorWeight,
		}, nil
	case "ptrace.tracee.ancestors.argv":
		return &eval.StringArrayEvaluator{
			EvalFnc: func(ctx *eval.Context) []string {
				if ptr := ctx.Cache[field]; ptr != nil {
					if result := (*[]string)(ptr); result != nil {
						return *result
					}
				}
				var results []string
				iterator := &model.ProcessAncestorsIterator{}
				value := iterator.Front(ctx)
				for value != nil {
					element := (*model.ProcessCacheEntry)(value)
					event := GetEvent(ctx)
					result := event.ResolveProcessArgv(&element.ProcessContext.Process)
					results = append(results, result...)
					value = iterator.Next()
				}
				ctx.Cache[field] = unsafe.Pointer(&results)
				return results
			}, Field: field,
			Weight: 100 * eval.IteratorWeight,
		}, nil
	case "ptrace.tracee.ancestors.argv0":
		return &eval.StringArrayEvaluator{
			EvalFnc: func(ctx *eval.Context) []string {
				if ptr := ctx.Cache[field]; ptr != nil {
					if result := (*[]string)(ptr); result != nil {
						return *result
					}
				}
				var results []string
				iterator := &model.ProcessAncestorsIterator{}
				value := iterator.Front(ctx)
				for value != nil {
					element := (*model.ProcessCacheEntry)(value)
					event := GetEvent(ctx)
					result := event.ResolveProcessArgv0(&element.ProcessContext.Process)
					results = append(results, result)
					value = iterator.Next()
				}
				ctx.Cache[field] = unsafe.Pointer(&results)
				return results
			}, Field: field,
			Weight: 100 * eval.IteratorWeight,
		}, nil
	case "ptrace.tracee.ancestors.cap_effective":
		return &eval.IntArrayEvaluator{
			EvalFnc: func(ctx *eval.Context) []int {
				if ptr := ctx.Cache[field]; ptr != nil {
					if result := (*[]int)(ptr); result != nil {
						return *result
					}
				}
				var results []int
				iterator := &model.ProcessAncestorsIterator{}
				value := iterator.Front(ctx)
				for value != nil {
					element := (*model.ProcessCacheEntry)(value)
					result := int(element.ProcessContext.Process.Credentials.CapEffective)
					results = append(results, result)
					value = iterator.Next()
				}
				ctx.Cache[field] = unsafe.Pointer(&results)
				return results
			}, Field: field,
			Weight: eval.IteratorWeight,
		}, nil
	case "ptrace.tracee.ancestors.cap_permitted":
		return &eval.IntArrayEvaluator{
			EvalFnc: func(ctx *eval.Context) []int {
				if ptr := ctx.Cache[field]; ptr != nil {
					if result := (*[]int)(ptr); result != nil {
						return *result
					}
				}
				var results []int
				iterator := &model.ProcessAncestorsIterator{}
				value := iterator.Front(ctx)
				for value != nil {
					element := (*model.ProcessCacheEntry)(value)
					result := int(element.ProcessContext.Process.Credentials.CapPermitted)
					results = append(results, result)
					value = iterator.Next()
				}
				ctx.Cache[field] = unsafe.Pointer(&results)
				return results
			}, Field: field,
			Weight: eval.IteratorWeight,
		}, nil
	case "ptrace.tracee.ancestors.comm":
		return &eval.StringArrayEvaluator{
			EvalFnc: func(ctx *eval.Context) []string {
				if ptr := ctx.Cache[field]; ptr != nil {
					if result := (*[]string)(ptr); result != nil {
						return *result
					}
				}
				var results []string
				iterator := &model.ProcessAncestorsIterator{}
				value := iterator.Front(ctx)
				for value != nil {
					element := (*model.ProcessCacheEntry)(value)
					result := element.ProcessContext.Process.Comm
					results = append(results, result)
					value = iterator.Next()
				}
				ctx.Cache[field] = unsafe.Pointer(&results)
				return results
			}, Field: field,
			Weight: eval.IteratorWeight,
		}, nil
	case "ptrace.tracee.ancestors.container.id":
		return &eval.StringArrayEvaluator{
			EvalFnc: func(ctx *eval.Context) []string {
				if ptr := ctx.Cache[field]; ptr != nil {
					if result := (*[]string)(ptr); result != nil {
						return *result
					}
				}
				var results []string
				iterator := &model.ProcessAncestorsIterator{}
				value := iterator.Front(ctx)
				for value != nil {
					element := (*model.ProcessCacheEntry)(value)
					result := element.ProcessContext.Process.ContainerID
					results = append(results, result)
					value = iterator.Next()
				}
				ctx.Cache[field] = unsafe.Pointer(&results)
				return results
			}, Field: field,
			Weight: eval.IteratorWeight,
		}, nil
	case "ptrace.tracee.ancestors.cookie":
		return &eval.IntArrayEvaluator{
			EvalFnc: func(ctx *eval.Context) []int {
				if ptr := ctx.Cache[field]; ptr != nil {
					if result := (*[]int)(ptr); result != nil {
						return *result
					}
				}
				var results []int
				iterator := &model.ProcessAncestorsIterator{}
				value := iterator.Front(ctx)
				for value != nil {
					element := (*model.ProcessCacheEntry)(value)
					result := int(element.ProcessContext.Process.Cookie)
					results = append(results, result)
					value = iterator.Next()
				}
				ctx.Cache[field] = unsafe.Pointer(&results)
				return results
			}, Field: field,
			Weight: eval.IteratorWeight,
		}, nil
	case "ptrace.tracee.ancestors.created_at":
		return &eval.IntArrayEvaluator{
			EvalFnc: func(ctx *eval.Context) []int {
				if ptr := ctx.Cache[field]; ptr != nil {
					if result := (*[]int)(ptr); result != nil {
						return *result
					}
				}
				var results []int
				iterator := &model.ProcessAncestorsIterator{}
				value := iterator.Front(ctx)
				for value != nil {
					element := (*model.ProcessCacheEntry)(value)
					event := GetEvent(ctx)
					result := int(event.ResolveProcessCreatedAt(&element.ProcessContext.Process))
					results = append(results, result)
					value = iterator.Next()
				}
				ctx.Cache[field] = unsafe.Pointer(&results)
				return results
			}, Field: field,
			Weight: eval.IteratorWeight,
		}, nil
	case "ptrace.tracee.ancestors.egid":
		return &eval.IntArrayEvaluator{
			EvalFnc: func(ctx *eval.Context) []int {
				if ptr := ctx.Cache[field]; ptr != nil {
					if result := (*[]int)(ptr); result != nil {
						return *result
					}
				}
				var results []int
				iterator := &model.ProcessAncestorsIterator{}
				value := iterator.Front(ctx)
				for value != nil {
					element := (*model.ProcessCacheEntry)(value)
					result := int(element.ProcessContext.Process.Credentials.EGID)
					results = append(results, result)
					value = iterator.Next()
				}
				ctx.Cache[field] = unsafe.Pointer(&results)
				return results
			}, Field: field,
			Weight: eval.IteratorWeight,
		}, nil
	case "ptrace.tracee.ancestors.egroup":
		return &eval.StringArrayEvaluator{
			EvalFnc: func(ctx *eval.Context) []string {
				if ptr := ctx.Cache[field]; ptr != nil {
					if result := (*[]string)(ptr); result != nil {
						return *result
					}
				}
				var results []string
				iterator := &model.ProcessAncestorsIterator{}
				value := iterator.Front(ctx)
				for value != nil {
					element := (*model.ProcessCacheEntry)(value)
					result := element.ProcessContext.Process.Credentials.EGroup
					results = append(results, result)
					value = iterator.Next()
				}
				ctx.Cache[field] = unsafe.Pointer(&results)
				return results
			}, Field: field,
			Weight: eval.IteratorWeight,
		}, nil
	case "ptrace.tracee.ancestors.envp":
		return &eval.StringArrayEvaluator{
			EvalFnc: func(ctx *eval.Context) []string {
				if ptr := ctx.Cache[field]; ptr != nil {
					if result := (*[]string)(ptr); result != nil {
						return *result
					}
				}
				var results []string
				iterator := &model.ProcessAncestorsIterator{}
				value := iterator.Front(ctx)
				for value != nil {
					element := (*model.ProcessCacheEntry)(value)
					event := GetEvent(ctx)
					result := event.ResolveProcessEnvp(&element.ProcessContext.Process)
					results = append(results, result...)
					value = iterator.Next()
				}
				ctx.Cache[field] = unsafe.Pointer(&results)
				return results
			}, Field: field,
			Weight: eval.IteratorWeight,
		}, nil
	case "ptrace.tracee.ancestors.envs":
		return &eval.StringArrayEvaluator{
			EvalFnc: func(ctx *eval.Context) []string {
				if ptr := ctx.Cache[field]; ptr != nil {
					if result := (*[]string)(ptr); result != nil {
						return *result
					}
				}
				var results []string
				iterator := &model.ProcessAncestorsIterator{}
				value := iterator.Front(ctx)
				for value != nil {
					element := (*model.ProcessCacheEntry)(value)
					event := GetEvent(ctx)
					result := event.ResolveProcessEnvs(&element.ProcessContext.Process)
					results = append(results, result...)
					value = iterator.Next()
				}
				ctx.Cache[field] = unsafe.Pointer(&results)
				return results
			}, Field: field,
			Weight: eval.IteratorWeight,
		}, nil
	case "ptrace.tracee.ancestors.envs_truncated":
		return &eval.BoolArrayEvaluator{
			EvalFnc: func(ctx *eval.Context) []bool {
				if ptr := ctx.Cache[field]; ptr != nil {
					if result := (*[]bool)(ptr); result != nil {
						return *result
					}
				}
				var results []bool
				iterator := &model.ProcessAncestorsIterator{}
				value := iterator.Front(ctx)
				for value != nil {
					element := (*model.ProcessCacheEntry)(value)
					event := GetEvent(ctx)
					result := event.ResolveProcessEnvsTruncated(&element.ProcessContext.Process)
					results = append(results, result)
					value = iterator.Next()
				}
				ctx.Cache[field] = unsafe.Pointer(&results)
				return results
			}, Field: field,
			Weight: eval.IteratorWeight,
		}, nil
	case "ptrace.tracee.ancestors.euid":
		return &eval.IntArrayEvaluator{
			EvalFnc: func(ctx *eval.Context) []int {
				if ptr := ctx.Cache[field]; ptr != nil {
					if result := (*[]int)(ptr); result != nil {
						return *result
					}
				}
				var results []int
				iterator := &model.ProcessAncestorsIterator{}
				value := iterator.Front(ctx)
				for value != nil {
					element := (*model.ProcessCacheEntry)(value)
					result := int(element.ProcessContext.Process.Credentials.EUID)
					results = append(results, result)
					value = iterator.Next()
				}
				ctx.Cache[field] = unsafe.Pointer(&results)
				return results
			}, Field: field,
			Weight: eval.IteratorWeight,
		}, nil
	case "ptrace.tracee.ancestors.euser":
		return &eval.StringArrayEvaluator{
			EvalFnc: func(ctx *eval.Context) []string {
				if ptr := ctx.Cache[field]; ptr != nil {
					if result := (*[]string)(ptr); result != nil {
						return *result
					}
				}
				var results []string
				iterator := &model.ProcessAncestorsIterator{}
				value := iterator.Front(ctx)
				for value != nil {
					element := (*model.ProcessCacheEntry)(value)
					result := element.ProcessContext.Process.Credentials.EUser
					results = append(results, result)
					value = iterator.Next()
				}
				ctx.Cache[field] = unsafe.Pointer(&results)
				return results
			}, Field: field,
			Weight: eval.IteratorWeight,
		}, nil
	case "ptrace.tracee.ancestors.file.change_time":
		return &eval.IntArrayEvaluator{
			EvalFnc: func(ctx *eval.Context) []int {
				if ptr := ctx.Cache[field]; ptr != nil {
					if result := (*[]int)(ptr); result != nil {
						return *result
					}
				}
				var results []int
				iterator := &model.ProcessAncestorsIterator{}
				value := iterator.Front(ctx)
				for value != nil {
					element := (*model.ProcessCacheEntry)(value)
					result := int(element.ProcessContext.Process.FileEvent.FileFields.CTime)
					results = append(results, result)
					value = iterator.Next()
				}
				ctx.Cache[field] = unsafe.Pointer(&results)
				return results
			}, Field: field,
			Weight: eval.IteratorWeight,
		}, nil
	case "ptrace.tracee.ancestors.file.filesystem":
		return &eval.StringArrayEvaluator{
			EvalFnc: func(ctx *eval.Context) []string {
				if ptr := ctx.Cache[field]; ptr != nil {
					if result := (*[]string)(ptr); result != nil {
						return *result
					}
				}
				var results []string
				iterator := &model.ProcessAncestorsIterator{}
				value := iterator.Front(ctx)
				for value != nil {
					element := (*model.ProcessCacheEntry)(value)
					event := GetEvent(ctx)
					result := event.ResolveFileFilesystem(&element.ProcessContext.Process.FileEvent)
					results = append(results, result)
					value = iterator.Next()
				}
				ctx.Cache[field] = unsafe.Pointer(&results)
				return results
			}, Field: field,
			Weight: eval.IteratorWeight,
		}, nil
	case "ptrace.tracee.ancestors.file.gid":
		return &eval.IntArrayEvaluator{
			EvalFnc: func(ctx *eval.Context) []int {
				if ptr := ctx.Cache[field]; ptr != nil {
					if result := (*[]int)(ptr); result != nil {
						return *result
					}
				}
				var results []int
				iterator := &model.ProcessAncestorsIterator{}
				value := iterator.Front(ctx)
				for value != nil {
					element := (*model.ProcessCacheEntry)(value)
					result := int(element.ProcessContext.Process.FileEvent.FileFields.GID)
					results = append(results, result)
					value = iterator.Next()
				}
				ctx.Cache[field] = unsafe.Pointer(&results)
				return results
			}, Field: field,
			Weight: eval.IteratorWeight,
		}, nil
	case "ptrace.tracee.ancestors.file.group":
		return &eval.StringArrayEvaluator{
			EvalFnc: func(ctx *eval.Context) []string {
				if ptr := ctx.Cache[field]; ptr != nil {
					if result := (*[]string)(ptr); result != nil {
						return *result
					}
				}
				var results []string
				iterator := &model.ProcessAncestorsIterator{}
				value := iterator.Front(ctx)
				for value != nil {
					element := (*model.ProcessCacheEntry)(value)
					event := GetEvent(ctx)
					result := event.ResolveFileFieldsGroup(&element.ProcessContext.Process.FileEvent.FileFields)
					results = append(results, result)
					value = iterator.Next()
				}
				ctx.Cache[field] = unsafe.Pointer(&results)
				return results
			}, Field: field,
			Weight: eval.IteratorWeight,
		}, nil
	case "ptrace.tracee.ancestors.file.in_upper_layer":
		return &eval.BoolArrayEvaluator{
			EvalFnc: func(ctx *eval.Context) []bool {
				if ptr := ctx.Cache[field]; ptr != nil {
					if result := (*[]bool)(ptr); result != nil {
						return *result
					}
				}
				var results []bool
				iterator := &model.ProcessAncestorsIterator{}
				value := iterator.Front(ctx)
				for value != nil {
					element := (*model.ProcessCacheEntry)(value)
					event := GetEvent(ctx)
					result := event.ResolveFileFieldsInUpperLayer(&element.ProcessContext.Process.FileEvent.FileFields)
					results = append(results, result)
					value = iterator.Next()
				}
				ctx.Cache[field] = unsafe.Pointer(&results)
				return results
			}, Field: field,
			Weight: eval.IteratorWeight,
		}, nil
	case "ptrace.tracee.ancestors.file.inode":
		return &eval.IntArrayEvaluator{
			EvalFnc: func(ctx *eval.Context) []int {
				if ptr := ctx.Cache[field]; ptr != nil {
					if result := (*[]int)(ptr); result != nil {
						return *result
					}
				}
				var results []int
				iterator := &model.ProcessAncestorsIterator{}
				value := iterator.Front(ctx)
				for value != nil {
					element := (*model.ProcessCacheEntry)(value)
					result := int(element.ProcessContext.Process.FileEvent.FileFields.Inode)
					results = append(results, result)
					value = iterator.Next()
				}
				ctx.Cache[field] = unsafe.Pointer(&results)
				return results
			}, Field: field,
			Weight: eval.IteratorWeight,
		}, nil
	case "ptrace.tracee.ancestors.file.mode":
		return &eval.IntArrayEvaluator{
			EvalFnc: func(ctx *eval.Context) []int {
				if ptr := ctx.Cache[field]; ptr != nil {
					if result := (*[]int)(ptr); result != nil {
						return *result
					}
				}
				var results []int
				iterator := &model.ProcessAncestorsIterator{}
				value := iterator.Front(ctx)
				for value != nil {
					element := (*model.ProcessCacheEntry)(value)
					result := int(element.ProcessContext.Process.FileEvent.FileFields.Mode)
					results = append(results, result)
					value = iterator.Next()
				}
				ctx.Cache[field] = unsafe.Pointer(&results)
				return results
			}, Field: field,
			Weight: eval.IteratorWeight,
		}, nil
	case "ptrace.tracee.ancestors.file.modification_time":
		return &eval.IntArrayEvaluator{
			EvalFnc: func(ctx *eval.Context) []int {
				if ptr := ctx.Cache[field]; ptr != nil {
					if result := (*[]int)(ptr); result != nil {
						return *result
					}
				}
				var results []int
				iterator := &model.ProcessAncestorsIterator{}
				value := iterator.Front(ctx)
				for value != nil {
					element := (*model.ProcessCacheEntry)(value)
					result := int(element.ProcessContext.Process.FileEvent.FileFields.MTime)
					results = append(results, result)
					value = iterator.Next()
				}
				ctx.Cache[field] = unsafe.Pointer(&results)
				return results
			}, Field: field,
			Weight: eval.IteratorWeight,
		}, nil
	case "ptrace.tracee.ancestors.file.mount_id":
		return &eval.IntArrayEvaluator{
			EvalFnc: func(ctx *eval.Context) []int {
				if ptr := ctx.Cache[field]; ptr != nil {
					if result := (*[]int)(ptr); result != nil {
						return *result
					}
				}
				var results []int
				iterator := &model.ProcessAncestorsIterator{}
				value := iterator.Front(ctx)
				for value != nil {
					element := (*model.ProcessCacheEntry)(value)
					result := int(element.ProcessContext.Process.FileEvent.FileFields.MountID)
					results = append(results, result)
					value = iterator.Next()
				}
				ctx.Cache[field] = unsafe.Pointer(&results)
				return results
			}, Field: field,
			Weight: eval.IteratorWeight,
		}, nil
	case "ptrace.tracee.ancestors.file.name":
		return &eval.StringArrayEvaluator{
			OpOverrides: model.ProcessSymlinkBasename,
			EvalFnc: func(ctx *eval.Context) []string {
				if ptr := ctx.Cache[field]; ptr != nil {
					if result := (*[]string)(ptr); result != nil {
						return *result
					}
				}
				var results []string
				iterator := &model.ProcessAncestorsIterator{}
				value := iterator.Front(ctx)
				for value != nil {
					element := (*model.ProcessCacheEntry)(value)
					event := GetEvent(ctx)
					result := event.ResolveFileBasename(&element.ProcessContext.Process.FileEvent)
					results = append(results, result)
					value = iterator.Next()
				}
				ctx.Cache[field] = unsafe.Pointer(&results)
				return results
			}, Field: field,
			Weight: eval.IteratorWeight,
		}, nil
	case "ptrace.tracee.ancestors.file.path":
		return &eval.StringArrayEvaluator{
			OpOverrides: model.ProcessSymlinkPathname,
			EvalFnc: func(ctx *eval.Context) []string {
				if ptr := ctx.Cache[field]; ptr != nil {
					if result := (*[]string)(ptr); result != nil {
						return *result
					}
				}
				var results []string
				iterator := &model.ProcessAncestorsIterator{}
				value := iterator.Front(ctx)
				for value != nil {
					element := (*model.ProcessCacheEntry)(value)
					event := GetEvent(ctx)
					result := event.ResolveFilePath(&element.ProcessContext.Process.FileEvent)
					results = append(results, result)
					value = iterator.Next()
				}
				ctx.Cache[field] = unsafe.Pointer(&results)
				return results
			}, Field: field,
			Weight: eval.IteratorWeight,
		}, nil
	case "ptrace.tracee.ancestors.file.rights":
		return &eval.IntArrayEvaluator{
			EvalFnc: func(ctx *eval.Context) []int {
				if ptr := ctx.Cache[field]; ptr != nil {
					if result := (*[]int)(ptr); result != nil {
						return *result
					}
				}
				var results []int
				iterator := &model.ProcessAncestorsIterator{}
				value := iterator.Front(ctx)
				for value != nil {
					element := (*model.ProcessCacheEntry)(value)
					event := GetEvent(ctx)
					result := int(event.ResolveRights(&element.ProcessContext.Process.FileEvent.FileFields))
					results = append(results, result)
					value = iterator.Next()
				}
				ctx.Cache[field] = unsafe.Pointer(&results)
				return results
			}, Field: field,
			Weight: eval.IteratorWeight,
		}, nil
	case "ptrace.tracee.ancestors.file.uid":
		return &eval.IntArrayEvaluator{
			EvalFnc: func(ctx *eval.Context) []int {
				if ptr := ctx.Cache[field]; ptr != nil {
					if result := (*[]int)(ptr); result != nil {
						return *result
					}
				}
				var results []int
				iterator := &model.ProcessAncestorsIterator{}
				value := iterator.Front(ctx)
				for value != nil {
					element := (*model.ProcessCacheEntry)(value)
					result := int(element.ProcessContext.Process.FileEvent.FileFields.UID)
					results = append(results, result)
					value = iterator.Next()
				}
				ctx.Cache[field] = unsafe.Pointer(&results)
				return results
			}, Field: field,
			Weight: eval.IteratorWeight,
		}, nil
	case "ptrace.tracee.ancestors.file.user":
		return &eval.StringArrayEvaluator{
			EvalFnc: func(ctx *eval.Context) []string {
				if ptr := ctx.Cache[field]; ptr != nil {
					if result := (*[]string)(ptr); result != nil {
						return *result
					}
				}
				var results []string
				iterator := &model.ProcessAncestorsIterator{}
				value := iterator.Front(ctx)
				for value != nil {
					element := (*model.ProcessCacheEntry)(value)
					event := GetEvent(ctx)
					result := event.ResolveFileFieldsUser(&element.ProcessContext.Process.FileEvent.FileFields)
					results = append(results, result)
					value = iterator.Next()
				}
				ctx.Cache[field] = unsafe.Pointer(&results)
				return results
			}, Field: field,
			Weight: eval.IteratorWeight,
		}, nil
	case "ptrace.tracee.ancestors.fsgid":
		return &eval.IntArrayEvaluator{
			EvalFnc: func(ctx *eval.Context) []int {
				if ptr := ctx.Cache[field]; ptr != nil {
					if result := (*[]int)(ptr); result != nil {
						return *result
					}
				}
				var results []int
				iterator := &model.ProcessAncestorsIterator{}
				value := iterator.Front(ctx)
				for value != nil {
					element := (*model.ProcessCacheEntry)(value)
					result := int(element.ProcessContext.Process.Credentials.FSGID)
					results = append(results, result)
					value = iterator.Next()
				}
				ctx.Cache[field] = unsafe.Pointer(&results)
				return results
			}, Field: field,
			Weight: eval.IteratorWeight,
		}, nil
	case "ptrace.tracee.ancestors.fsgroup":
		return &eval.StringArrayEvaluator{
			EvalFnc: func(ctx *eval.Context) []string {
				if ptr := ctx.Cache[field]; ptr != nil {
					if result := (*[]string)(ptr); result != nil {
						return *result
					}
				}
				var results []string
				iterator := &model.ProcessAncestorsIterator{}
				value := iterator.Front(ctx)
				for value != nil {
					element := (*model.ProcessCacheEntry)(value)
					result := element.ProcessContext.Process.Credentials.FSGroup
					results = append(results, result)
					value = iterator.Next()
				}
				ctx.Cache[field] = unsafe.Pointer(&results)
				return results
			}, Field: field,
			Weight: eval.IteratorWeight,
		}, nil
	case "ptrace.tracee.ancestors.fsuid":
		return &eval.IntArrayEvaluator{
			EvalFnc: func(ctx *eval.Context) []int {
				if ptr := ctx.Cache[field]; ptr != nil {
					if result := (*[]int)(ptr); result != nil {
						return *result
					}
				}
				var results []int
				iterator := &model.ProcessAncestorsIterator{}
				value := iterator.Front(ctx)
				for value != nil {
					element := (*model.ProcessCacheEntry)(value)
					result := int(element.ProcessContext.Process.Credentials.FSUID)
					results = append(results, result)
					value = iterator.Next()
				}
				ctx.Cache[field] = unsafe.Pointer(&results)
				return results
			}, Field: field,
			Weight: eval.IteratorWeight,
		}, nil
	case "ptrace.tracee.ancestors.fsuser":
		return &eval.StringArrayEvaluator{
			EvalFnc: func(ctx *eval.Context) []string {
				if ptr := ctx.Cache[field]; ptr != nil {
					if result := (*[]string)(ptr); result != nil {
						return *result
					}
				}
				var results []string
				iterator := &model.ProcessAncestorsIterator{}
				value := iterator.Front(ctx)
				for value != nil {
					element := (*model.ProcessCacheEntry)(value)
					result := element.ProcessContext.Process.Credentials.FSUser
					results = append(results, result)
					value = iterator.Next()
				}
				ctx.Cache[field] = unsafe.Pointer(&results)
				return results
			}, Field: field,
			Weight: eval.IteratorWeight,
		}, nil
	case "ptrace.tracee.ancestors.gid":
		return &eval.IntArrayEvaluator{
			EvalFnc: func(ctx *eval.Context) []int {
				if ptr := ctx.Cache[field]; ptr != nil {
					if result := (*[]int)(ptr); result != nil {
						return *result
					}
				}
				var results []int
				iterator := &model.ProcessAncestorsIterator{}
				value := iterator.Front(ctx)
				for value != nil {
					element := (*model.ProcessCacheEntry)(value)
					result := int(element.ProcessContext.Process.Credentials.GID)
					results = append(results, result)
					value = iterator.Next()
				}
				ctx.Cache[field] = unsafe.Pointer(&results)
				return results
			}, Field: field,
			Weight: eval.IteratorWeight,
		}, nil
	case "ptrace.tracee.ancestors.group":
		return &eval.StringArrayEvaluator{
			EvalFnc: func(ctx *eval.Context) []string {
				if ptr := ctx.Cache[field]; ptr != nil {
					if result := (*[]string)(ptr); result != nil {
						return *result
					}
				}
				var results []string
				iterator := &model.ProcessAncestorsIterator{}
				value := iterator.Front(ctx)
				for value != nil {
					element := (*model.ProcessCacheEntry)(value)
					result := element.ProcessContext.Process.Credentials.Group
					results = append(results, result)
					value = iterator.Next()
				}
				ctx.Cache[field] = unsafe.Pointer(&results)
				return results
			}, Field: field,
			Weight: eval.IteratorWeight,
		}, nil
	case "ptrace.tracee.ancestors.is_thread":
		return &eval.BoolArrayEvaluator{
			EvalFnc: func(ctx *eval.Context) []bool {
				if ptr := ctx.Cache[field]; ptr != nil {
					if result := (*[]bool)(ptr); result != nil {
						return *result
					}
				}
				var results []bool
				iterator := &model.ProcessAncestorsIterator{}
				value := iterator.Front(ctx)
				for value != nil {
					element := (*model.ProcessCacheEntry)(value)
					result := element.ProcessContext.Process.IsThread
					results = append(results, result)
					value = iterator.Next()
				}
				ctx.Cache[field] = unsafe.Pointer(&results)
				return results
			}, Field: field,
			Weight: eval.IteratorWeight,
		}, nil
	case "ptrace.tracee.ancestors.pid":
		return &eval.IntArrayEvaluator{
			EvalFnc: func(ctx *eval.Context) []int {
				if ptr := ctx.Cache[field]; ptr != nil {
					if result := (*[]int)(ptr); result != nil {
						return *result
					}
				}
				var results []int
				iterator := &model.ProcessAncestorsIterator{}
				value := iterator.Front(ctx)
				for value != nil {
					element := (*model.ProcessCacheEntry)(value)
					result := int(element.ProcessContext.Process.PIDContext.Pid)
					results = append(results, result)
					value = iterator.Next()
				}
				ctx.Cache[field] = unsafe.Pointer(&results)
				return results
			}, Field: field,
			Weight: eval.IteratorWeight,
		}, nil
	case "ptrace.tracee.ancestors.ppid":
		return &eval.IntArrayEvaluator{
			EvalFnc: func(ctx *eval.Context) []int {
				if ptr := ctx.Cache[field]; ptr != nil {
					if result := (*[]int)(ptr); result != nil {
						return *result
					}
				}
				var results []int
				iterator := &model.ProcessAncestorsIterator{}
				value := iterator.Front(ctx)
				for value != nil {
					element := (*model.ProcessCacheEntry)(value)
					result := int(element.ProcessContext.Process.PPid)
					results = append(results, result)
					value = iterator.Next()
				}
				ctx.Cache[field] = unsafe.Pointer(&results)
				return results
			}, Field: field,
			Weight: eval.IteratorWeight,
		}, nil
	case "ptrace.tracee.ancestors.tid":
		return &eval.IntArrayEvaluator{
			EvalFnc: func(ctx *eval.Context) []int {
				if ptr := ctx.Cache[field]; ptr != nil {
					if result := (*[]int)(ptr); result != nil {
						return *result
					}
				}
				var results []int
				iterator := &model.ProcessAncestorsIterator{}
				value := iterator.Front(ctx)
				for value != nil {
					element := (*model.ProcessCacheEntry)(value)
					result := int(element.ProcessContext.Process.PIDContext.Tid)
					results = append(results, result)
					value = iterator.Next()
				}
				ctx.Cache[field] = unsafe.Pointer(&results)
				return results
			}, Field: field,
			Weight: eval.IteratorWeight,
		}, nil
	case "ptrace.tracee.ancestors.tty_name":
		return &eval.StringArrayEvaluator{
			EvalFnc: func(ctx *eval.Context) []string {
				if ptr := ctx.Cache[field]; ptr != nil {
					if result := (*[]string)(ptr); result != nil {
						return *result
					}
				}
				var results []string
				iterator := &model.ProcessAncestorsIterator{}
				value := iterator.Front(ctx)
				for value != nil {
					element := (*model.ProcessCacheEntry)(value)
					result := element.ProcessContext.Process.TTYName
					results = append(results, result)
					value = iterator.Next()
				}
				ctx.Cache[field] = unsafe.Pointer(&results)
				return results
			}, Field: field,
			Weight: eval.IteratorWeight,
		}, nil
	case "ptrace.tracee.ancestors.uid":
		return &eval.IntArrayEvaluator{
			EvalFnc: func(ctx *eval.Context) []int {
				if ptr := ctx.Cache[field]; ptr != nil {
					if result := (*[]int)(ptr); result != nil {
						return *result
					}
				}
				var results []int
				iterator := &model.ProcessAncestorsIterator{}
				value := iterator.Front(ctx)
				for value != nil {
					element := (*model.ProcessCacheEntry)(value)
					result := int(element.ProcessContext.Process.Credentials.UID)
					results = append(results, result)
					value = iterator.Next()
				}
				ctx.Cache[field] = unsafe.Pointer(&results)
				return results
			}, Field: field,
			Weight: eval.IteratorWeight,
		}, nil
	case "ptrace.tracee.ancestors.user":
		return &eval.StringArrayEvaluator{
			EvalFnc: func(ctx *eval.Context) []string {
				if ptr := ctx.Cache[field]; ptr != nil {
					if result := (*[]string)(ptr); result != nil {
						return *result
					}
				}
				var results []string
				iterator := &model.ProcessAncestorsIterator{}
				value := iterator.Front(ctx)
				for value != nil {
					element := (*model.ProcessCacheEntry)(value)
					result := element.ProcessContext.Process.Credentials.User
					results = append(results, result)
					value = iterator.Next()
				}
				ctx.Cache[field] = unsafe.Pointer(&results)
				return results
			}, Field: field,
			Weight: eval.IteratorWeight,
		}, nil
	case "ptrace.tracee.args":
		return &eval.StringEvaluator{
			EvalFnc: func(ctx *eval.Context) string {
				event := GetEvent(ctx)
				return event.ResolveProcessArgs(&event.PTrace.Tracee.Process)
			},
			Field:  field,
			Weight: 100 * eval.HandlerWeight,
		}, nil
	case "ptrace.tracee.args_flags":
		return &eval.StringArrayEvaluator{
			EvalFnc: func(ctx *eval.Context) []string {
				event := GetEvent(ctx)
				return event.ResolveProcessArgsFlags(&event.PTrace.Tracee.Process)
			},
			Field:  field,
			Weight: eval.HandlerWeight,
		}, nil
	case "ptrace.tracee.args_options":
		return &eval.StringArrayEvaluator{
			EvalFnc: func(ctx *eval.Context) []string {
				event := GetEvent(ctx)
				return event.ResolveProcessArgsOptions(&event.PTrace.Tracee.Process)
			},
			Field:  field,
			Weight: eval.HandlerWeight,
		}, nil
	case "ptrace.tracee.args_truncated":
		return &eval.BoolEvaluator{
			EvalFnc: func(ctx *eval.Context) bool {
				event := GetEvent(ctx)
				return event.ResolveProcessArgsTruncated(&event.PTrace.Tracee.Process)
			},
			Field:  field,
			Weight: eval.HandlerWeight,
		}, nil
	case "ptrace.tracee.argv":
		return &eval.StringArrayEvaluator{
			EvalFnc: func(ctx *eval.Context) []string {
				event := GetEvent(ctx)
				return event.ResolveProcessArgv(&event.PTrace.Tracee.Process)
			},
			Field:  field,
			Weight: 100 * eval.HandlerWeight,
		}, nil
	case "ptrace.tracee.argv0":
		return &eval.StringEvaluator{
			EvalFnc: func(ctx *eval.Context) string {
				event := GetEvent(ctx)
				return event.ResolveProcessArgv0(&event.PTrace.Tracee.Process)
			},
			Field:  field,
			Weight: 100 * eval.HandlerWeight,
		}, nil
	case "ptrace.tracee.cap_effective":
		return &eval.IntEvaluator{
			EvalFnc: func(ctx *eval.Context) int {
				event := GetEvent(ctx)
				return int(event.PTrace.Tracee.Process.Credentials.CapEffective)
			},
			Field:  field,
			Weight: eval.FunctionWeight,
		}, nil
	case "ptrace.tracee.cap_permitted":
		return &eval.IntEvaluator{
			EvalFnc: func(ctx *eval.Context) int {
				event := GetEvent(ctx)
				return int(event.PTrace.Tracee.Process.Credentials.CapPermitted)
			},
			Field:  field,
			Weight: eval.FunctionWeight,
		}, nil
	case "ptrace.tracee.comm":
		return &eval.StringEvaluator{
			EvalFnc: func(ctx *eval.Context) string {
				event := GetEvent(ctx)
				return event.PTrace.Tracee.Process.Comm
			},
			Field:  field,
			Weight: eval.FunctionWeight,
		}, nil
	case "ptrace.tracee.container.id":
		return &eval.StringEvaluator{
			EvalFnc: func(ctx *eval.Context) string {
				event := GetEvent(ctx)
				return event.PTrace.Tracee.Process.ContainerID
			},
			Field:  field,
			Weight: eval.FunctionWeight,
		}, nil
	case "ptrace.tracee.cookie":
		return &eval.IntEvaluator{
			EvalFnc: func(ctx *eval.Context) int {
				event := GetEvent(ctx)
				return int(event.PTrace.Tracee.Process.Cookie)
			},
			Field:  field,
			Weight: eval.FunctionWeight,
		}, nil
	case "ptrace.tracee.created_at":
		return &eval.IntEvaluator{
			EvalFnc: func(ctx *eval.Context) int {
				event := GetEvent(ctx)
				return int(event.ResolveProcessCreatedAt(&event.PTrace.Tracee.Process))
			},
			Field:  field,
			Weight: eval.HandlerWeight,
		}, nil
	case "ptrace.tracee.egid":
		return &eval.IntEvaluator{
			EvalFnc: func(ctx *eval.Context) int {
				event := GetEvent(ctx)
				return int(event.PTrace.Tracee.Process.Credentials.EGID)
			},
			Field:  field,
			Weight: eval.FunctionWeight,
		}, nil
	case "ptrace.tracee.egroup":
		return &eval.StringEvaluator{
			EvalFnc: func(ctx *eval.Context) string {
				event := GetEvent(ctx)
				return event.PTrace.Tracee.Process.Credentials.EGroup
			},
			Field:  field,
			Weight: eval.FunctionWeight,
		}, nil
	case "ptrace.tracee.envp":
		return &eval.StringArrayEvaluator{
			EvalFnc: func(ctx *eval.Context) []string {
				event := GetEvent(ctx)
				return event.ResolveProcessEnvp(&event.PTrace.Tracee.Process)
			},
			Field:  field,
			Weight: eval.HandlerWeight,
		}, nil
	case "ptrace.tracee.envs":
		return &eval.StringArrayEvaluator{
			EvalFnc: func(ctx *eval.Context) []string {
				event := GetEvent(ctx)
				return event.ResolveProcessEnvs(&event.PTrace.Tracee.Process)
			},
			Field:  field,
			Weight: eval.HandlerWeight,
		}, nil
	case "ptrace.tracee.envs_truncated":
		return &eval.BoolEvaluator{
			EvalFnc: func(ctx *eval.Context) bool {
				event := GetEvent(ctx)
				return event.ResolveProcessEnvsTruncated(&event.PTrace.Tracee.Process)
			},
			Field:  field,
			Weight: eval.HandlerWeight,
		}, nil
	case "ptrace.tracee.euid":
		return &eval.IntEvaluator{
			EvalFnc: func(ctx *eval.Context) int {
				event := GetEvent(ctx)
				return int(event.PTrace.Tracee.Process.Credentials.EUID)
			},
			Field:  field,
			Weight: eval.FunctionWeight,
		}, nil
	case "ptrace.tracee.euser":
		return &eval.StringEvaluator{
			EvalFnc: func(ctx *eval.Context) string {
				event := GetEvent(ctx)
				return event.PTrace.Tracee.Process.Credentials.EUser
			},
			Field:  field,
			Weight: eval.FunctionWeight,
		}, nil
	case "ptrace.tracee.file.change_time":
		return &eval.IntEvaluator{
			EvalFnc: func(ctx *eval.Context) int {
				event := GetEvent(ctx)
				return int(event.PTrace.Tracee.Process.FileEvent.FileFields.CTime)
			},
			Field:  field,
			Weight: eval.FunctionWeight,
		}, nil
	case "ptrace.tracee.file.filesystem":
		return &eval.StringEvaluator{
			EvalFnc: func(ctx *eval.Context) string {
				event := GetEvent(ctx)
				return event.ResolveFileFilesystem(&event.PTrace.Tracee.Process.FileEvent)
			},
			Field:  field,
			Weight: eval.HandlerWeight,
		}, nil
	case "ptrace.tracee.file.gid":
		return &eval.IntEvaluator{
			EvalFnc: func(ctx *eval.Context) int {
				event := GetEvent(ctx)
				return int(event.PTrace.Tracee.Process.FileEvent.FileFields.GID)
			},
			Field:  field,
			Weight: eval.FunctionWeight,
		}, nil
	case "ptrace.tracee.file.group":
		return &eval.StringEvaluator{
			EvalFnc: func(ctx *eval.Context) string {
				event := GetEvent(ctx)
				return event.ResolveFileFieldsGroup(&event.PTrace.Tracee.Process.FileEvent.FileFields)
			},
			Field:  field,
			Weight: eval.HandlerWeight,
		}, nil
	case "ptrace.tracee.file.in_upper_layer":
		return &eval.BoolEvaluator{
			EvalFnc: func(ctx *eval.Context) bool {
				event := GetEvent(ctx)
				return event.ResolveFileFieldsInUpperLayer(&event.PTrace.Tracee.Process.FileEvent.FileFields)
			},
			Field:  field,
			Weight: eval.HandlerWeight,
		}, nil
	case "ptrace.tracee.file.inode":
		return &eval.IntEvaluator{
			EvalFnc: func(ctx *eval.Context) int {
				event := GetEvent(ctx)
				return int(event.PTrace.Tracee.Process.FileEvent.FileFields.Inode)
			},
			Field:  field,
			Weight: eval.FunctionWeight,
		}, nil
	case "ptrace.tracee.file.mode":
		return &eval.IntEvaluator{
			EvalFnc: func(ctx *eval.Context) int {
				event := GetEvent(ctx)
				return int(event.PTrace.Tracee.Process.FileEvent.FileFields.Mode)
			},
			Field:  field,
			Weight: eval.FunctionWeight,
		}, nil
	case "ptrace.tracee.file.modification_time":
		return &eval.IntEvaluator{
			EvalFnc: func(ctx *eval.Context) int {
				event := GetEvent(ctx)
				return int(event.PTrace.Tracee.Process.FileEvent.FileFields.MTime)
			},
			Field:  field,
			Weight: eval.FunctionWeight,
		}, nil
	case "ptrace.tracee.file.mount_id":
		return &eval.IntEvaluator{
			EvalFnc: func(ctx *eval.Context) int {
				event := GetEvent(ctx)
				return int(event.PTrace.Tracee.Process.FileEvent.FileFields.MountID)
			},
			Field:  field,
			Weight: eval.FunctionWeight,
		}, nil
	case "ptrace.tracee.file.name":
		return &eval.StringEvaluator{
			OpOverrides: model.ProcessSymlinkBasename,
			EvalFnc: func(ctx *eval.Context) string {
				event := GetEvent(ctx)
				return event.ResolveFileBasename(&event.PTrace.Tracee.Process.FileEvent)
			},
			Field:  field,
			Weight: eval.HandlerWeight,
		}, nil
	case "ptrace.tracee.file.path":
		return &eval.StringEvaluator{
			OpOverrides: model.ProcessSymlinkPathname,
			EvalFnc: func(ctx *eval.Context) string {
				event := GetEvent(ctx)
				return event.ResolveFilePath(&event.PTrace.Tracee.Process.FileEvent)
			},
			Field:  field,
			Weight: eval.HandlerWeight,
		}, nil
	case "ptrace.tracee.file.rights":
		return &eval.IntEvaluator{
			EvalFnc: func(ctx *eval.Context) int {
				event := GetEvent(ctx)
				return int(event.ResolveRights(&event.PTrace.Tracee.Process.FileEvent.FileFields))
			},
			Field:  field,
			Weight: eval.HandlerWeight,
		}, nil
	case "ptrace.tracee.file.uid":
		return &eval.IntEvaluator{
			EvalFnc: func(ctx *eval.Context) int {
				event := GetEvent(ctx)
				return int(event.PTrace.Tracee.Process.FileEvent.FileFields.UID)
			},
			Field:  field,
			Weight: eval.FunctionWeight,
		}, nil
	case "ptrace.tracee.file.user":
		return &eval.StringEvaluator{
			EvalFnc: func(ctx *eval.Context) string {
				event := GetEvent(ctx)
				return event.ResolveFileFieldsUser(&event.PTrace.Tracee.Process.FileEvent.FileFields)
			},
			Field:  field,
			Weight: eval.HandlerWeight,
		}, nil
	case "ptrace.tracee.fsgid":
		return &eval.IntEvaluator{
			EvalFnc: func(ctx *eval.Context) int {
				event := GetEvent(ctx)
				return int(event.PTrace.Tracee.Process.Credentials.FSGID)
			},
			Field:  field,
			Weight: eval.FunctionWeight,
		}, nil
	case "ptrace.tracee.fsgroup":
		return &eval.StringEvaluator{
			EvalFnc: func(ctx *eval.Context) string {
				event := GetEvent(ctx)
				return event.PTrace.Tracee.Process.Credentials.FSGroup
			},
			Field:  field,
			Weight: eval.FunctionWeight,
		}, nil
	case "ptrace.tracee.fsuid":
		return &eval.IntEvaluator{
			EvalFnc: func(ctx *eval.Context) int {
				event := GetEvent(ctx)
				return int(event.PTrace.Tracee.Process.Credentials.FSUID)
			},
			Field:  field,
			Weight: eval.FunctionWeight,
		}, nil
	case "ptrace.tracee.fsuser":
		return &eval.StringEvaluator{
			EvalFnc: func(ctx *eval.Context) string {
				event := GetEvent(ctx)
				return event.PTrace.Tracee.Process.Credentials.FSUser
			},
			Field:  field,
			Weight: eval.FunctionWeight,
		}, nil
	case "ptrace.tracee.gid":
		return &eval.IntEvaluator{
			EvalFnc: func(ctx *eval.Context) int {
				event := GetEvent(ctx)
				return int(event.PTrace.Tracee.Process.Credentials.GID)
			},
			Field:  field,
			Weight: eval.FunctionWeight,
		}, nil
	case "ptrace.tracee.group":
		return &eval.StringEvaluator{
			EvalFnc: func(ctx *eval.Context) string {
				event := GetEvent(ctx)
				return event.PTrace.Tracee.Process.Credentials.Group
			},
			Field:  field,
			Weight: eval.FunctionWeight,
		}, nil
	case "ptrace.tracee.is_thread":
		return &eval.BoolEvaluator{
			EvalFnc: func(ctx *eval.Context) bool {
				event := GetEvent(ctx)
				return event.PTrace.Tracee.Process.IsThread
			},
			Field:  field,
			Weight: eval.FunctionWeight,
		}, nil
	case "ptrace.tracee.pid":
		return &eval.IntEvaluator{
			EvalFnc: func(ctx *eval.Context) int {
				event := GetEvent(ctx)
				return int(event.PTrace.Tracee.Process.PIDContext.Pid)
			},
			Field:  field,
			Weight: eval.FunctionWeight,
		}, nil
	case "ptrace.tracee.ppid":
		return &eval.IntEvaluator{
			EvalFnc: func(ctx *eval.Context) int {
				event := GetEvent(ctx)
				return int(event.PTrace.Tracee.Process.PPid)
			},
			Field:  field,
			Weight: eval.FunctionWeight,
		}, nil
	case "ptrace.tracee.tid":
		return &eval.IntEvaluator{
			EvalFnc: func(ctx *eval.Context) int {
				event := GetEvent(ctx)
				return int(event.PTrace.Tracee.Process.PIDContext.Tid)
			},
			Field:  field,
			Weight: eval.FunctionWeight,
		}, nil
	case "ptrace.tracee.tty_name":
		return &eval.StringEvaluator{
			EvalFnc: func(ctx *eval.Context) string {
				event := GetEvent(ctx)
				return event.PTrace.Tracee.Process.TTYName
			},
			Field:  field,
			Weight: eval.FunctionWeight,
		}, nil
	case "ptrace.tracee.uid":
		return &eval.IntEvaluator{
			EvalFnc: func(ctx *eval.Context) int {
				event := GetEvent(ctx)
				return int(event.PTrace.Tracee.Process.Credentials.UID)
			},
			Field:  field,
			Weight: eval.FunctionWeight,
		}, nil
	case "ptrace.tracee.user":
		return &eval.StringEvaluator{
			EvalFnc: func(ctx *eval.Context) string {
				event := GetEvent(ctx)
				return event.PTrace.Tracee.Process.Credentials.User
			},
			Field:  field,
			Weight: eval.FunctionWeight,
		}, nil
	case "removexattr.file.change_time":
		return &eval.IntEvaluator{
			EvalFnc: func(ctx *eval.Context) int {
				event := GetEvent(ctx)
				return int(event.RemoveXAttr.File.FileFields.CTime)
			},
			Field:  field,
			Weight: eval.FunctionWeight,
		}, nil
	case "removexattr.file.destination.name":
		return &eval.StringEvaluator{
			EvalFnc: func(ctx *eval.Context) string {
				event := GetEvent(ctx)
				return event.ResolveXAttrName(&event.RemoveXAttr)
			},
			Field:  field,
			Weight: eval.HandlerWeight,
		}, nil
	case "removexattr.file.destination.namespace":
		return &eval.StringEvaluator{
			EvalFnc: func(ctx *eval.Context) string {
				event := GetEvent(ctx)
				return event.ResolveXAttrNamespace(&event.RemoveXAttr)
			},
			Field:  field,
			Weight: eval.HandlerWeight,
		}, nil
	case "removexattr.file.filesystem":
		return &eval.StringEvaluator{
			EvalFnc: func(ctx *eval.Context) string {
				event := GetEvent(ctx)
				return event.ResolveFileFilesystem(&event.RemoveXAttr.File)
			},
			Field:  field,
			Weight: eval.HandlerWeight,
		}, nil
	case "removexattr.file.gid":
		return &eval.IntEvaluator{
			EvalFnc: func(ctx *eval.Context) int {
				event := GetEvent(ctx)
				return int(event.RemoveXAttr.File.FileFields.GID)
			},
			Field:  field,
			Weight: eval.FunctionWeight,
		}, nil
	case "removexattr.file.group":
		return &eval.StringEvaluator{
			EvalFnc: func(ctx *eval.Context) string {
				event := GetEvent(ctx)
				return event.ResolveFileFieldsGroup(&event.RemoveXAttr.File.FileFields)
			},
			Field:  field,
			Weight: eval.HandlerWeight,
		}, nil
	case "removexattr.file.in_upper_layer":
		return &eval.BoolEvaluator{
			EvalFnc: func(ctx *eval.Context) bool {
				event := GetEvent(ctx)
				return event.ResolveFileFieldsInUpperLayer(&event.RemoveXAttr.File.FileFields)
			},
			Field:  field,
			Weight: eval.HandlerWeight,
		}, nil
	case "removexattr.file.inode":
		return &eval.IntEvaluator{
			EvalFnc: func(ctx *eval.Context) int {
				event := GetEvent(ctx)
				return int(event.RemoveXAttr.File.FileFields.Inode)
			},
			Field:  field,
			Weight: eval.FunctionWeight,
		}, nil
	case "removexattr.file.mode":
		return &eval.IntEvaluator{
			EvalFnc: func(ctx *eval.Context) int {
				event := GetEvent(ctx)
				return int(event.RemoveXAttr.File.FileFields.Mode)
			},
			Field:  field,
			Weight: eval.FunctionWeight,
		}, nil
	case "removexattr.file.modification_time":
		return &eval.IntEvaluator{
			EvalFnc: func(ctx *eval.Context) int {
				event := GetEvent(ctx)
				return int(event.RemoveXAttr.File.FileFields.MTime)
			},
			Field:  field,
			Weight: eval.FunctionWeight,
		}, nil
	case "removexattr.file.mount_id":
		return &eval.IntEvaluator{
			EvalFnc: func(ctx *eval.Context) int {
				event := GetEvent(ctx)
				return int(event.RemoveXAttr.File.FileFields.MountID)
			},
			Field:  field,
			Weight: eval.FunctionWeight,
		}, nil
	case "removexattr.file.name":
		return &eval.StringEvaluator{
			OpOverrides: model.ProcessSymlinkBasename,
			EvalFnc: func(ctx *eval.Context) string {
				event := GetEvent(ctx)
				return event.ResolveFileBasename(&event.RemoveXAttr.File)
			},
			Field:  field,
			Weight: eval.HandlerWeight,
		}, nil
	case "removexattr.file.path":
		return &eval.StringEvaluator{
			OpOverrides: model.ProcessSymlinkPathname,
			EvalFnc: func(ctx *eval.Context) string {
				event := GetEvent(ctx)
				return event.ResolveFilePath(&event.RemoveXAttr.File)
			},
			Field:  field,
			Weight: eval.HandlerWeight,
		}, nil
	case "removexattr.file.rights":
		return &eval.IntEvaluator{
			EvalFnc: func(ctx *eval.Context) int {
				event := GetEvent(ctx)
				return int(event.ResolveRights(&event.RemoveXAttr.File.FileFields))
			},
			Field:  field,
			Weight: eval.HandlerWeight,
		}, nil
	case "removexattr.file.uid":
		return &eval.IntEvaluator{
			EvalFnc: func(ctx *eval.Context) int {
				event := GetEvent(ctx)
				return int(event.RemoveXAttr.File.FileFields.UID)
			},
			Field:  field,
			Weight: eval.FunctionWeight,
		}, nil
	case "removexattr.file.user":
		return &eval.StringEvaluator{
			EvalFnc: func(ctx *eval.Context) string {
				event := GetEvent(ctx)
				return event.ResolveFileFieldsUser(&event.RemoveXAttr.File.FileFields)
			},
			Field:  field,
			Weight: eval.HandlerWeight,
		}, nil
	case "removexattr.retval":
		return &eval.IntEvaluator{
			EvalFnc: func(ctx *eval.Context) int {
				event := GetEvent(ctx)
				return int(event.RemoveXAttr.SyscallEvent.Retval)
			},
			Field:  field,
			Weight: eval.FunctionWeight,
		}, nil
	case "rename.file.change_time":
		return &eval.IntEvaluator{
			EvalFnc: func(ctx *eval.Context) int {
				event := GetEvent(ctx)
				return int(event.Rename.Old.FileFields.CTime)
			},
			Field:  field,
			Weight: eval.FunctionWeight,
		}, nil
	case "rename.file.destination.change_time":
		return &eval.IntEvaluator{
			EvalFnc: func(ctx *eval.Context) int {
				event := GetEvent(ctx)
				return int(event.Rename.New.FileFields.CTime)
			},
			Field:  field,
			Weight: eval.FunctionWeight,
		}, nil
	case "rename.file.destination.filesystem":
		return &eval.StringEvaluator{
			EvalFnc: func(ctx *eval.Context) string {
				event := GetEvent(ctx)
				return event.ResolveFileFilesystem(&event.Rename.New)
			},
			Field:  field,
			Weight: eval.HandlerWeight,
		}, nil
	case "rename.file.destination.gid":
		return &eval.IntEvaluator{
			EvalFnc: func(ctx *eval.Context) int {
				event := GetEvent(ctx)
				return int(event.Rename.New.FileFields.GID)
			},
			Field:  field,
			Weight: eval.FunctionWeight,
		}, nil
	case "rename.file.destination.group":
		return &eval.StringEvaluator{
			EvalFnc: func(ctx *eval.Context) string {
				event := GetEvent(ctx)
				return event.ResolveFileFieldsGroup(&event.Rename.New.FileFields)
			},
			Field:  field,
			Weight: eval.HandlerWeight,
		}, nil
	case "rename.file.destination.in_upper_layer":
		return &eval.BoolEvaluator{
			EvalFnc: func(ctx *eval.Context) bool {
				event := GetEvent(ctx)
				return event.ResolveFileFieldsInUpperLayer(&event.Rename.New.FileFields)
			},
			Field:  field,
			Weight: eval.HandlerWeight,
		}, nil
	case "rename.file.destination.inode":
		return &eval.IntEvaluator{
			EvalFnc: func(ctx *eval.Context) int {
				event := GetEvent(ctx)
				return int(event.Rename.New.FileFields.Inode)
			},
			Field:  field,
			Weight: eval.FunctionWeight,
		}, nil
	case "rename.file.destination.mode":
		return &eval.IntEvaluator{
			EvalFnc: func(ctx *eval.Context) int {
				event := GetEvent(ctx)
				return int(event.Rename.New.FileFields.Mode)
			},
			Field:  field,
			Weight: eval.FunctionWeight,
		}, nil
	case "rename.file.destination.modification_time":
		return &eval.IntEvaluator{
			EvalFnc: func(ctx *eval.Context) int {
				event := GetEvent(ctx)
				return int(event.Rename.New.FileFields.MTime)
			},
			Field:  field,
			Weight: eval.FunctionWeight,
		}, nil
	case "rename.file.destination.mount_id":
		return &eval.IntEvaluator{
			EvalFnc: func(ctx *eval.Context) int {
				event := GetEvent(ctx)
				return int(event.Rename.New.FileFields.MountID)
			},
			Field:  field,
			Weight: eval.FunctionWeight,
		}, nil
	case "rename.file.destination.name":
		return &eval.StringEvaluator{
			OpOverrides: model.ProcessSymlinkBasename,
			EvalFnc: func(ctx *eval.Context) string {
				event := GetEvent(ctx)
				return event.ResolveFileBasename(&event.Rename.New)
			},
			Field:  field,
			Weight: eval.HandlerWeight,
		}, nil
	case "rename.file.destination.path":
		return &eval.StringEvaluator{
			OpOverrides: model.ProcessSymlinkPathname,
			EvalFnc: func(ctx *eval.Context) string {
				event := GetEvent(ctx)
				return event.ResolveFilePath(&event.Rename.New)
			},
			Field:  field,
			Weight: eval.HandlerWeight,
		}, nil
	case "rename.file.destination.rights":
		return &eval.IntEvaluator{
			EvalFnc: func(ctx *eval.Context) int {
				event := GetEvent(ctx)
				return int(event.ResolveRights(&event.Rename.New.FileFields))
			},
			Field:  field,
			Weight: eval.HandlerWeight,
		}, nil
	case "rename.file.destination.uid":
		return &eval.IntEvaluator{
			EvalFnc: func(ctx *eval.Context) int {
				event := GetEvent(ctx)
				return int(event.Rename.New.FileFields.UID)
			},
			Field:  field,
			Weight: eval.FunctionWeight,
		}, nil
	case "rename.file.destination.user":
		return &eval.StringEvaluator{
			EvalFnc: func(ctx *eval.Context) string {
				event := GetEvent(ctx)
				return event.ResolveFileFieldsUser(&event.Rename.New.FileFields)
			},
			Field:  field,
			Weight: eval.HandlerWeight,
		}, nil
	case "rename.file.filesystem":
		return &eval.StringEvaluator{
			EvalFnc: func(ctx *eval.Context) string {
				event := GetEvent(ctx)
				return event.ResolveFileFilesystem(&event.Rename.Old)
			},
			Field:  field,
			Weight: eval.HandlerWeight,
		}, nil
	case "rename.file.gid":
		return &eval.IntEvaluator{
			EvalFnc: func(ctx *eval.Context) int {
				event := GetEvent(ctx)
				return int(event.Rename.Old.FileFields.GID)
			},
			Field:  field,
			Weight: eval.FunctionWeight,
		}, nil
	case "rename.file.group":
		return &eval.StringEvaluator{
			EvalFnc: func(ctx *eval.Context) string {
				event := GetEvent(ctx)
				return event.ResolveFileFieldsGroup(&event.Rename.Old.FileFields)
			},
			Field:  field,
			Weight: eval.HandlerWeight,
		}, nil
	case "rename.file.in_upper_layer":
		return &eval.BoolEvaluator{
			EvalFnc: func(ctx *eval.Context) bool {
				event := GetEvent(ctx)
				return event.ResolveFileFieldsInUpperLayer(&event.Rename.Old.FileFields)
			},
			Field:  field,
			Weight: eval.HandlerWeight,
		}, nil
	case "rename.file.inode":
		return &eval.IntEvaluator{
			EvalFnc: func(ctx *eval.Context) int {
				event := GetEvent(ctx)
				return int(event.Rename.Old.FileFields.Inode)
			},
			Field:  field,
			Weight: eval.FunctionWeight,
		}, nil
	case "rename.file.mode":
		return &eval.IntEvaluator{
			EvalFnc: func(ctx *eval.Context) int {
				event := GetEvent(ctx)
				return int(event.Rename.Old.FileFields.Mode)
			},
			Field:  field,
			Weight: eval.FunctionWeight,
		}, nil
	case "rename.file.modification_time":
		return &eval.IntEvaluator{
			EvalFnc: func(ctx *eval.Context) int {
				event := GetEvent(ctx)
				return int(event.Rename.Old.FileFields.MTime)
			},
			Field:  field,
			Weight: eval.FunctionWeight,
		}, nil
	case "rename.file.mount_id":
		return &eval.IntEvaluator{
			EvalFnc: func(ctx *eval.Context) int {
				event := GetEvent(ctx)
				return int(event.Rename.Old.FileFields.MountID)
			},
			Field:  field,
			Weight: eval.FunctionWeight,
		}, nil
	case "rename.file.name":
		return &eval.StringEvaluator{
			OpOverrides: model.ProcessSymlinkBasename,
			EvalFnc: func(ctx *eval.Context) string {
				event := GetEvent(ctx)
				return event.ResolveFileBasename(&event.Rename.Old)
			},
			Field:  field,
			Weight: eval.HandlerWeight,
		}, nil
	case "rename.file.path":
		return &eval.StringEvaluator{
			OpOverrides: model.ProcessSymlinkPathname,
			EvalFnc: func(ctx *eval.Context) string {
				event := GetEvent(ctx)
				return event.ResolveFilePath(&event.Rename.Old)
			},
			Field:  field,
			Weight: eval.HandlerWeight,
		}, nil
	case "rename.file.rights":
		return &eval.IntEvaluator{
			EvalFnc: func(ctx *eval.Context) int {
				event := GetEvent(ctx)
				return int(event.ResolveRights(&event.Rename.Old.FileFields))
			},
			Field:  field,
			Weight: eval.HandlerWeight,
		}, nil
	case "rename.file.uid":
		return &eval.IntEvaluator{
			EvalFnc: func(ctx *eval.Context) int {
				event := GetEvent(ctx)
				return int(event.Rename.Old.FileFields.UID)
			},
			Field:  field,
			Weight: eval.FunctionWeight,
		}, nil
	case "rename.file.user":
		return &eval.StringEvaluator{
			EvalFnc: func(ctx *eval.Context) string {
				event := GetEvent(ctx)
				return event.ResolveFileFieldsUser(&event.Rename.Old.FileFields)
			},
			Field:  field,
			Weight: eval.HandlerWeight,
		}, nil
	case "rename.retval":
		return &eval.IntEvaluator{
			EvalFnc: func(ctx *eval.Context) int {
				event := GetEvent(ctx)
				return int(event.Rename.SyscallEvent.Retval)
			},
			Field:  field,
			Weight: eval.FunctionWeight,
		}, nil
	case "rmdir.file.change_time":
		return &eval.IntEvaluator{
			EvalFnc: func(ctx *eval.Context) int {
				event := GetEvent(ctx)
				return int(event.Rmdir.File.FileFields.CTime)
			},
			Field:  field,
			Weight: eval.FunctionWeight,
		}, nil
	case "rmdir.file.filesystem":
		return &eval.StringEvaluator{
			EvalFnc: func(ctx *eval.Context) string {
				event := GetEvent(ctx)
				return event.ResolveFileFilesystem(&event.Rmdir.File)
			},
			Field:  field,
			Weight: eval.HandlerWeight,
		}, nil
	case "rmdir.file.gid":
		return &eval.IntEvaluator{
			EvalFnc: func(ctx *eval.Context) int {
				event := GetEvent(ctx)
				return int(event.Rmdir.File.FileFields.GID)
			},
			Field:  field,
			Weight: eval.FunctionWeight,
		}, nil
	case "rmdir.file.group":
		return &eval.StringEvaluator{
			EvalFnc: func(ctx *eval.Context) string {
				event := GetEvent(ctx)
				return event.ResolveFileFieldsGroup(&event.Rmdir.File.FileFields)
			},
			Field:  field,
			Weight: eval.HandlerWeight,
		}, nil
	case "rmdir.file.in_upper_layer":
		return &eval.BoolEvaluator{
			EvalFnc: func(ctx *eval.Context) bool {
				event := GetEvent(ctx)
				return event.ResolveFileFieldsInUpperLayer(&event.Rmdir.File.FileFields)
			},
			Field:  field,
			Weight: eval.HandlerWeight,
		}, nil
	case "rmdir.file.inode":
		return &eval.IntEvaluator{
			EvalFnc: func(ctx *eval.Context) int {
				event := GetEvent(ctx)
				return int(event.Rmdir.File.FileFields.Inode)
			},
			Field:  field,
			Weight: eval.FunctionWeight,
		}, nil
	case "rmdir.file.mode":
		return &eval.IntEvaluator{
			EvalFnc: func(ctx *eval.Context) int {
				event := GetEvent(ctx)
				return int(event.Rmdir.File.FileFields.Mode)
			},
			Field:  field,
			Weight: eval.FunctionWeight,
		}, nil
	case "rmdir.file.modification_time":
		return &eval.IntEvaluator{
			EvalFnc: func(ctx *eval.Context) int {
				event := GetEvent(ctx)
				return int(event.Rmdir.File.FileFields.MTime)
			},
			Field:  field,
			Weight: eval.FunctionWeight,
		}, nil
	case "rmdir.file.mount_id":
		return &eval.IntEvaluator{
			EvalFnc: func(ctx *eval.Context) int {
				event := GetEvent(ctx)
				return int(event.Rmdir.File.FileFields.MountID)
			},
			Field:  field,
			Weight: eval.FunctionWeight,
		}, nil
	case "rmdir.file.name":
		return &eval.StringEvaluator{
			OpOverrides: model.ProcessSymlinkBasename,
			EvalFnc: func(ctx *eval.Context) string {
				event := GetEvent(ctx)
				return event.ResolveFileBasename(&event.Rmdir.File)
			},
			Field:  field,
			Weight: eval.HandlerWeight,
		}, nil
	case "rmdir.file.path":
		return &eval.StringEvaluator{
			OpOverrides: model.ProcessSymlinkPathname,
			EvalFnc: func(ctx *eval.Context) string {
				event := GetEvent(ctx)
				return event.ResolveFilePath(&event.Rmdir.File)
			},
			Field:  field,
			Weight: eval.HandlerWeight,
		}, nil
	case "rmdir.file.rights":
		return &eval.IntEvaluator{
			EvalFnc: func(ctx *eval.Context) int {
				event := GetEvent(ctx)
				return int(event.ResolveRights(&event.Rmdir.File.FileFields))
			},
			Field:  field,
			Weight: eval.HandlerWeight,
		}, nil
	case "rmdir.file.uid":
		return &eval.IntEvaluator{
			EvalFnc: func(ctx *eval.Context) int {
				event := GetEvent(ctx)
				return int(event.Rmdir.File.FileFields.UID)
			},
			Field:  field,
			Weight: eval.FunctionWeight,
		}, nil
	case "rmdir.file.user":
		return &eval.StringEvaluator{
			EvalFnc: func(ctx *eval.Context) string {
				event := GetEvent(ctx)
				return event.ResolveFileFieldsUser(&event.Rmdir.File.FileFields)
			},
			Field:  field,
			Weight: eval.HandlerWeight,
		}, nil
	case "rmdir.retval":
		return &eval.IntEvaluator{
			EvalFnc: func(ctx *eval.Context) int {
				event := GetEvent(ctx)
				return int(event.Rmdir.SyscallEvent.Retval)
			},
			Field:  field,
			Weight: eval.FunctionWeight,
		}, nil
	case "selinux.bool.name":
		return &eval.StringEvaluator{
			EvalFnc: func(ctx *eval.Context) string {
				event := GetEvent(ctx)
				return event.ResolveSELinuxBoolName(&event.SELinux)
			},
			Field:  field,
			Weight: eval.HandlerWeight,
		}, nil
	case "selinux.bool.state":
		return &eval.StringEvaluator{
			EvalFnc: func(ctx *eval.Context) string {
				event := GetEvent(ctx)
				return event.SELinux.BoolChangeValue
			},
			Field:  field,
			Weight: eval.FunctionWeight,
		}, nil
	case "selinux.bool_commit.state":
		return &eval.BoolEvaluator{
			EvalFnc: func(ctx *eval.Context) bool {
				event := GetEvent(ctx)
				return event.SELinux.BoolCommitValue
			},
			Field:  field,
			Weight: eval.FunctionWeight,
		}, nil
	case "selinux.enforce.status":
		return &eval.StringEvaluator{
			EvalFnc: func(ctx *eval.Context) string {
				event := GetEvent(ctx)
				return event.SELinux.EnforceStatus
			},
			Field:  field,
			Weight: eval.FunctionWeight,
		}, nil
	case "setgid.egid":
		return &eval.IntEvaluator{
			EvalFnc: func(ctx *eval.Context) int {
				event := GetEvent(ctx)
				return int(event.SetGID.EGID)
			},
			Field:  field,
			Weight: eval.FunctionWeight,
		}, nil
	case "setgid.egroup":
		return &eval.StringEvaluator{
			EvalFnc: func(ctx *eval.Context) string {
				event := GetEvent(ctx)
				return event.ResolveSetgidEGroup(&event.SetGID)
			},
			Field:  field,
			Weight: eval.HandlerWeight,
		}, nil
	case "setgid.fsgid":
		return &eval.IntEvaluator{
			EvalFnc: func(ctx *eval.Context) int {
				event := GetEvent(ctx)
				return int(event.SetGID.FSGID)
			},
			Field:  field,
			Weight: eval.FunctionWeight,
		}, nil
	case "setgid.fsgroup":
		return &eval.StringEvaluator{
			EvalFnc: func(ctx *eval.Context) string {
				event := GetEvent(ctx)
				return event.ResolveSetgidFSGroup(&event.SetGID)
			},
			Field:  field,
			Weight: eval.HandlerWeight,
		}, nil
	case "setgid.gid":
		return &eval.IntEvaluator{
			EvalFnc: func(ctx *eval.Context) int {
				event := GetEvent(ctx)
				return int(event.SetGID.GID)
			},
			Field:  field,
			Weight: eval.FunctionWeight,
		}, nil
	case "setgid.group":
		return &eval.StringEvaluator{
			EvalFnc: func(ctx *eval.Context) string {
				event := GetEvent(ctx)
				return event.ResolveSetgidGroup(&event.SetGID)
			},
			Field:  field,
			Weight: eval.HandlerWeight,
		}, nil
	case "setuid.euid":
		return &eval.IntEvaluator{
			EvalFnc: func(ctx *eval.Context) int {
				event := GetEvent(ctx)
				return int(event.SetUID.EUID)
			},
			Field:  field,
			Weight: eval.FunctionWeight,
		}, nil
	case "setuid.euser":
		return &eval.StringEvaluator{
			EvalFnc: func(ctx *eval.Context) string {
				event := GetEvent(ctx)
				return event.ResolveSetuidEUser(&event.SetUID)
			},
			Field:  field,
			Weight: eval.HandlerWeight,
		}, nil
	case "setuid.fsuid":
		return &eval.IntEvaluator{
			EvalFnc: func(ctx *eval.Context) int {
				event := GetEvent(ctx)
				return int(event.SetUID.FSUID)
			},
			Field:  field,
			Weight: eval.FunctionWeight,
		}, nil
	case "setuid.fsuser":
		return &eval.StringEvaluator{
			EvalFnc: func(ctx *eval.Context) string {
				event := GetEvent(ctx)
				return event.ResolveSetuidFSUser(&event.SetUID)
			},
			Field:  field,
			Weight: eval.HandlerWeight,
		}, nil
	case "setuid.uid":
		return &eval.IntEvaluator{
			EvalFnc: func(ctx *eval.Context) int {
				event := GetEvent(ctx)
				return int(event.SetUID.UID)
			},
			Field:  field,
			Weight: eval.FunctionWeight,
		}, nil
	case "setuid.user":
		return &eval.StringEvaluator{
			EvalFnc: func(ctx *eval.Context) string {
				event := GetEvent(ctx)
				return event.ResolveSetuidUser(&event.SetUID)
			},
			Field:  field,
			Weight: eval.HandlerWeight,
		}, nil
	case "setxattr.file.change_time":
		return &eval.IntEvaluator{
			EvalFnc: func(ctx *eval.Context) int {
				event := GetEvent(ctx)
				return int(event.SetXAttr.File.FileFields.CTime)
			},
			Field:  field,
			Weight: eval.FunctionWeight,
		}, nil
	case "setxattr.file.destination.name":
		return &eval.StringEvaluator{
			EvalFnc: func(ctx *eval.Context) string {
				event := GetEvent(ctx)
				return event.ResolveXAttrName(&event.SetXAttr)
			},
			Field:  field,
			Weight: eval.HandlerWeight,
		}, nil
	case "setxattr.file.destination.namespace":
		return &eval.StringEvaluator{
			EvalFnc: func(ctx *eval.Context) string {
				event := GetEvent(ctx)
				return event.ResolveXAttrNamespace(&event.SetXAttr)
			},
			Field:  field,
			Weight: eval.HandlerWeight,
		}, nil
	case "setxattr.file.filesystem":
		return &eval.StringEvaluator{
			EvalFnc: func(ctx *eval.Context) string {
				event := GetEvent(ctx)
				return event.ResolveFileFilesystem(&event.SetXAttr.File)
			},
			Field:  field,
			Weight: eval.HandlerWeight,
		}, nil
	case "setxattr.file.gid":
		return &eval.IntEvaluator{
			EvalFnc: func(ctx *eval.Context) int {
				event := GetEvent(ctx)
				return int(event.SetXAttr.File.FileFields.GID)
			},
			Field:  field,
			Weight: eval.FunctionWeight,
		}, nil
	case "setxattr.file.group":
		return &eval.StringEvaluator{
			EvalFnc: func(ctx *eval.Context) string {
				event := GetEvent(ctx)
				return event.ResolveFileFieldsGroup(&event.SetXAttr.File.FileFields)
			},
			Field:  field,
			Weight: eval.HandlerWeight,
		}, nil
	case "setxattr.file.in_upper_layer":
		return &eval.BoolEvaluator{
			EvalFnc: func(ctx *eval.Context) bool {
				event := GetEvent(ctx)
				return event.ResolveFileFieldsInUpperLayer(&event.SetXAttr.File.FileFields)
			},
			Field:  field,
			Weight: eval.HandlerWeight,
		}, nil
	case "setxattr.file.inode":
		return &eval.IntEvaluator{
			EvalFnc: func(ctx *eval.Context) int {
				event := GetEvent(ctx)
				return int(event.SetXAttr.File.FileFields.Inode)
			},
			Field:  field,
			Weight: eval.FunctionWeight,
		}, nil
	case "setxattr.file.mode":
		return &eval.IntEvaluator{
			EvalFnc: func(ctx *eval.Context) int {
				event := GetEvent(ctx)
				return int(event.SetXAttr.File.FileFields.Mode)
			},
			Field:  field,
			Weight: eval.FunctionWeight,
		}, nil
	case "setxattr.file.modification_time":
		return &eval.IntEvaluator{
			EvalFnc: func(ctx *eval.Context) int {
				event := GetEvent(ctx)
				return int(event.SetXAttr.File.FileFields.MTime)
			},
			Field:  field,
			Weight: eval.FunctionWeight,
		}, nil
	case "setxattr.file.mount_id":
		return &eval.IntEvaluator{
			EvalFnc: func(ctx *eval.Context) int {
				event := GetEvent(ctx)
				return int(event.SetXAttr.File.FileFields.MountID)
			},
			Field:  field,
			Weight: eval.FunctionWeight,
		}, nil
	case "setxattr.file.name":
		return &eval.StringEvaluator{
			OpOverrides: model.ProcessSymlinkBasename,
			EvalFnc: func(ctx *eval.Context) string {
				event := GetEvent(ctx)
				return event.ResolveFileBasename(&event.SetXAttr.File)
			},
			Field:  field,
			Weight: eval.HandlerWeight,
		}, nil
	case "setxattr.file.path":
		return &eval.StringEvaluator{
			OpOverrides: model.ProcessSymlinkPathname,
			EvalFnc: func(ctx *eval.Context) string {
				event := GetEvent(ctx)
				return event.ResolveFilePath(&event.SetXAttr.File)
			},
			Field:  field,
			Weight: eval.HandlerWeight,
		}, nil
	case "setxattr.file.rights":
		return &eval.IntEvaluator{
			EvalFnc: func(ctx *eval.Context) int {
				event := GetEvent(ctx)
				return int(event.ResolveRights(&event.SetXAttr.File.FileFields))
			},
			Field:  field,
			Weight: eval.HandlerWeight,
		}, nil
	case "setxattr.file.uid":
		return &eval.IntEvaluator{
			EvalFnc: func(ctx *eval.Context) int {
				event := GetEvent(ctx)
				return int(event.SetXAttr.File.FileFields.UID)
			},
			Field:  field,
			Weight: eval.FunctionWeight,
		}, nil
	case "setxattr.file.user":
		return &eval.StringEvaluator{
			EvalFnc: func(ctx *eval.Context) string {
				event := GetEvent(ctx)
				return event.ResolveFileFieldsUser(&event.SetXAttr.File.FileFields)
			},
			Field:  field,
			Weight: eval.HandlerWeight,
		}, nil
	case "setxattr.retval":
		return &eval.IntEvaluator{
			EvalFnc: func(ctx *eval.Context) int {
				event := GetEvent(ctx)
				return int(event.SetXAttr.SyscallEvent.Retval)
			},
			Field:  field,
			Weight: eval.FunctionWeight,
		}, nil
	case "signal.pid":
		return &eval.IntEvaluator{
			EvalFnc: func(ctx *eval.Context) int {
				event := GetEvent(ctx)
				return int(event.Signal.PID)
			},
			Field:  field,
			Weight: eval.FunctionWeight,
		}, nil
	case "signal.retval":
		return &eval.IntEvaluator{
			EvalFnc: func(ctx *eval.Context) int {
				event := GetEvent(ctx)
				return int(event.Signal.SyscallEvent.Retval)
			},
			Field:  field,
			Weight: eval.FunctionWeight,
		}, nil
	case "signal.target.ancestors.args":
		return &eval.StringArrayEvaluator{
			EvalFnc: func(ctx *eval.Context) []string {
				if ptr := ctx.Cache[field]; ptr != nil {
					if result := (*[]string)(ptr); result != nil {
						return *result
					}
				}
				var results []string
				iterator := &model.ProcessAncestorsIterator{}
				value := iterator.Front(ctx)
				for value != nil {
					element := (*model.ProcessCacheEntry)(value)
					event := GetEvent(ctx)
					result := event.ResolveProcessArgs(&element.ProcessContext.Process)
					results = append(results, result)
					value = iterator.Next()
				}
				ctx.Cache[field] = unsafe.Pointer(&results)
				return results
			}, Field: field,
			Weight: 100 * eval.IteratorWeight,
		}, nil
	case "signal.target.ancestors.args_flags":
		return &eval.StringArrayEvaluator{
			EvalFnc: func(ctx *eval.Context) []string {
				if ptr := ctx.Cache[field]; ptr != nil {
					if result := (*[]string)(ptr); result != nil {
						return *result
					}
				}
				var results []string
				iterator := &model.ProcessAncestorsIterator{}
				value := iterator.Front(ctx)
				for value != nil {
					element := (*model.ProcessCacheEntry)(value)
					event := GetEvent(ctx)
					result := event.ResolveProcessArgsFlags(&element.ProcessContext.Process)
					results = append(results, result...)
					value = iterator.Next()
				}
				ctx.Cache[field] = unsafe.Pointer(&results)
				return results
			}, Field: field,
			Weight: eval.IteratorWeight,
		}, nil
	case "signal.target.ancestors.args_options":
		return &eval.StringArrayEvaluator{
			EvalFnc: func(ctx *eval.Context) []string {
				if ptr := ctx.Cache[field]; ptr != nil {
					if result := (*[]string)(ptr); result != nil {
						return *result
					}
				}
				var results []string
				iterator := &model.ProcessAncestorsIterator{}
				value := iterator.Front(ctx)
				for value != nil {
					element := (*model.ProcessCacheEntry)(value)
					event := GetEvent(ctx)
					result := event.ResolveProcessArgsOptions(&element.ProcessContext.Process)
					results = append(results, result...)
					value = iterator.Next()
				}
				ctx.Cache[field] = unsafe.Pointer(&results)
				return results
			}, Field: field,
			Weight: eval.IteratorWeight,
		}, nil
	case "signal.target.ancestors.args_truncated":
		return &eval.BoolArrayEvaluator{
			EvalFnc: func(ctx *eval.Context) []bool {
				if ptr := ctx.Cache[field]; ptr != nil {
					if result := (*[]bool)(ptr); result != nil {
						return *result
					}
				}
				var results []bool
				iterator := &model.ProcessAncestorsIterator{}
				value := iterator.Front(ctx)
				for value != nil {
					element := (*model.ProcessCacheEntry)(value)
					event := GetEvent(ctx)
					result := event.ResolveProcessArgsTruncated(&element.ProcessContext.Process)
					results = append(results, result)
					value = iterator.Next()
				}
				ctx.Cache[field] = unsafe.Pointer(&results)
				return results
			}, Field: field,
			Weight: eval.IteratorWeight,
		}, nil
	case "signal.target.ancestors.argv":
		return &eval.StringArrayEvaluator{
			EvalFnc: func(ctx *eval.Context) []string {
				if ptr := ctx.Cache[field]; ptr != nil {
					if result := (*[]string)(ptr); result != nil {
						return *result
					}
				}
				var results []string
				iterator := &model.ProcessAncestorsIterator{}
				value := iterator.Front(ctx)
				for value != nil {
					element := (*model.ProcessCacheEntry)(value)
					event := GetEvent(ctx)
					result := event.ResolveProcessArgv(&element.ProcessContext.Process)
					results = append(results, result...)
					value = iterator.Next()
				}
				ctx.Cache[field] = unsafe.Pointer(&results)
				return results
			}, Field: field,
			Weight: 100 * eval.IteratorWeight,
		}, nil
	case "signal.target.ancestors.argv0":
		return &eval.StringArrayEvaluator{
			EvalFnc: func(ctx *eval.Context) []string {
				if ptr := ctx.Cache[field]; ptr != nil {
					if result := (*[]string)(ptr); result != nil {
						return *result
					}
				}
				var results []string
				iterator := &model.ProcessAncestorsIterator{}
				value := iterator.Front(ctx)
				for value != nil {
					element := (*model.ProcessCacheEntry)(value)
					event := GetEvent(ctx)
					result := event.ResolveProcessArgv0(&element.ProcessContext.Process)
					results = append(results, result)
					value = iterator.Next()
				}
				ctx.Cache[field] = unsafe.Pointer(&results)
				return results
			}, Field: field,
			Weight: 100 * eval.IteratorWeight,
		}, nil
	case "signal.target.ancestors.cap_effective":
		return &eval.IntArrayEvaluator{
			EvalFnc: func(ctx *eval.Context) []int {
				if ptr := ctx.Cache[field]; ptr != nil {
					if result := (*[]int)(ptr); result != nil {
						return *result
					}
				}
				var results []int
				iterator := &model.ProcessAncestorsIterator{}
				value := iterator.Front(ctx)
				for value != nil {
					element := (*model.ProcessCacheEntry)(value)
					result := int(element.ProcessContext.Process.Credentials.CapEffective)
					results = append(results, result)
					value = iterator.Next()
				}
				ctx.Cache[field] = unsafe.Pointer(&results)
				return results
			}, Field: field,
			Weight: eval.IteratorWeight,
		}, nil
	case "signal.target.ancestors.cap_permitted":
		return &eval.IntArrayEvaluator{
			EvalFnc: func(ctx *eval.Context) []int {
				if ptr := ctx.Cache[field]; ptr != nil {
					if result := (*[]int)(ptr); result != nil {
						return *result
					}
				}
				var results []int
				iterator := &model.ProcessAncestorsIterator{}
				value := iterator.Front(ctx)
				for value != nil {
					element := (*model.ProcessCacheEntry)(value)
					result := int(element.ProcessContext.Process.Credentials.CapPermitted)
					results = append(results, result)
					value = iterator.Next()
				}
				ctx.Cache[field] = unsafe.Pointer(&results)
				return results
			}, Field: field,
			Weight: eval.IteratorWeight,
		}, nil
	case "signal.target.ancestors.comm":
		return &eval.StringArrayEvaluator{
			EvalFnc: func(ctx *eval.Context) []string {
				if ptr := ctx.Cache[field]; ptr != nil {
					if result := (*[]string)(ptr); result != nil {
						return *result
					}
				}
				var results []string
				iterator := &model.ProcessAncestorsIterator{}
				value := iterator.Front(ctx)
				for value != nil {
					element := (*model.ProcessCacheEntry)(value)
					result := element.ProcessContext.Process.Comm
					results = append(results, result)
					value = iterator.Next()
				}
				ctx.Cache[field] = unsafe.Pointer(&results)
				return results
			}, Field: field,
			Weight: eval.IteratorWeight,
		}, nil
	case "signal.target.ancestors.container.id":
		return &eval.StringArrayEvaluator{
			EvalFnc: func(ctx *eval.Context) []string {
				if ptr := ctx.Cache[field]; ptr != nil {
					if result := (*[]string)(ptr); result != nil {
						return *result
					}
				}
				var results []string
				iterator := &model.ProcessAncestorsIterator{}
				value := iterator.Front(ctx)
				for value != nil {
					element := (*model.ProcessCacheEntry)(value)
					result := element.ProcessContext.Process.ContainerID
					results = append(results, result)
					value = iterator.Next()
				}
				ctx.Cache[field] = unsafe.Pointer(&results)
				return results
			}, Field: field,
			Weight: eval.IteratorWeight,
		}, nil
	case "signal.target.ancestors.cookie":
		return &eval.IntArrayEvaluator{
			EvalFnc: func(ctx *eval.Context) []int {
				if ptr := ctx.Cache[field]; ptr != nil {
					if result := (*[]int)(ptr); result != nil {
						return *result
					}
				}
				var results []int
				iterator := &model.ProcessAncestorsIterator{}
				value := iterator.Front(ctx)
				for value != nil {
					element := (*model.ProcessCacheEntry)(value)
					result := int(element.ProcessContext.Process.Cookie)
					results = append(results, result)
					value = iterator.Next()
				}
				ctx.Cache[field] = unsafe.Pointer(&results)
				return results
			}, Field: field,
			Weight: eval.IteratorWeight,
		}, nil
	case "signal.target.ancestors.created_at":
		return &eval.IntArrayEvaluator{
			EvalFnc: func(ctx *eval.Context) []int {
				if ptr := ctx.Cache[field]; ptr != nil {
					if result := (*[]int)(ptr); result != nil {
						return *result
					}
				}
				var results []int
				iterator := &model.ProcessAncestorsIterator{}
				value := iterator.Front(ctx)
				for value != nil {
					element := (*model.ProcessCacheEntry)(value)
					event := GetEvent(ctx)
					result := int(event.ResolveProcessCreatedAt(&element.ProcessContext.Process))
					results = append(results, result)
					value = iterator.Next()
				}
				ctx.Cache[field] = unsafe.Pointer(&results)
				return results
			}, Field: field,
			Weight: eval.IteratorWeight,
		}, nil
	case "signal.target.ancestors.egid":
		return &eval.IntArrayEvaluator{
			EvalFnc: func(ctx *eval.Context) []int {
				if ptr := ctx.Cache[field]; ptr != nil {
					if result := (*[]int)(ptr); result != nil {
						return *result
					}
				}
				var results []int
				iterator := &model.ProcessAncestorsIterator{}
				value := iterator.Front(ctx)
				for value != nil {
					element := (*model.ProcessCacheEntry)(value)
					result := int(element.ProcessContext.Process.Credentials.EGID)
					results = append(results, result)
					value = iterator.Next()
				}
				ctx.Cache[field] = unsafe.Pointer(&results)
				return results
			}, Field: field,
			Weight: eval.IteratorWeight,
		}, nil
	case "signal.target.ancestors.egroup":
		return &eval.StringArrayEvaluator{
			EvalFnc: func(ctx *eval.Context) []string {
				if ptr := ctx.Cache[field]; ptr != nil {
					if result := (*[]string)(ptr); result != nil {
						return *result
					}
				}
				var results []string
				iterator := &model.ProcessAncestorsIterator{}
				value := iterator.Front(ctx)
				for value != nil {
					element := (*model.ProcessCacheEntry)(value)
					result := element.ProcessContext.Process.Credentials.EGroup
					results = append(results, result)
					value = iterator.Next()
				}
				ctx.Cache[field] = unsafe.Pointer(&results)
				return results
			}, Field: field,
			Weight: eval.IteratorWeight,
		}, nil
	case "signal.target.ancestors.envp":
		return &eval.StringArrayEvaluator{
			EvalFnc: func(ctx *eval.Context) []string {
				if ptr := ctx.Cache[field]; ptr != nil {
					if result := (*[]string)(ptr); result != nil {
						return *result
					}
				}
				var results []string
				iterator := &model.ProcessAncestorsIterator{}
				value := iterator.Front(ctx)
				for value != nil {
					element := (*model.ProcessCacheEntry)(value)
					event := GetEvent(ctx)
					result := event.ResolveProcessEnvp(&element.ProcessContext.Process)
					results = append(results, result...)
					value = iterator.Next()
				}
				ctx.Cache[field] = unsafe.Pointer(&results)
				return results
			}, Field: field,
			Weight: eval.IteratorWeight,
		}, nil
	case "signal.target.ancestors.envs":
		return &eval.StringArrayEvaluator{
			EvalFnc: func(ctx *eval.Context) []string {
				if ptr := ctx.Cache[field]; ptr != nil {
					if result := (*[]string)(ptr); result != nil {
						return *result
					}
				}
				var results []string
				iterator := &model.ProcessAncestorsIterator{}
				value := iterator.Front(ctx)
				for value != nil {
					element := (*model.ProcessCacheEntry)(value)
					event := GetEvent(ctx)
					result := event.ResolveProcessEnvs(&element.ProcessContext.Process)
					results = append(results, result...)
					value = iterator.Next()
				}
				ctx.Cache[field] = unsafe.Pointer(&results)
				return results
			}, Field: field,
			Weight: eval.IteratorWeight,
		}, nil
	case "signal.target.ancestors.envs_truncated":
		return &eval.BoolArrayEvaluator{
			EvalFnc: func(ctx *eval.Context) []bool {
				if ptr := ctx.Cache[field]; ptr != nil {
					if result := (*[]bool)(ptr); result != nil {
						return *result
					}
				}
				var results []bool
				iterator := &model.ProcessAncestorsIterator{}
				value := iterator.Front(ctx)
				for value != nil {
					element := (*model.ProcessCacheEntry)(value)
					event := GetEvent(ctx)
					result := event.ResolveProcessEnvsTruncated(&element.ProcessContext.Process)
					results = append(results, result)
					value = iterator.Next()
				}
				ctx.Cache[field] = unsafe.Pointer(&results)
				return results
			}, Field: field,
			Weight: eval.IteratorWeight,
		}, nil
	case "signal.target.ancestors.euid":
		return &eval.IntArrayEvaluator{
			EvalFnc: func(ctx *eval.Context) []int {
				if ptr := ctx.Cache[field]; ptr != nil {
					if result := (*[]int)(ptr); result != nil {
						return *result
					}
				}
				var results []int
				iterator := &model.ProcessAncestorsIterator{}
				value := iterator.Front(ctx)
				for value != nil {
					element := (*model.ProcessCacheEntry)(value)
					result := int(element.ProcessContext.Process.Credentials.EUID)
					results = append(results, result)
					value = iterator.Next()
				}
				ctx.Cache[field] = unsafe.Pointer(&results)
				return results
			}, Field: field,
			Weight: eval.IteratorWeight,
		}, nil
	case "signal.target.ancestors.euser":
		return &eval.StringArrayEvaluator{
			EvalFnc: func(ctx *eval.Context) []string {
				if ptr := ctx.Cache[field]; ptr != nil {
					if result := (*[]string)(ptr); result != nil {
						return *result
					}
				}
				var results []string
				iterator := &model.ProcessAncestorsIterator{}
				value := iterator.Front(ctx)
				for value != nil {
					element := (*model.ProcessCacheEntry)(value)
					result := element.ProcessContext.Process.Credentials.EUser
					results = append(results, result)
					value = iterator.Next()
				}
				ctx.Cache[field] = unsafe.Pointer(&results)
				return results
			}, Field: field,
			Weight: eval.IteratorWeight,
		}, nil
	case "signal.target.ancestors.file.change_time":
		return &eval.IntArrayEvaluator{
			EvalFnc: func(ctx *eval.Context) []int {
				if ptr := ctx.Cache[field]; ptr != nil {
					if result := (*[]int)(ptr); result != nil {
						return *result
					}
				}
				var results []int
				iterator := &model.ProcessAncestorsIterator{}
				value := iterator.Front(ctx)
				for value != nil {
					element := (*model.ProcessCacheEntry)(value)
					result := int(element.ProcessContext.Process.FileEvent.FileFields.CTime)
					results = append(results, result)
					value = iterator.Next()
				}
				ctx.Cache[field] = unsafe.Pointer(&results)
				return results
			}, Field: field,
			Weight: eval.IteratorWeight,
		}, nil
	case "signal.target.ancestors.file.filesystem":
		return &eval.StringArrayEvaluator{
			EvalFnc: func(ctx *eval.Context) []string {
				if ptr := ctx.Cache[field]; ptr != nil {
					if result := (*[]string)(ptr); result != nil {
						return *result
					}
				}
				var results []string
				iterator := &model.ProcessAncestorsIterator{}
				value := iterator.Front(ctx)
				for value != nil {
					element := (*model.ProcessCacheEntry)(value)
					event := GetEvent(ctx)
					result := event.ResolveFileFilesystem(&element.ProcessContext.Process.FileEvent)
					results = append(results, result)
					value = iterator.Next()
				}
				ctx.Cache[field] = unsafe.Pointer(&results)
				return results
			}, Field: field,
			Weight: eval.IteratorWeight,
		}, nil
	case "signal.target.ancestors.file.gid":
		return &eval.IntArrayEvaluator{
			EvalFnc: func(ctx *eval.Context) []int {
				if ptr := ctx.Cache[field]; ptr != nil {
					if result := (*[]int)(ptr); result != nil {
						return *result
					}
				}
				var results []int
				iterator := &model.ProcessAncestorsIterator{}
				value := iterator.Front(ctx)
				for value != nil {
					element := (*model.ProcessCacheEntry)(value)
					result := int(element.ProcessContext.Process.FileEvent.FileFields.GID)
					results = append(results, result)
					value = iterator.Next()
				}
				ctx.Cache[field] = unsafe.Pointer(&results)
				return results
			}, Field: field,
			Weight: eval.IteratorWeight,
		}, nil
	case "signal.target.ancestors.file.group":
		return &eval.StringArrayEvaluator{
			EvalFnc: func(ctx *eval.Context) []string {
				if ptr := ctx.Cache[field]; ptr != nil {
					if result := (*[]string)(ptr); result != nil {
						return *result
					}
				}
				var results []string
				iterator := &model.ProcessAncestorsIterator{}
				value := iterator.Front(ctx)
				for value != nil {
					element := (*model.ProcessCacheEntry)(value)
					event := GetEvent(ctx)
					result := event.ResolveFileFieldsGroup(&element.ProcessContext.Process.FileEvent.FileFields)
					results = append(results, result)
					value = iterator.Next()
				}
				ctx.Cache[field] = unsafe.Pointer(&results)
				return results
			}, Field: field,
			Weight: eval.IteratorWeight,
		}, nil
	case "signal.target.ancestors.file.in_upper_layer":
		return &eval.BoolArrayEvaluator{
			EvalFnc: func(ctx *eval.Context) []bool {
				if ptr := ctx.Cache[field]; ptr != nil {
					if result := (*[]bool)(ptr); result != nil {
						return *result
					}
				}
				var results []bool
				iterator := &model.ProcessAncestorsIterator{}
				value := iterator.Front(ctx)
				for value != nil {
					element := (*model.ProcessCacheEntry)(value)
					event := GetEvent(ctx)
					result := event.ResolveFileFieldsInUpperLayer(&element.ProcessContext.Process.FileEvent.FileFields)
					results = append(results, result)
					value = iterator.Next()
				}
				ctx.Cache[field] = unsafe.Pointer(&results)
				return results
			}, Field: field,
			Weight: eval.IteratorWeight,
		}, nil
	case "signal.target.ancestors.file.inode":
		return &eval.IntArrayEvaluator{
			EvalFnc: func(ctx *eval.Context) []int {
				if ptr := ctx.Cache[field]; ptr != nil {
					if result := (*[]int)(ptr); result != nil {
						return *result
					}
				}
				var results []int
				iterator := &model.ProcessAncestorsIterator{}
				value := iterator.Front(ctx)
				for value != nil {
					element := (*model.ProcessCacheEntry)(value)
					result := int(element.ProcessContext.Process.FileEvent.FileFields.Inode)
					results = append(results, result)
					value = iterator.Next()
				}
				ctx.Cache[field] = unsafe.Pointer(&results)
				return results
			}, Field: field,
			Weight: eval.IteratorWeight,
		}, nil
	case "signal.target.ancestors.file.mode":
		return &eval.IntArrayEvaluator{
			EvalFnc: func(ctx *eval.Context) []int {
				if ptr := ctx.Cache[field]; ptr != nil {
					if result := (*[]int)(ptr); result != nil {
						return *result
					}
				}
				var results []int
				iterator := &model.ProcessAncestorsIterator{}
				value := iterator.Front(ctx)
				for value != nil {
					element := (*model.ProcessCacheEntry)(value)
					result := int(element.ProcessContext.Process.FileEvent.FileFields.Mode)
					results = append(results, result)
					value = iterator.Next()
				}
				ctx.Cache[field] = unsafe.Pointer(&results)
				return results
			}, Field: field,
			Weight: eval.IteratorWeight,
		}, nil
	case "signal.target.ancestors.file.modification_time":
		return &eval.IntArrayEvaluator{
			EvalFnc: func(ctx *eval.Context) []int {
				if ptr := ctx.Cache[field]; ptr != nil {
					if result := (*[]int)(ptr); result != nil {
						return *result
					}
				}
				var results []int
				iterator := &model.ProcessAncestorsIterator{}
				value := iterator.Front(ctx)
				for value != nil {
					element := (*model.ProcessCacheEntry)(value)
					result := int(element.ProcessContext.Process.FileEvent.FileFields.MTime)
					results = append(results, result)
					value = iterator.Next()
				}
				ctx.Cache[field] = unsafe.Pointer(&results)
				return results
			}, Field: field,
			Weight: eval.IteratorWeight,
		}, nil
	case "signal.target.ancestors.file.mount_id":
		return &eval.IntArrayEvaluator{
			EvalFnc: func(ctx *eval.Context) []int {
				if ptr := ctx.Cache[field]; ptr != nil {
					if result := (*[]int)(ptr); result != nil {
						return *result
					}
				}
				var results []int
				iterator := &model.ProcessAncestorsIterator{}
				value := iterator.Front(ctx)
				for value != nil {
					element := (*model.ProcessCacheEntry)(value)
					result := int(element.ProcessContext.Process.FileEvent.FileFields.MountID)
					results = append(results, result)
					value = iterator.Next()
				}
				ctx.Cache[field] = unsafe.Pointer(&results)
				return results
			}, Field: field,
			Weight: eval.IteratorWeight,
		}, nil
	case "signal.target.ancestors.file.name":
		return &eval.StringArrayEvaluator{
			OpOverrides: model.ProcessSymlinkBasename,
			EvalFnc: func(ctx *eval.Context) []string {
				if ptr := ctx.Cache[field]; ptr != nil {
					if result := (*[]string)(ptr); result != nil {
						return *result
					}
				}
				var results []string
				iterator := &model.ProcessAncestorsIterator{}
				value := iterator.Front(ctx)
				for value != nil {
					element := (*model.ProcessCacheEntry)(value)
					event := GetEvent(ctx)
					result := event.ResolveFileBasename(&element.ProcessContext.Process.FileEvent)
					results = append(results, result)
					value = iterator.Next()
				}
				ctx.Cache[field] = unsafe.Pointer(&results)
				return results
			}, Field: field,
			Weight: eval.IteratorWeight,
		}, nil
	case "signal.target.ancestors.file.path":
		return &eval.StringArrayEvaluator{
			OpOverrides: model.ProcessSymlinkPathname,
			EvalFnc: func(ctx *eval.Context) []string {
				if ptr := ctx.Cache[field]; ptr != nil {
					if result := (*[]string)(ptr); result != nil {
						return *result
					}
				}
				var results []string
				iterator := &model.ProcessAncestorsIterator{}
				value := iterator.Front(ctx)
				for value != nil {
					element := (*model.ProcessCacheEntry)(value)
					event := GetEvent(ctx)
					result := event.ResolveFilePath(&element.ProcessContext.Process.FileEvent)
					results = append(results, result)
					value = iterator.Next()
				}
				ctx.Cache[field] = unsafe.Pointer(&results)
				return results
			}, Field: field,
			Weight: eval.IteratorWeight,
		}, nil
	case "signal.target.ancestors.file.rights":
		return &eval.IntArrayEvaluator{
			EvalFnc: func(ctx *eval.Context) []int {
				if ptr := ctx.Cache[field]; ptr != nil {
					if result := (*[]int)(ptr); result != nil {
						return *result
					}
				}
				var results []int
				iterator := &model.ProcessAncestorsIterator{}
				value := iterator.Front(ctx)
				for value != nil {
					element := (*model.ProcessCacheEntry)(value)
					event := GetEvent(ctx)
					result := int(event.ResolveRights(&element.ProcessContext.Process.FileEvent.FileFields))
					results = append(results, result)
					value = iterator.Next()
				}
				ctx.Cache[field] = unsafe.Pointer(&results)
				return results
			}, Field: field,
			Weight: eval.IteratorWeight,
		}, nil
	case "signal.target.ancestors.file.uid":
		return &eval.IntArrayEvaluator{
			EvalFnc: func(ctx *eval.Context) []int {
				if ptr := ctx.Cache[field]; ptr != nil {
					if result := (*[]int)(ptr); result != nil {
						return *result
					}
				}
				var results []int
				iterator := &model.ProcessAncestorsIterator{}
				value := iterator.Front(ctx)
				for value != nil {
					element := (*model.ProcessCacheEntry)(value)
					result := int(element.ProcessContext.Process.FileEvent.FileFields.UID)
					results = append(results, result)
					value = iterator.Next()
				}
				ctx.Cache[field] = unsafe.Pointer(&results)
				return results
			}, Field: field,
			Weight: eval.IteratorWeight,
		}, nil
	case "signal.target.ancestors.file.user":
		return &eval.StringArrayEvaluator{
			EvalFnc: func(ctx *eval.Context) []string {
				if ptr := ctx.Cache[field]; ptr != nil {
					if result := (*[]string)(ptr); result != nil {
						return *result
					}
				}
				var results []string
				iterator := &model.ProcessAncestorsIterator{}
				value := iterator.Front(ctx)
				for value != nil {
					element := (*model.ProcessCacheEntry)(value)
					event := GetEvent(ctx)
					result := event.ResolveFileFieldsUser(&element.ProcessContext.Process.FileEvent.FileFields)
					results = append(results, result)
					value = iterator.Next()
				}
				ctx.Cache[field] = unsafe.Pointer(&results)
				return results
			}, Field: field,
			Weight: eval.IteratorWeight,
		}, nil
	case "signal.target.ancestors.fsgid":
		return &eval.IntArrayEvaluator{
			EvalFnc: func(ctx *eval.Context) []int {
				if ptr := ctx.Cache[field]; ptr != nil {
					if result := (*[]int)(ptr); result != nil {
						return *result
					}
				}
				var results []int
				iterator := &model.ProcessAncestorsIterator{}
				value := iterator.Front(ctx)
				for value != nil {
					element := (*model.ProcessCacheEntry)(value)
					result := int(element.ProcessContext.Process.Credentials.FSGID)
					results = append(results, result)
					value = iterator.Next()
				}
				ctx.Cache[field] = unsafe.Pointer(&results)
				return results
			}, Field: field,
			Weight: eval.IteratorWeight,
		}, nil
	case "signal.target.ancestors.fsgroup":
		return &eval.StringArrayEvaluator{
			EvalFnc: func(ctx *eval.Context) []string {
				if ptr := ctx.Cache[field]; ptr != nil {
					if result := (*[]string)(ptr); result != nil {
						return *result
					}
				}
				var results []string
				iterator := &model.ProcessAncestorsIterator{}
				value := iterator.Front(ctx)
				for value != nil {
					element := (*model.ProcessCacheEntry)(value)
					result := element.ProcessContext.Process.Credentials.FSGroup
					results = append(results, result)
					value = iterator.Next()
				}
				ctx.Cache[field] = unsafe.Pointer(&results)
				return results
			}, Field: field,
			Weight: eval.IteratorWeight,
		}, nil
	case "signal.target.ancestors.fsuid":
		return &eval.IntArrayEvaluator{
			EvalFnc: func(ctx *eval.Context) []int {
				if ptr := ctx.Cache[field]; ptr != nil {
					if result := (*[]int)(ptr); result != nil {
						return *result
					}
				}
				var results []int
				iterator := &model.ProcessAncestorsIterator{}
				value := iterator.Front(ctx)
				for value != nil {
					element := (*model.ProcessCacheEntry)(value)
					result := int(element.ProcessContext.Process.Credentials.FSUID)
					results = append(results, result)
					value = iterator.Next()
				}
				ctx.Cache[field] = unsafe.Pointer(&results)
				return results
			}, Field: field,
			Weight: eval.IteratorWeight,
		}, nil
	case "signal.target.ancestors.fsuser":
		return &eval.StringArrayEvaluator{
			EvalFnc: func(ctx *eval.Context) []string {
				if ptr := ctx.Cache[field]; ptr != nil {
					if result := (*[]string)(ptr); result != nil {
						return *result
					}
				}
				var results []string
				iterator := &model.ProcessAncestorsIterator{}
				value := iterator.Front(ctx)
				for value != nil {
					element := (*model.ProcessCacheEntry)(value)
					result := element.ProcessContext.Process.Credentials.FSUser
					results = append(results, result)
					value = iterator.Next()
				}
				ctx.Cache[field] = unsafe.Pointer(&results)
				return results
			}, Field: field,
			Weight: eval.IteratorWeight,
		}, nil
	case "signal.target.ancestors.gid":
		return &eval.IntArrayEvaluator{
			EvalFnc: func(ctx *eval.Context) []int {
				if ptr := ctx.Cache[field]; ptr != nil {
					if result := (*[]int)(ptr); result != nil {
						return *result
					}
				}
				var results []int
				iterator := &model.ProcessAncestorsIterator{}
				value := iterator.Front(ctx)
				for value != nil {
					element := (*model.ProcessCacheEntry)(value)
					result := int(element.ProcessContext.Process.Credentials.GID)
					results = append(results, result)
					value = iterator.Next()
				}
				ctx.Cache[field] = unsafe.Pointer(&results)
				return results
			}, Field: field,
			Weight: eval.IteratorWeight,
		}, nil
	case "signal.target.ancestors.group":
		return &eval.StringArrayEvaluator{
			EvalFnc: func(ctx *eval.Context) []string {
				if ptr := ctx.Cache[field]; ptr != nil {
					if result := (*[]string)(ptr); result != nil {
						return *result
					}
				}
				var results []string
				iterator := &model.ProcessAncestorsIterator{}
				value := iterator.Front(ctx)
				for value != nil {
					element := (*model.ProcessCacheEntry)(value)
					result := element.ProcessContext.Process.Credentials.Group
					results = append(results, result)
					value = iterator.Next()
				}
				ctx.Cache[field] = unsafe.Pointer(&results)
				return results
			}, Field: field,
			Weight: eval.IteratorWeight,
		}, nil
	case "signal.target.ancestors.is_thread":
		return &eval.BoolArrayEvaluator{
			EvalFnc: func(ctx *eval.Context) []bool {
				if ptr := ctx.Cache[field]; ptr != nil {
					if result := (*[]bool)(ptr); result != nil {
						return *result
					}
				}
				var results []bool
				iterator := &model.ProcessAncestorsIterator{}
				value := iterator.Front(ctx)
				for value != nil {
					element := (*model.ProcessCacheEntry)(value)
					result := element.ProcessContext.Process.IsThread
					results = append(results, result)
					value = iterator.Next()
				}
				ctx.Cache[field] = unsafe.Pointer(&results)
				return results
			}, Field: field,
			Weight: eval.IteratorWeight,
		}, nil
	case "signal.target.ancestors.pid":
		return &eval.IntArrayEvaluator{
			EvalFnc: func(ctx *eval.Context) []int {
				if ptr := ctx.Cache[field]; ptr != nil {
					if result := (*[]int)(ptr); result != nil {
						return *result
					}
				}
				var results []int
				iterator := &model.ProcessAncestorsIterator{}
				value := iterator.Front(ctx)
				for value != nil {
					element := (*model.ProcessCacheEntry)(value)
					result := int(element.ProcessContext.Process.PIDContext.Pid)
					results = append(results, result)
					value = iterator.Next()
				}
				ctx.Cache[field] = unsafe.Pointer(&results)
				return results
			}, Field: field,
			Weight: eval.IteratorWeight,
		}, nil
	case "signal.target.ancestors.ppid":
		return &eval.IntArrayEvaluator{
			EvalFnc: func(ctx *eval.Context) []int {
				if ptr := ctx.Cache[field]; ptr != nil {
					if result := (*[]int)(ptr); result != nil {
						return *result
					}
				}
				var results []int
				iterator := &model.ProcessAncestorsIterator{}
				value := iterator.Front(ctx)
				for value != nil {
					element := (*model.ProcessCacheEntry)(value)
					result := int(element.ProcessContext.Process.PPid)
					results = append(results, result)
					value = iterator.Next()
				}
				ctx.Cache[field] = unsafe.Pointer(&results)
				return results
			}, Field: field,
			Weight: eval.IteratorWeight,
		}, nil
	case "signal.target.ancestors.tid":
		return &eval.IntArrayEvaluator{
			EvalFnc: func(ctx *eval.Context) []int {
				if ptr := ctx.Cache[field]; ptr != nil {
					if result := (*[]int)(ptr); result != nil {
						return *result
					}
				}
				var results []int
				iterator := &model.ProcessAncestorsIterator{}
				value := iterator.Front(ctx)
				for value != nil {
					element := (*model.ProcessCacheEntry)(value)
					result := int(element.ProcessContext.Process.PIDContext.Tid)
					results = append(results, result)
					value = iterator.Next()
				}
				ctx.Cache[field] = unsafe.Pointer(&results)
				return results
			}, Field: field,
			Weight: eval.IteratorWeight,
		}, nil
	case "signal.target.ancestors.tty_name":
		return &eval.StringArrayEvaluator{
			EvalFnc: func(ctx *eval.Context) []string {
				if ptr := ctx.Cache[field]; ptr != nil {
					if result := (*[]string)(ptr); result != nil {
						return *result
					}
				}
				var results []string
				iterator := &model.ProcessAncestorsIterator{}
				value := iterator.Front(ctx)
				for value != nil {
					element := (*model.ProcessCacheEntry)(value)
					result := element.ProcessContext.Process.TTYName
					results = append(results, result)
					value = iterator.Next()
				}
				ctx.Cache[field] = unsafe.Pointer(&results)
				return results
			}, Field: field,
			Weight: eval.IteratorWeight,
		}, nil
	case "signal.target.ancestors.uid":
		return &eval.IntArrayEvaluator{
			EvalFnc: func(ctx *eval.Context) []int {
				if ptr := ctx.Cache[field]; ptr != nil {
					if result := (*[]int)(ptr); result != nil {
						return *result
					}
				}
				var results []int
				iterator := &model.ProcessAncestorsIterator{}
				value := iterator.Front(ctx)
				for value != nil {
					element := (*model.ProcessCacheEntry)(value)
					result := int(element.ProcessContext.Process.Credentials.UID)
					results = append(results, result)
					value = iterator.Next()
				}
				ctx.Cache[field] = unsafe.Pointer(&results)
				return results
			}, Field: field,
			Weight: eval.IteratorWeight,
		}, nil
	case "signal.target.ancestors.user":
		return &eval.StringArrayEvaluator{
			EvalFnc: func(ctx *eval.Context) []string {
				if ptr := ctx.Cache[field]; ptr != nil {
					if result := (*[]string)(ptr); result != nil {
						return *result
					}
				}
				var results []string
				iterator := &model.ProcessAncestorsIterator{}
				value := iterator.Front(ctx)
				for value != nil {
					element := (*model.ProcessCacheEntry)(value)
					result := element.ProcessContext.Process.Credentials.User
					results = append(results, result)
					value = iterator.Next()
				}
				ctx.Cache[field] = unsafe.Pointer(&results)
				return results
			}, Field: field,
			Weight: eval.IteratorWeight,
		}, nil
	case "signal.target.args":
		return &eval.StringEvaluator{
			EvalFnc: func(ctx *eval.Context) string {
				event := GetEvent(ctx)
				return event.ResolveProcessArgs(&event.Signal.Target.Process)
			},
			Field:  field,
			Weight: 100 * eval.HandlerWeight,
		}, nil
	case "signal.target.args_flags":
		return &eval.StringArrayEvaluator{
			EvalFnc: func(ctx *eval.Context) []string {
				event := GetEvent(ctx)
				return event.ResolveProcessArgsFlags(&event.Signal.Target.Process)
			},
			Field:  field,
			Weight: eval.HandlerWeight,
		}, nil
	case "signal.target.args_options":
		return &eval.StringArrayEvaluator{
			EvalFnc: func(ctx *eval.Context) []string {
				event := GetEvent(ctx)
				return event.ResolveProcessArgsOptions(&event.Signal.Target.Process)
			},
			Field:  field,
			Weight: eval.HandlerWeight,
		}, nil
	case "signal.target.args_truncated":
		return &eval.BoolEvaluator{
			EvalFnc: func(ctx *eval.Context) bool {
				event := GetEvent(ctx)
				return event.ResolveProcessArgsTruncated(&event.Signal.Target.Process)
			},
			Field:  field,
			Weight: eval.HandlerWeight,
		}, nil
	case "signal.target.argv":
		return &eval.StringArrayEvaluator{
			EvalFnc: func(ctx *eval.Context) []string {
				event := GetEvent(ctx)
				return event.ResolveProcessArgv(&event.Signal.Target.Process)
			},
			Field:  field,
			Weight: 100 * eval.HandlerWeight,
		}, nil
	case "signal.target.argv0":
		return &eval.StringEvaluator{
			EvalFnc: func(ctx *eval.Context) string {
				event := GetEvent(ctx)
				return event.ResolveProcessArgv0(&event.Signal.Target.Process)
			},
			Field:  field,
			Weight: 100 * eval.HandlerWeight,
		}, nil
	case "signal.target.cap_effective":
		return &eval.IntEvaluator{
			EvalFnc: func(ctx *eval.Context) int {
				event := GetEvent(ctx)
				return int(event.Signal.Target.Process.Credentials.CapEffective)
			},
			Field:  field,
			Weight: eval.FunctionWeight,
		}, nil
	case "signal.target.cap_permitted":
		return &eval.IntEvaluator{
			EvalFnc: func(ctx *eval.Context) int {
				event := GetEvent(ctx)
				return int(event.Signal.Target.Process.Credentials.CapPermitted)
			},
			Field:  field,
			Weight: eval.FunctionWeight,
		}, nil
	case "signal.target.comm":
		return &eval.StringEvaluator{
			EvalFnc: func(ctx *eval.Context) string {
				event := GetEvent(ctx)
				return event.Signal.Target.Process.Comm
			},
			Field:  field,
			Weight: eval.FunctionWeight,
		}, nil
	case "signal.target.container.id":
		return &eval.StringEvaluator{
			EvalFnc: func(ctx *eval.Context) string {
				event := GetEvent(ctx)
				return event.Signal.Target.Process.ContainerID
			},
			Field:  field,
			Weight: eval.FunctionWeight,
		}, nil
	case "signal.target.cookie":
		return &eval.IntEvaluator{
			EvalFnc: func(ctx *eval.Context) int {
				event := GetEvent(ctx)
				return int(event.Signal.Target.Process.Cookie)
			},
			Field:  field,
			Weight: eval.FunctionWeight,
		}, nil
	case "signal.target.created_at":
		return &eval.IntEvaluator{
			EvalFnc: func(ctx *eval.Context) int {
				event := GetEvent(ctx)
				return int(event.ResolveProcessCreatedAt(&event.Signal.Target.Process))
			},
			Field:  field,
			Weight: eval.HandlerWeight,
		}, nil
	case "signal.target.egid":
		return &eval.IntEvaluator{
			EvalFnc: func(ctx *eval.Context) int {
				event := GetEvent(ctx)
				return int(event.Signal.Target.Process.Credentials.EGID)
			},
			Field:  field,
			Weight: eval.FunctionWeight,
		}, nil
	case "signal.target.egroup":
		return &eval.StringEvaluator{
			EvalFnc: func(ctx *eval.Context) string {
				event := GetEvent(ctx)
				return event.Signal.Target.Process.Credentials.EGroup
			},
			Field:  field,
			Weight: eval.FunctionWeight,
		}, nil
	case "signal.target.envp":
		return &eval.StringArrayEvaluator{
			EvalFnc: func(ctx *eval.Context) []string {
				event := GetEvent(ctx)
				return event.ResolveProcessEnvp(&event.Signal.Target.Process)
			},
			Field:  field,
			Weight: eval.HandlerWeight,
		}, nil
	case "signal.target.envs":
		return &eval.StringArrayEvaluator{
			EvalFnc: func(ctx *eval.Context) []string {
				event := GetEvent(ctx)
				return event.ResolveProcessEnvs(&event.Signal.Target.Process)
			},
			Field:  field,
			Weight: eval.HandlerWeight,
		}, nil
	case "signal.target.envs_truncated":
		return &eval.BoolEvaluator{
			EvalFnc: func(ctx *eval.Context) bool {
				event := GetEvent(ctx)
				return event.ResolveProcessEnvsTruncated(&event.Signal.Target.Process)
			},
			Field:  field,
			Weight: eval.HandlerWeight,
		}, nil
	case "signal.target.euid":
		return &eval.IntEvaluator{
			EvalFnc: func(ctx *eval.Context) int {
				event := GetEvent(ctx)
				return int(event.Signal.Target.Process.Credentials.EUID)
			},
			Field:  field,
			Weight: eval.FunctionWeight,
		}, nil
	case "signal.target.euser":
		return &eval.StringEvaluator{
			EvalFnc: func(ctx *eval.Context) string {
				event := GetEvent(ctx)
				return event.Signal.Target.Process.Credentials.EUser
			},
			Field:  field,
			Weight: eval.FunctionWeight,
		}, nil
	case "signal.target.file.change_time":
		return &eval.IntEvaluator{
			EvalFnc: func(ctx *eval.Context) int {
				event := GetEvent(ctx)
				return int(event.Signal.Target.Process.FileEvent.FileFields.CTime)
			},
			Field:  field,
			Weight: eval.FunctionWeight,
		}, nil
	case "signal.target.file.filesystem":
		return &eval.StringEvaluator{
			EvalFnc: func(ctx *eval.Context) string {
				event := GetEvent(ctx)
				return event.ResolveFileFilesystem(&event.Signal.Target.Process.FileEvent)
			},
			Field:  field,
			Weight: eval.HandlerWeight,
		}, nil
	case "signal.target.file.gid":
		return &eval.IntEvaluator{
			EvalFnc: func(ctx *eval.Context) int {
				event := GetEvent(ctx)
				return int(event.Signal.Target.Process.FileEvent.FileFields.GID)
			},
			Field:  field,
			Weight: eval.FunctionWeight,
		}, nil
	case "signal.target.file.group":
		return &eval.StringEvaluator{
			EvalFnc: func(ctx *eval.Context) string {
				event := GetEvent(ctx)
				return event.ResolveFileFieldsGroup(&event.Signal.Target.Process.FileEvent.FileFields)
			},
			Field:  field,
			Weight: eval.HandlerWeight,
		}, nil
	case "signal.target.file.in_upper_layer":
		return &eval.BoolEvaluator{
			EvalFnc: func(ctx *eval.Context) bool {
				event := GetEvent(ctx)
				return event.ResolveFileFieldsInUpperLayer(&event.Signal.Target.Process.FileEvent.FileFields)
			},
			Field:  field,
			Weight: eval.HandlerWeight,
		}, nil
	case "signal.target.file.inode":
		return &eval.IntEvaluator{
			EvalFnc: func(ctx *eval.Context) int {
				event := GetEvent(ctx)
				return int(event.Signal.Target.Process.FileEvent.FileFields.Inode)
			},
			Field:  field,
			Weight: eval.FunctionWeight,
		}, nil
	case "signal.target.file.mode":
		return &eval.IntEvaluator{
			EvalFnc: func(ctx *eval.Context) int {
				event := GetEvent(ctx)
				return int(event.Signal.Target.Process.FileEvent.FileFields.Mode)
			},
			Field:  field,
			Weight: eval.FunctionWeight,
		}, nil
	case "signal.target.file.modification_time":
		return &eval.IntEvaluator{
			EvalFnc: func(ctx *eval.Context) int {
				event := GetEvent(ctx)
				return int(event.Signal.Target.Process.FileEvent.FileFields.MTime)
			},
			Field:  field,
			Weight: eval.FunctionWeight,
		}, nil
	case "signal.target.file.mount_id":
		return &eval.IntEvaluator{
			EvalFnc: func(ctx *eval.Context) int {
				event := GetEvent(ctx)
				return int(event.Signal.Target.Process.FileEvent.FileFields.MountID)
			},
			Field:  field,
			Weight: eval.FunctionWeight,
		}, nil
	case "signal.target.file.name":
		return &eval.StringEvaluator{
			OpOverrides: model.ProcessSymlinkBasename,
			EvalFnc: func(ctx *eval.Context) string {
				event := GetEvent(ctx)
				return event.ResolveFileBasename(&event.Signal.Target.Process.FileEvent)
			},
			Field:  field,
			Weight: eval.HandlerWeight,
		}, nil
	case "signal.target.file.path":
		return &eval.StringEvaluator{
			OpOverrides: model.ProcessSymlinkPathname,
			EvalFnc: func(ctx *eval.Context) string {
				event := GetEvent(ctx)
				return event.ResolveFilePath(&event.Signal.Target.Process.FileEvent)
			},
			Field:  field,
			Weight: eval.HandlerWeight,
		}, nil
	case "signal.target.file.rights":
		return &eval.IntEvaluator{
			EvalFnc: func(ctx *eval.Context) int {
				event := GetEvent(ctx)
				return int(event.ResolveRights(&event.Signal.Target.Process.FileEvent.FileFields))
			},
			Field:  field,
			Weight: eval.HandlerWeight,
		}, nil
	case "signal.target.file.uid":
		return &eval.IntEvaluator{
			EvalFnc: func(ctx *eval.Context) int {
				event := GetEvent(ctx)
				return int(event.Signal.Target.Process.FileEvent.FileFields.UID)
			},
			Field:  field,
			Weight: eval.FunctionWeight,
		}, nil
	case "signal.target.file.user":
		return &eval.StringEvaluator{
			EvalFnc: func(ctx *eval.Context) string {
				event := GetEvent(ctx)
				return event.ResolveFileFieldsUser(&event.Signal.Target.Process.FileEvent.FileFields)
			},
			Field:  field,
			Weight: eval.HandlerWeight,
		}, nil
	case "signal.target.fsgid":
		return &eval.IntEvaluator{
			EvalFnc: func(ctx *eval.Context) int {
				event := GetEvent(ctx)
				return int(event.Signal.Target.Process.Credentials.FSGID)
			},
			Field:  field,
			Weight: eval.FunctionWeight,
		}, nil
	case "signal.target.fsgroup":
		return &eval.StringEvaluator{
			EvalFnc: func(ctx *eval.Context) string {
				event := GetEvent(ctx)
				return event.Signal.Target.Process.Credentials.FSGroup
			},
			Field:  field,
			Weight: eval.FunctionWeight,
		}, nil
	case "signal.target.fsuid":
		return &eval.IntEvaluator{
			EvalFnc: func(ctx *eval.Context) int {
				event := GetEvent(ctx)
				return int(event.Signal.Target.Process.Credentials.FSUID)
			},
			Field:  field,
			Weight: eval.FunctionWeight,
		}, nil
	case "signal.target.fsuser":
		return &eval.StringEvaluator{
			EvalFnc: func(ctx *eval.Context) string {
				event := GetEvent(ctx)
				return event.Signal.Target.Process.Credentials.FSUser
			},
			Field:  field,
			Weight: eval.FunctionWeight,
		}, nil
	case "signal.target.gid":
		return &eval.IntEvaluator{
			EvalFnc: func(ctx *eval.Context) int {
				event := GetEvent(ctx)
				return int(event.Signal.Target.Process.Credentials.GID)
			},
			Field:  field,
			Weight: eval.FunctionWeight,
		}, nil
	case "signal.target.group":
		return &eval.StringEvaluator{
			EvalFnc: func(ctx *eval.Context) string {
				event := GetEvent(ctx)
				return event.Signal.Target.Process.Credentials.Group
			},
			Field:  field,
			Weight: eval.FunctionWeight,
		}, nil
	case "signal.target.is_thread":
		return &eval.BoolEvaluator{
			EvalFnc: func(ctx *eval.Context) bool {
				event := GetEvent(ctx)
				return event.Signal.Target.Process.IsThread
			},
			Field:  field,
			Weight: eval.FunctionWeight,
		}, nil
	case "signal.target.pid":
		return &eval.IntEvaluator{
			EvalFnc: func(ctx *eval.Context) int {
				event := GetEvent(ctx)
				return int(event.Signal.Target.Process.PIDContext.Pid)
			},
			Field:  field,
			Weight: eval.FunctionWeight,
		}, nil
	case "signal.target.ppid":
		return &eval.IntEvaluator{
			EvalFnc: func(ctx *eval.Context) int {
				event := GetEvent(ctx)
				return int(event.Signal.Target.Process.PPid)
			},
			Field:  field,
			Weight: eval.FunctionWeight,
		}, nil
	case "signal.target.tid":
		return &eval.IntEvaluator{
			EvalFnc: func(ctx *eval.Context) int {
				event := GetEvent(ctx)
				return int(event.Signal.Target.Process.PIDContext.Tid)
			},
			Field:  field,
			Weight: eval.FunctionWeight,
		}, nil
	case "signal.target.tty_name":
		return &eval.StringEvaluator{
			EvalFnc: func(ctx *eval.Context) string {
				event := GetEvent(ctx)
				return event.Signal.Target.Process.TTYName
			},
			Field:  field,
			Weight: eval.FunctionWeight,
		}, nil
	case "signal.target.uid":
		return &eval.IntEvaluator{
			EvalFnc: func(ctx *eval.Context) int {
				event := GetEvent(ctx)
				return int(event.Signal.Target.Process.Credentials.UID)
			},
			Field:  field,
			Weight: eval.FunctionWeight,
		}, nil
	case "signal.target.user":
		return &eval.StringEvaluator{
			EvalFnc: func(ctx *eval.Context) string {
				event := GetEvent(ctx)
				return event.Signal.Target.Process.Credentials.User
			},
			Field:  field,
			Weight: eval.FunctionWeight,
		}, nil
	case "signal.type":
		return &eval.IntEvaluator{
			EvalFnc: func(ctx *eval.Context) int {
				event := GetEvent(ctx)
				return int(event.Signal.Type)
			},
			Field:  field,
			Weight: eval.FunctionWeight,
		}, nil
	case "splice.file.change_time":
		return &eval.IntEvaluator{
			EvalFnc: func(ctx *eval.Context) int {
				event := GetEvent(ctx)
				return int(event.Splice.File.FileFields.CTime)
			},
			Field:  field,
			Weight: eval.FunctionWeight,
		}, nil
	case "splice.file.filesystem":
		return &eval.StringEvaluator{
			EvalFnc: func(ctx *eval.Context) string {
				event := GetEvent(ctx)
				return event.ResolveFileFilesystem(&event.Splice.File)
			},
			Field:  field,
			Weight: eval.HandlerWeight,
		}, nil
	case "splice.file.gid":
		return &eval.IntEvaluator{
			EvalFnc: func(ctx *eval.Context) int {
				event := GetEvent(ctx)
				return int(event.Splice.File.FileFields.GID)
			},
			Field:  field,
			Weight: eval.FunctionWeight,
		}, nil
	case "splice.file.group":
		return &eval.StringEvaluator{
			EvalFnc: func(ctx *eval.Context) string {
				event := GetEvent(ctx)
				return event.ResolveFileFieldsGroup(&event.Splice.File.FileFields)
			},
			Field:  field,
			Weight: eval.HandlerWeight,
		}, nil
	case "splice.file.in_upper_layer":
		return &eval.BoolEvaluator{
			EvalFnc: func(ctx *eval.Context) bool {
				event := GetEvent(ctx)
				return event.ResolveFileFieldsInUpperLayer(&event.Splice.File.FileFields)
			},
			Field:  field,
			Weight: eval.HandlerWeight,
		}, nil
	case "splice.file.inode":
		return &eval.IntEvaluator{
			EvalFnc: func(ctx *eval.Context) int {
				event := GetEvent(ctx)
				return int(event.Splice.File.FileFields.Inode)
			},
			Field:  field,
			Weight: eval.FunctionWeight,
		}, nil
	case "splice.file.mode":
		return &eval.IntEvaluator{
			EvalFnc: func(ctx *eval.Context) int {
				event := GetEvent(ctx)
				return int(event.Splice.File.FileFields.Mode)
			},
			Field:  field,
			Weight: eval.FunctionWeight,
		}, nil
	case "splice.file.modification_time":
		return &eval.IntEvaluator{
			EvalFnc: func(ctx *eval.Context) int {
				event := GetEvent(ctx)
				return int(event.Splice.File.FileFields.MTime)
			},
			Field:  field,
			Weight: eval.FunctionWeight,
		}, nil
	case "splice.file.mount_id":
		return &eval.IntEvaluator{
			EvalFnc: func(ctx *eval.Context) int {
				event := GetEvent(ctx)
				return int(event.Splice.File.FileFields.MountID)
			},
			Field:  field,
			Weight: eval.FunctionWeight,
		}, nil
	case "splice.file.name":
		return &eval.StringEvaluator{
			OpOverrides: model.ProcessSymlinkBasename,
			EvalFnc: func(ctx *eval.Context) string {
				event := GetEvent(ctx)
				return event.ResolveFileBasename(&event.Splice.File)
			},
			Field:  field,
			Weight: eval.HandlerWeight,
		}, nil
	case "splice.file.path":
		return &eval.StringEvaluator{
			OpOverrides: model.ProcessSymlinkPathname,
			EvalFnc: func(ctx *eval.Context) string {
				event := GetEvent(ctx)
				return event.ResolveFilePath(&event.Splice.File)
			},
			Field:  field,
			Weight: eval.HandlerWeight,
		}, nil
	case "splice.file.rights":
		return &eval.IntEvaluator{
			EvalFnc: func(ctx *eval.Context) int {
				event := GetEvent(ctx)
				return int(event.ResolveRights(&event.Splice.File.FileFields))
			},
			Field:  field,
			Weight: eval.HandlerWeight,
		}, nil
	case "splice.file.uid":
		return &eval.IntEvaluator{
			EvalFnc: func(ctx *eval.Context) int {
				event := GetEvent(ctx)
				return int(event.Splice.File.FileFields.UID)
			},
			Field:  field,
			Weight: eval.FunctionWeight,
		}, nil
	case "splice.file.user":
		return &eval.StringEvaluator{
			EvalFnc: func(ctx *eval.Context) string {
				event := GetEvent(ctx)
				return event.ResolveFileFieldsUser(&event.Splice.File.FileFields)
			},
			Field:  field,
			Weight: eval.HandlerWeight,
		}, nil
	case "splice.pipe_entry_flag":
		return &eval.IntEvaluator{
			EvalFnc: func(ctx *eval.Context) int {
				event := GetEvent(ctx)
				return int(event.Splice.PipeEntryFlag)
			},
			Field:  field,
			Weight: eval.FunctionWeight,
		}, nil
	case "splice.pipe_exit_flag":
		return &eval.IntEvaluator{
			EvalFnc: func(ctx *eval.Context) int {
				event := GetEvent(ctx)
				return int(event.Splice.PipeExitFlag)
			},
			Field:  field,
			Weight: eval.FunctionWeight,
		}, nil
	case "splice.retval":
		return &eval.IntEvaluator{
			EvalFnc: func(ctx *eval.Context) int {
				event := GetEvent(ctx)
				return int(event.Splice.SyscallEvent.Retval)
			},
			Field:  field,
			Weight: eval.FunctionWeight,
		}, nil
	case "unlink.file.change_time":
		return &eval.IntEvaluator{
			EvalFnc: func(ctx *eval.Context) int {
				event := GetEvent(ctx)
				return int(event.Unlink.File.FileFields.CTime)
			},
			Field:  field,
			Weight: eval.FunctionWeight,
		}, nil
	case "unlink.file.filesystem":
		return &eval.StringEvaluator{
			EvalFnc: func(ctx *eval.Context) string {
				event := GetEvent(ctx)
				return event.ResolveFileFilesystem(&event.Unlink.File)
			},
			Field:  field,
			Weight: eval.HandlerWeight,
		}, nil
	case "unlink.file.gid":
		return &eval.IntEvaluator{
			EvalFnc: func(ctx *eval.Context) int {
				event := GetEvent(ctx)
				return int(event.Unlink.File.FileFields.GID)
			},
			Field:  field,
			Weight: eval.FunctionWeight,
		}, nil
	case "unlink.file.group":
		return &eval.StringEvaluator{
			EvalFnc: func(ctx *eval.Context) string {
				event := GetEvent(ctx)
				return event.ResolveFileFieldsGroup(&event.Unlink.File.FileFields)
			},
			Field:  field,
			Weight: eval.HandlerWeight,
		}, nil
	case "unlink.file.in_upper_layer":
		return &eval.BoolEvaluator{
			EvalFnc: func(ctx *eval.Context) bool {
				event := GetEvent(ctx)
				return event.ResolveFileFieldsInUpperLayer(&event.Unlink.File.FileFields)
			},
			Field:  field,
			Weight: eval.HandlerWeight,
		}, nil
	case "unlink.file.inode":
		return &eval.IntEvaluator{
			EvalFnc: func(ctx *eval.Context) int {
				event := GetEvent(ctx)
				return int(event.Unlink.File.FileFields.Inode)
			},
			Field:  field,
			Weight: eval.FunctionWeight,
		}, nil
	case "unlink.file.mode":
		return &eval.IntEvaluator{
			EvalFnc: func(ctx *eval.Context) int {
				event := GetEvent(ctx)
				return int(event.Unlink.File.FileFields.Mode)
			},
			Field:  field,
			Weight: eval.FunctionWeight,
		}, nil
	case "unlink.file.modification_time":
		return &eval.IntEvaluator{
			EvalFnc: func(ctx *eval.Context) int {
				event := GetEvent(ctx)
				return int(event.Unlink.File.FileFields.MTime)
			},
			Field:  field,
			Weight: eval.FunctionWeight,
		}, nil
	case "unlink.file.mount_id":
		return &eval.IntEvaluator{
			EvalFnc: func(ctx *eval.Context) int {
				event := GetEvent(ctx)
				return int(event.Unlink.File.FileFields.MountID)
			},
			Field:  field,
			Weight: eval.FunctionWeight,
		}, nil
	case "unlink.file.name":
		return &eval.StringEvaluator{
			OpOverrides: model.ProcessSymlinkBasename,
			EvalFnc: func(ctx *eval.Context) string {
				event := GetEvent(ctx)
				return event.ResolveFileBasename(&event.Unlink.File)
			},
			Field:  field,
			Weight: eval.HandlerWeight,
		}, nil
	case "unlink.file.path":
		return &eval.StringEvaluator{
			OpOverrides: model.ProcessSymlinkPathname,
			EvalFnc: func(ctx *eval.Context) string {
				event := GetEvent(ctx)
				return event.ResolveFilePath(&event.Unlink.File)
			},
			Field:  field,
			Weight: eval.HandlerWeight,
		}, nil
	case "unlink.file.rights":
		return &eval.IntEvaluator{
			EvalFnc: func(ctx *eval.Context) int {
				event := GetEvent(ctx)
				return int(event.ResolveRights(&event.Unlink.File.FileFields))
			},
			Field:  field,
			Weight: eval.HandlerWeight,
		}, nil
	case "unlink.file.uid":
		return &eval.IntEvaluator{
			EvalFnc: func(ctx *eval.Context) int {
				event := GetEvent(ctx)
				return int(event.Unlink.File.FileFields.UID)
			},
			Field:  field,
			Weight: eval.FunctionWeight,
		}, nil
	case "unlink.file.user":
		return &eval.StringEvaluator{
			EvalFnc: func(ctx *eval.Context) string {
				event := GetEvent(ctx)
				return event.ResolveFileFieldsUser(&event.Unlink.File.FileFields)
			},
			Field:  field,
			Weight: eval.HandlerWeight,
		}, nil
	case "unlink.flags":
		return &eval.IntEvaluator{
			EvalFnc: func(ctx *eval.Context) int {
				event := GetEvent(ctx)
				return int(event.Unlink.Flags)
			},
			Field:  field,
			Weight: eval.FunctionWeight,
		}, nil
	case "unlink.retval":
		return &eval.IntEvaluator{
			EvalFnc: func(ctx *eval.Context) int {
				event := GetEvent(ctx)
				return int(event.Unlink.SyscallEvent.Retval)
			},
			Field:  field,
			Weight: eval.FunctionWeight,
		}, nil
	case "unload_module.name":
		return &eval.StringEvaluator{
			EvalFnc: func(ctx *eval.Context) string {
				event := GetEvent(ctx)
				return event.UnloadModule.Name
			},
			Field:  field,
			Weight: eval.FunctionWeight,
		}, nil
	case "unload_module.retval":
		return &eval.IntEvaluator{
			EvalFnc: func(ctx *eval.Context) int {
				event := GetEvent(ctx)
				return int(event.UnloadModule.SyscallEvent.Retval)
			},
			Field:  field,
			Weight: eval.FunctionWeight,
		}, nil
	case "utimes.file.change_time":
		return &eval.IntEvaluator{
			EvalFnc: func(ctx *eval.Context) int {
				event := GetEvent(ctx)
				return int(event.Utimes.File.FileFields.CTime)
			},
			Field:  field,
			Weight: eval.FunctionWeight,
		}, nil
	case "utimes.file.filesystem":
		return &eval.StringEvaluator{
			EvalFnc: func(ctx *eval.Context) string {
				event := GetEvent(ctx)
				return event.ResolveFileFilesystem(&event.Utimes.File)
			},
			Field:  field,
			Weight: eval.HandlerWeight,
		}, nil
	case "utimes.file.gid":
		return &eval.IntEvaluator{
			EvalFnc: func(ctx *eval.Context) int {
				event := GetEvent(ctx)
				return int(event.Utimes.File.FileFields.GID)
			},
			Field:  field,
			Weight: eval.FunctionWeight,
		}, nil
	case "utimes.file.group":
		return &eval.StringEvaluator{
			EvalFnc: func(ctx *eval.Context) string {
				event := GetEvent(ctx)
				return event.ResolveFileFieldsGroup(&event.Utimes.File.FileFields)
			},
			Field:  field,
			Weight: eval.HandlerWeight,
		}, nil
	case "utimes.file.in_upper_layer":
		return &eval.BoolEvaluator{
			EvalFnc: func(ctx *eval.Context) bool {
				event := GetEvent(ctx)
				return event.ResolveFileFieldsInUpperLayer(&event.Utimes.File.FileFields)
			},
			Field:  field,
			Weight: eval.HandlerWeight,
		}, nil
	case "utimes.file.inode":
		return &eval.IntEvaluator{
			EvalFnc: func(ctx *eval.Context) int {
				event := GetEvent(ctx)
				return int(event.Utimes.File.FileFields.Inode)
			},
			Field:  field,
			Weight: eval.FunctionWeight,
		}, nil
	case "utimes.file.mode":
		return &eval.IntEvaluator{
			EvalFnc: func(ctx *eval.Context) int {
				event := GetEvent(ctx)
				return int(event.Utimes.File.FileFields.Mode)
			},
			Field:  field,
			Weight: eval.FunctionWeight,
		}, nil
	case "utimes.file.modification_time":
		return &eval.IntEvaluator{
			EvalFnc: func(ctx *eval.Context) int {
				event := GetEvent(ctx)
				return int(event.Utimes.File.FileFields.MTime)
			},
			Field:  field,
			Weight: eval.FunctionWeight,
		}, nil
	case "utimes.file.mount_id":
		return &eval.IntEvaluator{
			EvalFnc: func(ctx *eval.Context) int {
				event := GetEvent(ctx)
				return int(event.Utimes.File.FileFields.MountID)
			},
			Field:  field,
			Weight: eval.FunctionWeight,
		}, nil
	case "utimes.file.name":
		return &eval.StringEvaluator{
			OpOverrides: model.ProcessSymlinkBasename,
			EvalFnc: func(ctx *eval.Context) string {
				event := GetEvent(ctx)
				return event.ResolveFileBasename(&event.Utimes.File)
			},
			Field:  field,
			Weight: eval.HandlerWeight,
		}, nil
	case "utimes.file.path":
		return &eval.StringEvaluator{
			OpOverrides: model.ProcessSymlinkPathname,
			EvalFnc: func(ctx *eval.Context) string {
				event := GetEvent(ctx)
				return event.ResolveFilePath(&event.Utimes.File)
			},
			Field:  field,
			Weight: eval.HandlerWeight,
		}, nil
	case "utimes.file.rights":
		return &eval.IntEvaluator{
			EvalFnc: func(ctx *eval.Context) int {
				event := GetEvent(ctx)
				return int(event.ResolveRights(&event.Utimes.File.FileFields))
			},
			Field:  field,
			Weight: eval.HandlerWeight,
		}, nil
	case "utimes.file.uid":
		return &eval.IntEvaluator{
			EvalFnc: func(ctx *eval.Context) int {
				event := GetEvent(ctx)
				return int(event.Utimes.File.FileFields.UID)
			},
			Field:  field,
			Weight: eval.FunctionWeight,
		}, nil
	case "utimes.file.user":
		return &eval.StringEvaluator{
			EvalFnc: func(ctx *eval.Context) string {
				event := GetEvent(ctx)
				return event.ResolveFileFieldsUser(&event.Utimes.File.FileFields)
			},
			Field:  field,
			Weight: eval.HandlerWeight,
		}, nil
	case "utimes.retval":
		return &eval.IntEvaluator{
			EvalFnc: func(ctx *eval.Context) int {
				event := GetEvent(ctx)
				return int(event.Utimes.SyscallEvent.Retval)
			},
			Field:  field,
			Weight: eval.FunctionWeight,
		}, nil
	}
	return nil, &eval.ErrFieldNotFound{Field: field}
}
