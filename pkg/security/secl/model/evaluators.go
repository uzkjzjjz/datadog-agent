// Code generated - DO NOT EDIT.
package model

import (
	"github.com/DataDog/datadog-agent/pkg/security/secl/compiler/eval"
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
				result := make([]int, len(event.BPF.Program.Helpers))
				for i, v := range event.BPF.Program.Helpers {
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
				return event.Chmod.File.Filesystem
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
				return event.Chmod.File.FileFields.Group
			},
			Field:  field,
			Weight: eval.HandlerWeight,
		}, nil
	case "chmod.file.in_upper_layer":
		return &eval.BoolEvaluator{
			EvalFnc: func(ctx *eval.Context) bool {
				event := GetEvent(ctx)
				return event.Chmod.File.FileFields.InUpperLayer
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
			OpOverrides: ProcessSymlinkBasename,
			EvalFnc: func(ctx *eval.Context) string {
				event := GetEvent(ctx)
				return event.Chmod.File.BasenameStr
			},
			Field:  field,
			Weight: eval.HandlerWeight,
		}, nil
	case "chmod.file.path":
		return &eval.StringEvaluator{
			OpOverrides: ProcessSymlinkPathname,
			EvalFnc: func(ctx *eval.Context) string {
				event := GetEvent(ctx)
				return event.Chmod.File.PathnameStr
			},
			Field:  field,
			Weight: eval.HandlerWeight,
		}, nil
	case "chmod.file.rights":
		return &eval.IntEvaluator{
			EvalFnc: func(ctx *eval.Context) int {
				event := GetEvent(ctx)
				return int(event.Chmod.File.FileFields.Mode)
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
				return event.Chmod.File.FileFields.User
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
				return event.Chown.Group
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
				return event.Chown.User
			},
			Field:  field,
			Weight: eval.HandlerWeight,
		}, nil
	case "chown.file.filesystem":
		return &eval.StringEvaluator{
			EvalFnc: func(ctx *eval.Context) string {
				event := GetEvent(ctx)
				return event.Chown.File.Filesystem
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
				return event.Chown.File.FileFields.Group
			},
			Field:  field,
			Weight: eval.HandlerWeight,
		}, nil
	case "chown.file.in_upper_layer":
		return &eval.BoolEvaluator{
			EvalFnc: func(ctx *eval.Context) bool {
				event := GetEvent(ctx)
				return event.Chown.File.FileFields.InUpperLayer
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
			OpOverrides: ProcessSymlinkBasename,
			EvalFnc: func(ctx *eval.Context) string {
				event := GetEvent(ctx)
				return event.Chown.File.BasenameStr
			},
			Field:  field,
			Weight: eval.HandlerWeight,
		}, nil
	case "chown.file.path":
		return &eval.StringEvaluator{
			OpOverrides: ProcessSymlinkPathname,
			EvalFnc: func(ctx *eval.Context) string {
				event := GetEvent(ctx)
				return event.Chown.File.PathnameStr
			},
			Field:  field,
			Weight: eval.HandlerWeight,
		}, nil
	case "chown.file.rights":
		return &eval.IntEvaluator{
			EvalFnc: func(ctx *eval.Context) int {
				event := GetEvent(ctx)
				return int(event.Chown.File.FileFields.Mode)
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
				return event.Chown.File.FileFields.User
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
				return event.ContainerContext.ID
			},
			Field:  field,
			Weight: eval.HandlerWeight,
		}, nil
	case "container.tags":
		return &eval.StringArrayEvaluator{
			EvalFnc: func(ctx *eval.Context) []string {
				event := GetEvent(ctx)
				return event.ContainerContext.Tags
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
				return event.Exec.Process.Args
			},
			Field:  field,
			Weight: 100 * eval.HandlerWeight,
		}, nil
	case "exec.args_flags":
		return &eval.StringArrayEvaluator{
			EvalFnc: func(ctx *eval.Context) []string {
				event := GetEvent(ctx)
				return event.Exec.Process.Argv
			},
			Field:  field,
			Weight: eval.HandlerWeight,
		}, nil
	case "exec.args_options":
		return &eval.StringArrayEvaluator{
			EvalFnc: func(ctx *eval.Context) []string {
				event := GetEvent(ctx)
				return event.Exec.Process.Argv
			},
			Field:  field,
			Weight: eval.HandlerWeight,
		}, nil
	case "exec.args_truncated":
		return &eval.BoolEvaluator{
			EvalFnc: func(ctx *eval.Context) bool {
				event := GetEvent(ctx)
				return event.Exec.Process.ArgsTruncated
			},
			Field:  field,
			Weight: eval.HandlerWeight,
		}, nil
	case "exec.argv":
		return &eval.StringArrayEvaluator{
			EvalFnc: func(ctx *eval.Context) []string {
				event := GetEvent(ctx)
				return event.Exec.Process.Argv
			},
			Field:  field,
			Weight: 100 * eval.HandlerWeight,
		}, nil
	case "exec.argv0":
		return &eval.StringEvaluator{
			EvalFnc: func(ctx *eval.Context) string {
				event := GetEvent(ctx)
				return event.Exec.Process.Argv0
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
				return int(event.Exec.Process.CreatedAt)
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
				return event.Exec.Process.Envp
			},
			Field:  field,
			Weight: eval.HandlerWeight,
		}, nil
	case "exec.envs":
		return &eval.StringArrayEvaluator{
			EvalFnc: func(ctx *eval.Context) []string {
				event := GetEvent(ctx)
				return event.Exec.Process.Envs
			},
			Field:  field,
			Weight: eval.HandlerWeight,
		}, nil
	case "exec.envs_truncated":
		return &eval.BoolEvaluator{
			EvalFnc: func(ctx *eval.Context) bool {
				event := GetEvent(ctx)
				return event.Exec.Process.EnvsTruncated
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
				return event.Exec.Process.FileEvent.Filesystem
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
				return event.Exec.Process.FileEvent.FileFields.Group
			},
			Field:  field,
			Weight: eval.HandlerWeight,
		}, nil
	case "exec.file.in_upper_layer":
		return &eval.BoolEvaluator{
			EvalFnc: func(ctx *eval.Context) bool {
				event := GetEvent(ctx)
				return event.Exec.Process.FileEvent.FileFields.InUpperLayer
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
			OpOverrides: ProcessSymlinkBasename,
			EvalFnc: func(ctx *eval.Context) string {
				event := GetEvent(ctx)
				return event.Exec.Process.FileEvent.BasenameStr
			},
			Field:  field,
			Weight: eval.HandlerWeight,
		}, nil
	case "exec.file.path":
		return &eval.StringEvaluator{
			OpOverrides: ProcessSymlinkPathname,
			EvalFnc: func(ctx *eval.Context) string {
				event := GetEvent(ctx)
				return event.Exec.Process.FileEvent.PathnameStr
			},
			Field:  field,
			Weight: eval.HandlerWeight,
		}, nil
	case "exec.file.rights":
		return &eval.IntEvaluator{
			EvalFnc: func(ctx *eval.Context) int {
				event := GetEvent(ctx)
				return int(event.Exec.Process.FileEvent.FileFields.Mode)
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
				return event.Exec.Process.FileEvent.FileFields.User
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
				return event.Exit.Process.Args
			},
			Field:  field,
			Weight: 100 * eval.HandlerWeight,
		}, nil
	case "exit.args_flags":
		return &eval.StringArrayEvaluator{
			EvalFnc: func(ctx *eval.Context) []string {
				event := GetEvent(ctx)
				return event.Exit.Process.Argv
			},
			Field:  field,
			Weight: eval.HandlerWeight,
		}, nil
	case "exit.args_options":
		return &eval.StringArrayEvaluator{
			EvalFnc: func(ctx *eval.Context) []string {
				event := GetEvent(ctx)
				return event.Exit.Process.Argv
			},
			Field:  field,
			Weight: eval.HandlerWeight,
		}, nil
	case "exit.args_truncated":
		return &eval.BoolEvaluator{
			EvalFnc: func(ctx *eval.Context) bool {
				event := GetEvent(ctx)
				return event.Exit.Process.ArgsTruncated
			},
			Field:  field,
			Weight: eval.HandlerWeight,
		}, nil
	case "exit.argv":
		return &eval.StringArrayEvaluator{
			EvalFnc: func(ctx *eval.Context) []string {
				event := GetEvent(ctx)
				return event.Exit.Process.Argv
			},
			Field:  field,
			Weight: 100 * eval.HandlerWeight,
		}, nil
	case "exit.argv0":
		return &eval.StringEvaluator{
			EvalFnc: func(ctx *eval.Context) string {
				event := GetEvent(ctx)
				return event.Exit.Process.Argv0
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
				return int(event.Exit.Process.CreatedAt)
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
				return event.Exit.Process.Envp
			},
			Field:  field,
			Weight: eval.HandlerWeight,
		}, nil
	case "exit.envs":
		return &eval.StringArrayEvaluator{
			EvalFnc: func(ctx *eval.Context) []string {
				event := GetEvent(ctx)
				return event.Exit.Process.Envs
			},
			Field:  field,
			Weight: eval.HandlerWeight,
		}, nil
	case "exit.envs_truncated":
		return &eval.BoolEvaluator{
			EvalFnc: func(ctx *eval.Context) bool {
				event := GetEvent(ctx)
				return event.Exit.Process.EnvsTruncated
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
				return event.Exit.Process.FileEvent.Filesystem
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
				return event.Exit.Process.FileEvent.FileFields.Group
			},
			Field:  field,
			Weight: eval.HandlerWeight,
		}, nil
	case "exit.file.in_upper_layer":
		return &eval.BoolEvaluator{
			EvalFnc: func(ctx *eval.Context) bool {
				event := GetEvent(ctx)
				return event.Exit.Process.FileEvent.FileFields.InUpperLayer
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
			OpOverrides: ProcessSymlinkBasename,
			EvalFnc: func(ctx *eval.Context) string {
				event := GetEvent(ctx)
				return event.Exit.Process.FileEvent.BasenameStr
			},
			Field:  field,
			Weight: eval.HandlerWeight,
		}, nil
	case "exit.file.path":
		return &eval.StringEvaluator{
			OpOverrides: ProcessSymlinkPathname,
			EvalFnc: func(ctx *eval.Context) string {
				event := GetEvent(ctx)
				return event.Exit.Process.FileEvent.PathnameStr
			},
			Field:  field,
			Weight: eval.HandlerWeight,
		}, nil
	case "exit.file.rights":
		return &eval.IntEvaluator{
			EvalFnc: func(ctx *eval.Context) int {
				event := GetEvent(ctx)
				return int(event.Exit.Process.FileEvent.FileFields.Mode)
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
				return event.Exit.Process.FileEvent.FileFields.User
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
				return event.Link.Target.Filesystem
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
				return event.Link.Target.FileFields.Group
			},
			Field:  field,
			Weight: eval.HandlerWeight,
		}, nil
	case "link.file.destination.in_upper_layer":
		return &eval.BoolEvaluator{
			EvalFnc: func(ctx *eval.Context) bool {
				event := GetEvent(ctx)
				return event.Link.Target.FileFields.InUpperLayer
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
			OpOverrides: ProcessSymlinkBasename,
			EvalFnc: func(ctx *eval.Context) string {
				event := GetEvent(ctx)
				return event.Link.Target.BasenameStr
			},
			Field:  field,
			Weight: eval.HandlerWeight,
		}, nil
	case "link.file.destination.path":
		return &eval.StringEvaluator{
			OpOverrides: ProcessSymlinkPathname,
			EvalFnc: func(ctx *eval.Context) string {
				event := GetEvent(ctx)
				return event.Link.Target.PathnameStr
			},
			Field:  field,
			Weight: eval.HandlerWeight,
		}, nil
	case "link.file.destination.rights":
		return &eval.IntEvaluator{
			EvalFnc: func(ctx *eval.Context) int {
				event := GetEvent(ctx)
				return int(event.Link.Target.FileFields.Mode)
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
				return event.Link.Target.FileFields.User
			},
			Field:  field,
			Weight: eval.HandlerWeight,
		}, nil
	case "link.file.filesystem":
		return &eval.StringEvaluator{
			EvalFnc: func(ctx *eval.Context) string {
				event := GetEvent(ctx)
				return event.Link.Source.Filesystem
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
				return event.Link.Source.FileFields.Group
			},
			Field:  field,
			Weight: eval.HandlerWeight,
		}, nil
	case "link.file.in_upper_layer":
		return &eval.BoolEvaluator{
			EvalFnc: func(ctx *eval.Context) bool {
				event := GetEvent(ctx)
				return event.Link.Source.FileFields.InUpperLayer
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
			OpOverrides: ProcessSymlinkBasename,
			EvalFnc: func(ctx *eval.Context) string {
				event := GetEvent(ctx)
				return event.Link.Source.BasenameStr
			},
			Field:  field,
			Weight: eval.HandlerWeight,
		}, nil
	case "link.file.path":
		return &eval.StringEvaluator{
			OpOverrides: ProcessSymlinkPathname,
			EvalFnc: func(ctx *eval.Context) string {
				event := GetEvent(ctx)
				return event.Link.Source.PathnameStr
			},
			Field:  field,
			Weight: eval.HandlerWeight,
		}, nil
	case "link.file.rights":
		return &eval.IntEvaluator{
			EvalFnc: func(ctx *eval.Context) int {
				event := GetEvent(ctx)
				return int(event.Link.Source.FileFields.Mode)
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
				return event.Link.Source.FileFields.User
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
				return event.LoadModule.File.Filesystem
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
				return event.LoadModule.File.FileFields.Group
			},
			Field:  field,
			Weight: eval.HandlerWeight,
		}, nil
	case "load_module.file.in_upper_layer":
		return &eval.BoolEvaluator{
			EvalFnc: func(ctx *eval.Context) bool {
				event := GetEvent(ctx)
				return event.LoadModule.File.FileFields.InUpperLayer
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
			OpOverrides: ProcessSymlinkBasename,
			EvalFnc: func(ctx *eval.Context) string {
				event := GetEvent(ctx)
				return event.LoadModule.File.BasenameStr
			},
			Field:  field,
			Weight: eval.HandlerWeight,
		}, nil
	case "load_module.file.path":
		return &eval.StringEvaluator{
			OpOverrides: ProcessSymlinkPathname,
			EvalFnc: func(ctx *eval.Context) string {
				event := GetEvent(ctx)
				return event.LoadModule.File.PathnameStr
			},
			Field:  field,
			Weight: eval.HandlerWeight,
		}, nil
	case "load_module.file.rights":
		return &eval.IntEvaluator{
			EvalFnc: func(ctx *eval.Context) int {
				event := GetEvent(ctx)
				return int(event.LoadModule.File.FileFields.Mode)
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
				return event.LoadModule.File.FileFields.User
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
				return event.Mkdir.File.Filesystem
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
				return event.Mkdir.File.FileFields.Group
			},
			Field:  field,
			Weight: eval.HandlerWeight,
		}, nil
	case "mkdir.file.in_upper_layer":
		return &eval.BoolEvaluator{
			EvalFnc: func(ctx *eval.Context) bool {
				event := GetEvent(ctx)
				return event.Mkdir.File.FileFields.InUpperLayer
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
			OpOverrides: ProcessSymlinkBasename,
			EvalFnc: func(ctx *eval.Context) string {
				event := GetEvent(ctx)
				return event.Mkdir.File.BasenameStr
			},
			Field:  field,
			Weight: eval.HandlerWeight,
		}, nil
	case "mkdir.file.path":
		return &eval.StringEvaluator{
			OpOverrides: ProcessSymlinkPathname,
			EvalFnc: func(ctx *eval.Context) string {
				event := GetEvent(ctx)
				return event.Mkdir.File.PathnameStr
			},
			Field:  field,
			Weight: eval.HandlerWeight,
		}, nil
	case "mkdir.file.rights":
		return &eval.IntEvaluator{
			EvalFnc: func(ctx *eval.Context) int {
				event := GetEvent(ctx)
				return int(event.Mkdir.File.FileFields.Mode)
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
				return event.Mkdir.File.FileFields.User
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
				return event.MMap.File.Filesystem
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
				return event.MMap.File.FileFields.Group
			},
			Field:  field,
			Weight: eval.HandlerWeight,
		}, nil
	case "mmap.file.in_upper_layer":
		return &eval.BoolEvaluator{
			EvalFnc: func(ctx *eval.Context) bool {
				event := GetEvent(ctx)
				return event.MMap.File.FileFields.InUpperLayer
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
			OpOverrides: ProcessSymlinkBasename,
			EvalFnc: func(ctx *eval.Context) string {
				event := GetEvent(ctx)
				return event.MMap.File.BasenameStr
			},
			Field:  field,
			Weight: eval.HandlerWeight,
		}, nil
	case "mmap.file.path":
		return &eval.StringEvaluator{
			OpOverrides: ProcessSymlinkPathname,
			EvalFnc: func(ctx *eval.Context) string {
				event := GetEvent(ctx)
				return event.MMap.File.PathnameStr
			},
			Field:  field,
			Weight: eval.HandlerWeight,
		}, nil
	case "mmap.file.rights":
		return &eval.IntEvaluator{
			EvalFnc: func(ctx *eval.Context) int {
				event := GetEvent(ctx)
				return int(event.MMap.File.FileFields.Mode)
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
				return event.MMap.File.FileFields.User
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
				return event.NetworkContext.Device.IfName
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
				return event.Open.File.Filesystem
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
				return event.Open.File.FileFields.Group
			},
			Field:  field,
			Weight: eval.HandlerWeight,
		}, nil
	case "open.file.in_upper_layer":
		return &eval.BoolEvaluator{
			EvalFnc: func(ctx *eval.Context) bool {
				event := GetEvent(ctx)
				return event.Open.File.FileFields.InUpperLayer
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
			OpOverrides: ProcessSymlinkBasename,
			EvalFnc: func(ctx *eval.Context) string {
				event := GetEvent(ctx)
				return event.Open.File.BasenameStr
			},
			Field:  field,
			Weight: eval.HandlerWeight,
		}, nil
	case "open.file.path":
		return &eval.StringEvaluator{
			OpOverrides: ProcessSymlinkPathname,
			EvalFnc: func(ctx *eval.Context) string {
				event := GetEvent(ctx)
				return event.Open.File.PathnameStr
			},
			Field:  field,
			Weight: eval.HandlerWeight,
		}, nil
	case "open.file.rights":
		return &eval.IntEvaluator{
			EvalFnc: func(ctx *eval.Context) int {
				event := GetEvent(ctx)
				return int(event.Open.File.FileFields.Mode)
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
				return event.Open.File.FileFields.User
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
				var results []string
				iterator := &ProcessAncestorsIterator{}
				value := iterator.Front(ctx)
				for value != nil {
					element := (*ProcessCacheEntry)(value)
					result := element.ProcessContext.Process.Args
					results = append(results, result)
					value = iterator.Next()
				}
				return results
			}, Field: field,
			Weight: 100 * eval.IteratorWeight,
		}, nil
	case "process.ancestors.args_flags":
		return &eval.StringArrayEvaluator{
			EvalFnc: func(ctx *eval.Context) []string {
				var results []string
				iterator := &ProcessAncestorsIterator{}
				value := iterator.Front(ctx)
				for value != nil {
					element := (*ProcessCacheEntry)(value)
					result := element.ProcessContext.Process.Argv
					results = append(results, result...)
					value = iterator.Next()
				}
				return results
			}, Field: field,
			Weight: eval.IteratorWeight,
		}, nil
	case "process.ancestors.args_options":
		return &eval.StringArrayEvaluator{
			EvalFnc: func(ctx *eval.Context) []string {
				var results []string
				iterator := &ProcessAncestorsIterator{}
				value := iterator.Front(ctx)
				for value != nil {
					element := (*ProcessCacheEntry)(value)
					result := element.ProcessContext.Process.Argv
					results = append(results, result...)
					value = iterator.Next()
				}
				return results
			}, Field: field,
			Weight: eval.IteratorWeight,
		}, nil
	case "process.ancestors.args_truncated":
		return &eval.BoolArrayEvaluator{
			EvalFnc: func(ctx *eval.Context) []bool {
				var results []bool
				iterator := &ProcessAncestorsIterator{}
				value := iterator.Front(ctx)
				for value != nil {
					element := (*ProcessCacheEntry)(value)
					result := element.ProcessContext.Process.ArgsTruncated
					results = append(results, result)
					value = iterator.Next()
				}
				return results
			}, Field: field,
			Weight: eval.IteratorWeight,
		}, nil
	case "process.ancestors.argv":
		return &eval.StringArrayEvaluator{
			EvalFnc: func(ctx *eval.Context) []string {
				var results []string
				iterator := &ProcessAncestorsIterator{}
				value := iterator.Front(ctx)
				for value != nil {
					element := (*ProcessCacheEntry)(value)
					result := element.ProcessContext.Process.Argv
					results = append(results, result...)
					value = iterator.Next()
				}
				return results
			}, Field: field,
			Weight: 100 * eval.IteratorWeight,
		}, nil
	case "process.ancestors.argv0":
		return &eval.StringArrayEvaluator{
			EvalFnc: func(ctx *eval.Context) []string {
				var results []string
				iterator := &ProcessAncestorsIterator{}
				value := iterator.Front(ctx)
				for value != nil {
					element := (*ProcessCacheEntry)(value)
					result := element.ProcessContext.Process.Argv0
					results = append(results, result)
					value = iterator.Next()
				}
				return results
			}, Field: field,
			Weight: 100 * eval.IteratorWeight,
		}, nil
	case "process.ancestors.cap_effective":
		return &eval.IntArrayEvaluator{
			EvalFnc: func(ctx *eval.Context) []int {
				var results []int
				iterator := &ProcessAncestorsIterator{}
				value := iterator.Front(ctx)
				for value != nil {
					element := (*ProcessCacheEntry)(value)
					result := int(element.ProcessContext.Process.Credentials.CapEffective)
					results = append(results, result)
					value = iterator.Next()
				}
				return results
			}, Field: field,
			Weight: eval.IteratorWeight,
		}, nil
	case "process.ancestors.cap_permitted":
		return &eval.IntArrayEvaluator{
			EvalFnc: func(ctx *eval.Context) []int {
				var results []int
				iterator := &ProcessAncestorsIterator{}
				value := iterator.Front(ctx)
				for value != nil {
					element := (*ProcessCacheEntry)(value)
					result := int(element.ProcessContext.Process.Credentials.CapPermitted)
					results = append(results, result)
					value = iterator.Next()
				}
				return results
			}, Field: field,
			Weight: eval.IteratorWeight,
		}, nil
	case "process.ancestors.comm":
		return &eval.StringArrayEvaluator{
			EvalFnc: func(ctx *eval.Context) []string {
				var results []string
				iterator := &ProcessAncestorsIterator{}
				value := iterator.Front(ctx)
				for value != nil {
					element := (*ProcessCacheEntry)(value)
					result := element.ProcessContext.Process.Comm
					results = append(results, result)
					value = iterator.Next()
				}
				return results
			}, Field: field,
			Weight: eval.IteratorWeight,
		}, nil
	case "process.ancestors.container.id":
		return &eval.StringArrayEvaluator{
			EvalFnc: func(ctx *eval.Context) []string {
				var results []string
				iterator := &ProcessAncestorsIterator{}
				value := iterator.Front(ctx)
				for value != nil {
					element := (*ProcessCacheEntry)(value)
					result := element.ProcessContext.Process.ContainerID
					results = append(results, result)
					value = iterator.Next()
				}
				return results
			}, Field: field,
			Weight: eval.IteratorWeight,
		}, nil
	case "process.ancestors.cookie":
		return &eval.IntArrayEvaluator{
			EvalFnc: func(ctx *eval.Context) []int {
				var results []int
				iterator := &ProcessAncestorsIterator{}
				value := iterator.Front(ctx)
				for value != nil {
					element := (*ProcessCacheEntry)(value)
					result := int(element.ProcessContext.Process.Cookie)
					results = append(results, result)
					value = iterator.Next()
				}
				return results
			}, Field: field,
			Weight: eval.IteratorWeight,
		}, nil
	case "process.ancestors.created_at":
		return &eval.IntArrayEvaluator{
			EvalFnc: func(ctx *eval.Context) []int {
				var results []int
				iterator := &ProcessAncestorsIterator{}
				value := iterator.Front(ctx)
				for value != nil {
					element := (*ProcessCacheEntry)(value)
					result := int(element.ProcessContext.Process.CreatedAt)
					results = append(results, result)
					value = iterator.Next()
				}
				return results
			}, Field: field,
			Weight: eval.IteratorWeight,
		}, nil
	case "process.ancestors.egid":
		return &eval.IntArrayEvaluator{
			EvalFnc: func(ctx *eval.Context) []int {
				var results []int
				iterator := &ProcessAncestorsIterator{}
				value := iterator.Front(ctx)
				for value != nil {
					element := (*ProcessCacheEntry)(value)
					result := int(element.ProcessContext.Process.Credentials.EGID)
					results = append(results, result)
					value = iterator.Next()
				}
				return results
			}, Field: field,
			Weight: eval.IteratorWeight,
		}, nil
	case "process.ancestors.egroup":
		return &eval.StringArrayEvaluator{
			EvalFnc: func(ctx *eval.Context) []string {
				var results []string
				iterator := &ProcessAncestorsIterator{}
				value := iterator.Front(ctx)
				for value != nil {
					element := (*ProcessCacheEntry)(value)
					result := element.ProcessContext.Process.Credentials.EGroup
					results = append(results, result)
					value = iterator.Next()
				}
				return results
			}, Field: field,
			Weight: eval.IteratorWeight,
		}, nil
	case "process.ancestors.envp":
		return &eval.StringArrayEvaluator{
			EvalFnc: func(ctx *eval.Context) []string {
				var results []string
				iterator := &ProcessAncestorsIterator{}
				value := iterator.Front(ctx)
				for value != nil {
					element := (*ProcessCacheEntry)(value)
					result := element.ProcessContext.Process.Envp
					results = append(results, result...)
					value = iterator.Next()
				}
				return results
			}, Field: field,
			Weight: eval.IteratorWeight,
		}, nil
	case "process.ancestors.envs":
		return &eval.StringArrayEvaluator{
			EvalFnc: func(ctx *eval.Context) []string {
				var results []string
				iterator := &ProcessAncestorsIterator{}
				value := iterator.Front(ctx)
				for value != nil {
					element := (*ProcessCacheEntry)(value)
					result := element.ProcessContext.Process.Envs
					results = append(results, result...)
					value = iterator.Next()
				}
				return results
			}, Field: field,
			Weight: eval.IteratorWeight,
		}, nil
	case "process.ancestors.envs_truncated":
		return &eval.BoolArrayEvaluator{
			EvalFnc: func(ctx *eval.Context) []bool {
				var results []bool
				iterator := &ProcessAncestorsIterator{}
				value := iterator.Front(ctx)
				for value != nil {
					element := (*ProcessCacheEntry)(value)
					result := element.ProcessContext.Process.EnvsTruncated
					results = append(results, result)
					value = iterator.Next()
				}
				return results
			}, Field: field,
			Weight: eval.IteratorWeight,
		}, nil
	case "process.ancestors.euid":
		return &eval.IntArrayEvaluator{
			EvalFnc: func(ctx *eval.Context) []int {
				var results []int
				iterator := &ProcessAncestorsIterator{}
				value := iterator.Front(ctx)
				for value != nil {
					element := (*ProcessCacheEntry)(value)
					result := int(element.ProcessContext.Process.Credentials.EUID)
					results = append(results, result)
					value = iterator.Next()
				}
				return results
			}, Field: field,
			Weight: eval.IteratorWeight,
		}, nil
	case "process.ancestors.euser":
		return &eval.StringArrayEvaluator{
			EvalFnc: func(ctx *eval.Context) []string {
				var results []string
				iterator := &ProcessAncestorsIterator{}
				value := iterator.Front(ctx)
				for value != nil {
					element := (*ProcessCacheEntry)(value)
					result := element.ProcessContext.Process.Credentials.EUser
					results = append(results, result)
					value = iterator.Next()
				}
				return results
			}, Field: field,
			Weight: eval.IteratorWeight,
		}, nil
	case "process.ancestors.file.change_time":
		return &eval.IntArrayEvaluator{
			EvalFnc: func(ctx *eval.Context) []int {
				var results []int
				iterator := &ProcessAncestorsIterator{}
				value := iterator.Front(ctx)
				for value != nil {
					element := (*ProcessCacheEntry)(value)
					result := int(element.ProcessContext.Process.FileEvent.FileFields.CTime)
					results = append(results, result)
					value = iterator.Next()
				}
				return results
			}, Field: field,
			Weight: eval.IteratorWeight,
		}, nil
	case "process.ancestors.file.filesystem":
		return &eval.StringArrayEvaluator{
			EvalFnc: func(ctx *eval.Context) []string {
				var results []string
				iterator := &ProcessAncestorsIterator{}
				value := iterator.Front(ctx)
				for value != nil {
					element := (*ProcessCacheEntry)(value)
					result := element.ProcessContext.Process.FileEvent.Filesystem
					results = append(results, result)
					value = iterator.Next()
				}
				return results
			}, Field: field,
			Weight: eval.IteratorWeight,
		}, nil
	case "process.ancestors.file.gid":
		return &eval.IntArrayEvaluator{
			EvalFnc: func(ctx *eval.Context) []int {
				var results []int
				iterator := &ProcessAncestorsIterator{}
				value := iterator.Front(ctx)
				for value != nil {
					element := (*ProcessCacheEntry)(value)
					result := int(element.ProcessContext.Process.FileEvent.FileFields.GID)
					results = append(results, result)
					value = iterator.Next()
				}
				return results
			}, Field: field,
			Weight: eval.IteratorWeight,
		}, nil
	case "process.ancestors.file.group":
		return &eval.StringArrayEvaluator{
			EvalFnc: func(ctx *eval.Context) []string {
				var results []string
				iterator := &ProcessAncestorsIterator{}
				value := iterator.Front(ctx)
				for value != nil {
					element := (*ProcessCacheEntry)(value)
					result := element.ProcessContext.Process.FileEvent.FileFields.Group
					results = append(results, result)
					value = iterator.Next()
				}
				return results
			}, Field: field,
			Weight: eval.IteratorWeight,
		}, nil
	case "process.ancestors.file.in_upper_layer":
		return &eval.BoolArrayEvaluator{
			EvalFnc: func(ctx *eval.Context) []bool {
				var results []bool
				iterator := &ProcessAncestorsIterator{}
				value := iterator.Front(ctx)
				for value != nil {
					element := (*ProcessCacheEntry)(value)
					result := element.ProcessContext.Process.FileEvent.FileFields.InUpperLayer
					results = append(results, result)
					value = iterator.Next()
				}
				return results
			}, Field: field,
			Weight: eval.IteratorWeight,
		}, nil
	case "process.ancestors.file.inode":
		return &eval.IntArrayEvaluator{
			EvalFnc: func(ctx *eval.Context) []int {
				var results []int
				iterator := &ProcessAncestorsIterator{}
				value := iterator.Front(ctx)
				for value != nil {
					element := (*ProcessCacheEntry)(value)
					result := int(element.ProcessContext.Process.FileEvent.FileFields.Inode)
					results = append(results, result)
					value = iterator.Next()
				}
				return results
			}, Field: field,
			Weight: eval.IteratorWeight,
		}, nil
	case "process.ancestors.file.mode":
		return &eval.IntArrayEvaluator{
			EvalFnc: func(ctx *eval.Context) []int {
				var results []int
				iterator := &ProcessAncestorsIterator{}
				value := iterator.Front(ctx)
				for value != nil {
					element := (*ProcessCacheEntry)(value)
					result := int(element.ProcessContext.Process.FileEvent.FileFields.Mode)
					results = append(results, result)
					value = iterator.Next()
				}
				return results
			}, Field: field,
			Weight: eval.IteratorWeight,
		}, nil
	case "process.ancestors.file.modification_time":
		return &eval.IntArrayEvaluator{
			EvalFnc: func(ctx *eval.Context) []int {
				var results []int
				iterator := &ProcessAncestorsIterator{}
				value := iterator.Front(ctx)
				for value != nil {
					element := (*ProcessCacheEntry)(value)
					result := int(element.ProcessContext.Process.FileEvent.FileFields.MTime)
					results = append(results, result)
					value = iterator.Next()
				}
				return results
			}, Field: field,
			Weight: eval.IteratorWeight,
		}, nil
	case "process.ancestors.file.mount_id":
		return &eval.IntArrayEvaluator{
			EvalFnc: func(ctx *eval.Context) []int {
				var results []int
				iterator := &ProcessAncestorsIterator{}
				value := iterator.Front(ctx)
				for value != nil {
					element := (*ProcessCacheEntry)(value)
					result := int(element.ProcessContext.Process.FileEvent.FileFields.MountID)
					results = append(results, result)
					value = iterator.Next()
				}
				return results
			}, Field: field,
			Weight: eval.IteratorWeight,
		}, nil
	case "process.ancestors.file.name":
		return &eval.StringArrayEvaluator{
			OpOverrides: ProcessSymlinkBasename,
			EvalFnc: func(ctx *eval.Context) []string {
				var results []string
				iterator := &ProcessAncestorsIterator{}
				value := iterator.Front(ctx)
				for value != nil {
					element := (*ProcessCacheEntry)(value)
					result := element.ProcessContext.Process.FileEvent.BasenameStr
					results = append(results, result)
					value = iterator.Next()
				}
				return results
			}, Field: field,
			Weight: eval.IteratorWeight,
		}, nil
	case "process.ancestors.file.path":
		return &eval.StringArrayEvaluator{
			OpOverrides: ProcessSymlinkPathname,
			EvalFnc: func(ctx *eval.Context) []string {
				var results []string
				iterator := &ProcessAncestorsIterator{}
				value := iterator.Front(ctx)
				for value != nil {
					element := (*ProcessCacheEntry)(value)
					result := element.ProcessContext.Process.FileEvent.PathnameStr
					results = append(results, result)
					value = iterator.Next()
				}
				return results
			}, Field: field,
			Weight: eval.IteratorWeight,
		}, nil
	case "process.ancestors.file.rights":
		return &eval.IntArrayEvaluator{
			EvalFnc: func(ctx *eval.Context) []int {
				var results []int
				iterator := &ProcessAncestorsIterator{}
				value := iterator.Front(ctx)
				for value != nil {
					element := (*ProcessCacheEntry)(value)
					result := int(element.ProcessContext.Process.FileEvent.FileFields.Mode)
					results = append(results, result)
					value = iterator.Next()
				}
				return results
			}, Field: field,
			Weight: eval.IteratorWeight,
		}, nil
	case "process.ancestors.file.uid":
		return &eval.IntArrayEvaluator{
			EvalFnc: func(ctx *eval.Context) []int {
				var results []int
				iterator := &ProcessAncestorsIterator{}
				value := iterator.Front(ctx)
				for value != nil {
					element := (*ProcessCacheEntry)(value)
					result := int(element.ProcessContext.Process.FileEvent.FileFields.UID)
					results = append(results, result)
					value = iterator.Next()
				}
				return results
			}, Field: field,
			Weight: eval.IteratorWeight,
		}, nil
	case "process.ancestors.file.user":
		return &eval.StringArrayEvaluator{
			EvalFnc: func(ctx *eval.Context) []string {
				var results []string
				iterator := &ProcessAncestorsIterator{}
				value := iterator.Front(ctx)
				for value != nil {
					element := (*ProcessCacheEntry)(value)
					result := element.ProcessContext.Process.FileEvent.FileFields.User
					results = append(results, result)
					value = iterator.Next()
				}
				return results
			}, Field: field,
			Weight: eval.IteratorWeight,
		}, nil
	case "process.ancestors.fsgid":
		return &eval.IntArrayEvaluator{
			EvalFnc: func(ctx *eval.Context) []int {
				var results []int
				iterator := &ProcessAncestorsIterator{}
				value := iterator.Front(ctx)
				for value != nil {
					element := (*ProcessCacheEntry)(value)
					result := int(element.ProcessContext.Process.Credentials.FSGID)
					results = append(results, result)
					value = iterator.Next()
				}
				return results
			}, Field: field,
			Weight: eval.IteratorWeight,
		}, nil
	case "process.ancestors.fsgroup":
		return &eval.StringArrayEvaluator{
			EvalFnc: func(ctx *eval.Context) []string {
				var results []string
				iterator := &ProcessAncestorsIterator{}
				value := iterator.Front(ctx)
				for value != nil {
					element := (*ProcessCacheEntry)(value)
					result := element.ProcessContext.Process.Credentials.FSGroup
					results = append(results, result)
					value = iterator.Next()
				}
				return results
			}, Field: field,
			Weight: eval.IteratorWeight,
		}, nil
	case "process.ancestors.fsuid":
		return &eval.IntArrayEvaluator{
			EvalFnc: func(ctx *eval.Context) []int {
				var results []int
				iterator := &ProcessAncestorsIterator{}
				value := iterator.Front(ctx)
				for value != nil {
					element := (*ProcessCacheEntry)(value)
					result := int(element.ProcessContext.Process.Credentials.FSUID)
					results = append(results, result)
					value = iterator.Next()
				}
				return results
			}, Field: field,
			Weight: eval.IteratorWeight,
		}, nil
	case "process.ancestors.fsuser":
		return &eval.StringArrayEvaluator{
			EvalFnc: func(ctx *eval.Context) []string {
				var results []string
				iterator := &ProcessAncestorsIterator{}
				value := iterator.Front(ctx)
				for value != nil {
					element := (*ProcessCacheEntry)(value)
					result := element.ProcessContext.Process.Credentials.FSUser
					results = append(results, result)
					value = iterator.Next()
				}
				return results
			}, Field: field,
			Weight: eval.IteratorWeight,
		}, nil
	case "process.ancestors.gid":
		return &eval.IntArrayEvaluator{
			EvalFnc: func(ctx *eval.Context) []int {
				var results []int
				iterator := &ProcessAncestorsIterator{}
				value := iterator.Front(ctx)
				for value != nil {
					element := (*ProcessCacheEntry)(value)
					result := int(element.ProcessContext.Process.Credentials.GID)
					results = append(results, result)
					value = iterator.Next()
				}
				return results
			}, Field: field,
			Weight: eval.IteratorWeight,
		}, nil
	case "process.ancestors.group":
		return &eval.StringArrayEvaluator{
			EvalFnc: func(ctx *eval.Context) []string {
				var results []string
				iterator := &ProcessAncestorsIterator{}
				value := iterator.Front(ctx)
				for value != nil {
					element := (*ProcessCacheEntry)(value)
					result := element.ProcessContext.Process.Credentials.Group
					results = append(results, result)
					value = iterator.Next()
				}
				return results
			}, Field: field,
			Weight: eval.IteratorWeight,
		}, nil
	case "process.ancestors.is_thread":
		return &eval.BoolArrayEvaluator{
			EvalFnc: func(ctx *eval.Context) []bool {
				var results []bool
				iterator := &ProcessAncestorsIterator{}
				value := iterator.Front(ctx)
				for value != nil {
					element := (*ProcessCacheEntry)(value)
					result := element.ProcessContext.Process.IsThread
					results = append(results, result)
					value = iterator.Next()
				}
				return results
			}, Field: field,
			Weight: eval.IteratorWeight,
		}, nil
	case "process.ancestors.pid":
		return &eval.IntArrayEvaluator{
			EvalFnc: func(ctx *eval.Context) []int {
				var results []int
				iterator := &ProcessAncestorsIterator{}
				value := iterator.Front(ctx)
				for value != nil {
					element := (*ProcessCacheEntry)(value)
					result := int(element.ProcessContext.Process.PIDContext.Pid)
					results = append(results, result)
					value = iterator.Next()
				}
				return results
			}, Field: field,
			Weight: eval.IteratorWeight,
		}, nil
	case "process.ancestors.ppid":
		return &eval.IntArrayEvaluator{
			EvalFnc: func(ctx *eval.Context) []int {
				var results []int
				iterator := &ProcessAncestorsIterator{}
				value := iterator.Front(ctx)
				for value != nil {
					element := (*ProcessCacheEntry)(value)
					result := int(element.ProcessContext.Process.PPid)
					results = append(results, result)
					value = iterator.Next()
				}
				return results
			}, Field: field,
			Weight: eval.IteratorWeight,
		}, nil
	case "process.ancestors.tid":
		return &eval.IntArrayEvaluator{
			EvalFnc: func(ctx *eval.Context) []int {
				var results []int
				iterator := &ProcessAncestorsIterator{}
				value := iterator.Front(ctx)
				for value != nil {
					element := (*ProcessCacheEntry)(value)
					result := int(element.ProcessContext.Process.PIDContext.Tid)
					results = append(results, result)
					value = iterator.Next()
				}
				return results
			}, Field: field,
			Weight: eval.IteratorWeight,
		}, nil
	case "process.ancestors.tty_name":
		return &eval.StringArrayEvaluator{
			EvalFnc: func(ctx *eval.Context) []string {
				var results []string
				iterator := &ProcessAncestorsIterator{}
				value := iterator.Front(ctx)
				for value != nil {
					element := (*ProcessCacheEntry)(value)
					result := element.ProcessContext.Process.TTYName
					results = append(results, result)
					value = iterator.Next()
				}
				return results
			}, Field: field,
			Weight: eval.IteratorWeight,
		}, nil
	case "process.ancestors.uid":
		return &eval.IntArrayEvaluator{
			EvalFnc: func(ctx *eval.Context) []int {
				var results []int
				iterator := &ProcessAncestorsIterator{}
				value := iterator.Front(ctx)
				for value != nil {
					element := (*ProcessCacheEntry)(value)
					result := int(element.ProcessContext.Process.Credentials.UID)
					results = append(results, result)
					value = iterator.Next()
				}
				return results
			}, Field: field,
			Weight: eval.IteratorWeight,
		}, nil
	case "process.ancestors.user":
		return &eval.StringArrayEvaluator{
			EvalFnc: func(ctx *eval.Context) []string {
				var results []string
				iterator := &ProcessAncestorsIterator{}
				value := iterator.Front(ctx)
				for value != nil {
					element := (*ProcessCacheEntry)(value)
					result := element.ProcessContext.Process.Credentials.User
					results = append(results, result)
					value = iterator.Next()
				}
				return results
			}, Field: field,
			Weight: eval.IteratorWeight,
		}, nil
	case "process.args":
		return &eval.StringEvaluator{
			EvalFnc: func(ctx *eval.Context) string {
				event := GetEvent(ctx)
				return event.ProcessContext.Process.Args
			},
			Field:  field,
			Weight: 100 * eval.HandlerWeight,
		}, nil
	case "process.args_flags":
		return &eval.StringArrayEvaluator{
			EvalFnc: func(ctx *eval.Context) []string {
				event := GetEvent(ctx)
				return event.ProcessContext.Process.Argv
			},
			Field:  field,
			Weight: eval.HandlerWeight,
		}, nil
	case "process.args_options":
		return &eval.StringArrayEvaluator{
			EvalFnc: func(ctx *eval.Context) []string {
				event := GetEvent(ctx)
				return event.ProcessContext.Process.Argv
			},
			Field:  field,
			Weight: eval.HandlerWeight,
		}, nil
	case "process.args_truncated":
		return &eval.BoolEvaluator{
			EvalFnc: func(ctx *eval.Context) bool {
				event := GetEvent(ctx)
				return event.ProcessContext.Process.ArgsTruncated
			},
			Field:  field,
			Weight: eval.HandlerWeight,
		}, nil
	case "process.argv":
		return &eval.StringArrayEvaluator{
			EvalFnc: func(ctx *eval.Context) []string {
				event := GetEvent(ctx)
				return event.ProcessContext.Process.Argv
			},
			Field:  field,
			Weight: 100 * eval.HandlerWeight,
		}, nil
	case "process.argv0":
		return &eval.StringEvaluator{
			EvalFnc: func(ctx *eval.Context) string {
				event := GetEvent(ctx)
				return event.ProcessContext.Process.Argv0
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
				return int(event.ProcessContext.Process.CreatedAt)
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
				return event.ProcessContext.Process.Envp
			},
			Field:  field,
			Weight: eval.HandlerWeight,
		}, nil
	case "process.envs":
		return &eval.StringArrayEvaluator{
			EvalFnc: func(ctx *eval.Context) []string {
				event := GetEvent(ctx)
				return event.ProcessContext.Process.Envs
			},
			Field:  field,
			Weight: eval.HandlerWeight,
		}, nil
	case "process.envs_truncated":
		return &eval.BoolEvaluator{
			EvalFnc: func(ctx *eval.Context) bool {
				event := GetEvent(ctx)
				return event.ProcessContext.Process.EnvsTruncated
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
				return event.ProcessContext.Process.FileEvent.Filesystem
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
				return event.ProcessContext.Process.FileEvent.FileFields.Group
			},
			Field:  field,
			Weight: eval.HandlerWeight,
		}, nil
	case "process.file.in_upper_layer":
		return &eval.BoolEvaluator{
			EvalFnc: func(ctx *eval.Context) bool {
				event := GetEvent(ctx)
				return event.ProcessContext.Process.FileEvent.FileFields.InUpperLayer
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
			OpOverrides: ProcessSymlinkBasename,
			EvalFnc: func(ctx *eval.Context) string {
				event := GetEvent(ctx)
				return event.ProcessContext.Process.FileEvent.BasenameStr
			},
			Field:  field,
			Weight: eval.HandlerWeight,
		}, nil
	case "process.file.path":
		return &eval.StringEvaluator{
			OpOverrides: ProcessSymlinkPathname,
			EvalFnc: func(ctx *eval.Context) string {
				event := GetEvent(ctx)
				return event.ProcessContext.Process.FileEvent.PathnameStr
			},
			Field:  field,
			Weight: eval.HandlerWeight,
		}, nil
	case "process.file.rights":
		return &eval.IntEvaluator{
			EvalFnc: func(ctx *eval.Context) int {
				event := GetEvent(ctx)
				return int(event.ProcessContext.Process.FileEvent.FileFields.Mode)
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
				return event.ProcessContext.Process.FileEvent.FileFields.User
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
				var results []string
				iterator := &ProcessAncestorsIterator{}
				value := iterator.Front(ctx)
				for value != nil {
					element := (*ProcessCacheEntry)(value)
					result := element.ProcessContext.Process.Args
					results = append(results, result)
					value = iterator.Next()
				}
				return results
			}, Field: field,
			Weight: 100 * eval.IteratorWeight,
		}, nil
	case "ptrace.tracee.ancestors.args_flags":
		return &eval.StringArrayEvaluator{
			EvalFnc: func(ctx *eval.Context) []string {
				var results []string
				iterator := &ProcessAncestorsIterator{}
				value := iterator.Front(ctx)
				for value != nil {
					element := (*ProcessCacheEntry)(value)
					result := element.ProcessContext.Process.Argv
					results = append(results, result...)
					value = iterator.Next()
				}
				return results
			}, Field: field,
			Weight: eval.IteratorWeight,
		}, nil
	case "ptrace.tracee.ancestors.args_options":
		return &eval.StringArrayEvaluator{
			EvalFnc: func(ctx *eval.Context) []string {
				var results []string
				iterator := &ProcessAncestorsIterator{}
				value := iterator.Front(ctx)
				for value != nil {
					element := (*ProcessCacheEntry)(value)
					result := element.ProcessContext.Process.Argv
					results = append(results, result...)
					value = iterator.Next()
				}
				return results
			}, Field: field,
			Weight: eval.IteratorWeight,
		}, nil
	case "ptrace.tracee.ancestors.args_truncated":
		return &eval.BoolArrayEvaluator{
			EvalFnc: func(ctx *eval.Context) []bool {
				var results []bool
				iterator := &ProcessAncestorsIterator{}
				value := iterator.Front(ctx)
				for value != nil {
					element := (*ProcessCacheEntry)(value)
					result := element.ProcessContext.Process.ArgsTruncated
					results = append(results, result)
					value = iterator.Next()
				}
				return results
			}, Field: field,
			Weight: eval.IteratorWeight,
		}, nil
	case "ptrace.tracee.ancestors.argv":
		return &eval.StringArrayEvaluator{
			EvalFnc: func(ctx *eval.Context) []string {
				var results []string
				iterator := &ProcessAncestorsIterator{}
				value := iterator.Front(ctx)
				for value != nil {
					element := (*ProcessCacheEntry)(value)
					result := element.ProcessContext.Process.Argv
					results = append(results, result...)
					value = iterator.Next()
				}
				return results
			}, Field: field,
			Weight: 100 * eval.IteratorWeight,
		}, nil
	case "ptrace.tracee.ancestors.argv0":
		return &eval.StringArrayEvaluator{
			EvalFnc: func(ctx *eval.Context) []string {
				var results []string
				iterator := &ProcessAncestorsIterator{}
				value := iterator.Front(ctx)
				for value != nil {
					element := (*ProcessCacheEntry)(value)
					result := element.ProcessContext.Process.Argv0
					results = append(results, result)
					value = iterator.Next()
				}
				return results
			}, Field: field,
			Weight: 100 * eval.IteratorWeight,
		}, nil
	case "ptrace.tracee.ancestors.cap_effective":
		return &eval.IntArrayEvaluator{
			EvalFnc: func(ctx *eval.Context) []int {
				var results []int
				iterator := &ProcessAncestorsIterator{}
				value := iterator.Front(ctx)
				for value != nil {
					element := (*ProcessCacheEntry)(value)
					result := int(element.ProcessContext.Process.Credentials.CapEffective)
					results = append(results, result)
					value = iterator.Next()
				}
				return results
			}, Field: field,
			Weight: eval.IteratorWeight,
		}, nil
	case "ptrace.tracee.ancestors.cap_permitted":
		return &eval.IntArrayEvaluator{
			EvalFnc: func(ctx *eval.Context) []int {
				var results []int
				iterator := &ProcessAncestorsIterator{}
				value := iterator.Front(ctx)
				for value != nil {
					element := (*ProcessCacheEntry)(value)
					result := int(element.ProcessContext.Process.Credentials.CapPermitted)
					results = append(results, result)
					value = iterator.Next()
				}
				return results
			}, Field: field,
			Weight: eval.IteratorWeight,
		}, nil
	case "ptrace.tracee.ancestors.comm":
		return &eval.StringArrayEvaluator{
			EvalFnc: func(ctx *eval.Context) []string {
				var results []string
				iterator := &ProcessAncestorsIterator{}
				value := iterator.Front(ctx)
				for value != nil {
					element := (*ProcessCacheEntry)(value)
					result := element.ProcessContext.Process.Comm
					results = append(results, result)
					value = iterator.Next()
				}
				return results
			}, Field: field,
			Weight: eval.IteratorWeight,
		}, nil
	case "ptrace.tracee.ancestors.container.id":
		return &eval.StringArrayEvaluator{
			EvalFnc: func(ctx *eval.Context) []string {
				var results []string
				iterator := &ProcessAncestorsIterator{}
				value := iterator.Front(ctx)
				for value != nil {
					element := (*ProcessCacheEntry)(value)
					result := element.ProcessContext.Process.ContainerID
					results = append(results, result)
					value = iterator.Next()
				}
				return results
			}, Field: field,
			Weight: eval.IteratorWeight,
		}, nil
	case "ptrace.tracee.ancestors.cookie":
		return &eval.IntArrayEvaluator{
			EvalFnc: func(ctx *eval.Context) []int {
				var results []int
				iterator := &ProcessAncestorsIterator{}
				value := iterator.Front(ctx)
				for value != nil {
					element := (*ProcessCacheEntry)(value)
					result := int(element.ProcessContext.Process.Cookie)
					results = append(results, result)
					value = iterator.Next()
				}
				return results
			}, Field: field,
			Weight: eval.IteratorWeight,
		}, nil
	case "ptrace.tracee.ancestors.created_at":
		return &eval.IntArrayEvaluator{
			EvalFnc: func(ctx *eval.Context) []int {
				var results []int
				iterator := &ProcessAncestorsIterator{}
				value := iterator.Front(ctx)
				for value != nil {
					element := (*ProcessCacheEntry)(value)
					result := int(element.ProcessContext.Process.CreatedAt)
					results = append(results, result)
					value = iterator.Next()
				}
				return results
			}, Field: field,
			Weight: eval.IteratorWeight,
		}, nil
	case "ptrace.tracee.ancestors.egid":
		return &eval.IntArrayEvaluator{
			EvalFnc: func(ctx *eval.Context) []int {
				var results []int
				iterator := &ProcessAncestorsIterator{}
				value := iterator.Front(ctx)
				for value != nil {
					element := (*ProcessCacheEntry)(value)
					result := int(element.ProcessContext.Process.Credentials.EGID)
					results = append(results, result)
					value = iterator.Next()
				}
				return results
			}, Field: field,
			Weight: eval.IteratorWeight,
		}, nil
	case "ptrace.tracee.ancestors.egroup":
		return &eval.StringArrayEvaluator{
			EvalFnc: func(ctx *eval.Context) []string {
				var results []string
				iterator := &ProcessAncestorsIterator{}
				value := iterator.Front(ctx)
				for value != nil {
					element := (*ProcessCacheEntry)(value)
					result := element.ProcessContext.Process.Credentials.EGroup
					results = append(results, result)
					value = iterator.Next()
				}
				return results
			}, Field: field,
			Weight: eval.IteratorWeight,
		}, nil
	case "ptrace.tracee.ancestors.envp":
		return &eval.StringArrayEvaluator{
			EvalFnc: func(ctx *eval.Context) []string {
				var results []string
				iterator := &ProcessAncestorsIterator{}
				value := iterator.Front(ctx)
				for value != nil {
					element := (*ProcessCacheEntry)(value)
					result := element.ProcessContext.Process.Envp
					results = append(results, result...)
					value = iterator.Next()
				}
				return results
			}, Field: field,
			Weight: eval.IteratorWeight,
		}, nil
	case "ptrace.tracee.ancestors.envs":
		return &eval.StringArrayEvaluator{
			EvalFnc: func(ctx *eval.Context) []string {
				var results []string
				iterator := &ProcessAncestorsIterator{}
				value := iterator.Front(ctx)
				for value != nil {
					element := (*ProcessCacheEntry)(value)
					result := element.ProcessContext.Process.Envs
					results = append(results, result...)
					value = iterator.Next()
				}
				return results
			}, Field: field,
			Weight: eval.IteratorWeight,
		}, nil
	case "ptrace.tracee.ancestors.envs_truncated":
		return &eval.BoolArrayEvaluator{
			EvalFnc: func(ctx *eval.Context) []bool {
				var results []bool
				iterator := &ProcessAncestorsIterator{}
				value := iterator.Front(ctx)
				for value != nil {
					element := (*ProcessCacheEntry)(value)
					result := element.ProcessContext.Process.EnvsTruncated
					results = append(results, result)
					value = iterator.Next()
				}
				return results
			}, Field: field,
			Weight: eval.IteratorWeight,
		}, nil
	case "ptrace.tracee.ancestors.euid":
		return &eval.IntArrayEvaluator{
			EvalFnc: func(ctx *eval.Context) []int {
				var results []int
				iterator := &ProcessAncestorsIterator{}
				value := iterator.Front(ctx)
				for value != nil {
					element := (*ProcessCacheEntry)(value)
					result := int(element.ProcessContext.Process.Credentials.EUID)
					results = append(results, result)
					value = iterator.Next()
				}
				return results
			}, Field: field,
			Weight: eval.IteratorWeight,
		}, nil
	case "ptrace.tracee.ancestors.euser":
		return &eval.StringArrayEvaluator{
			EvalFnc: func(ctx *eval.Context) []string {
				var results []string
				iterator := &ProcessAncestorsIterator{}
				value := iterator.Front(ctx)
				for value != nil {
					element := (*ProcessCacheEntry)(value)
					result := element.ProcessContext.Process.Credentials.EUser
					results = append(results, result)
					value = iterator.Next()
				}
				return results
			}, Field: field,
			Weight: eval.IteratorWeight,
		}, nil
	case "ptrace.tracee.ancestors.file.change_time":
		return &eval.IntArrayEvaluator{
			EvalFnc: func(ctx *eval.Context) []int {
				var results []int
				iterator := &ProcessAncestorsIterator{}
				value := iterator.Front(ctx)
				for value != nil {
					element := (*ProcessCacheEntry)(value)
					result := int(element.ProcessContext.Process.FileEvent.FileFields.CTime)
					results = append(results, result)
					value = iterator.Next()
				}
				return results
			}, Field: field,
			Weight: eval.IteratorWeight,
		}, nil
	case "ptrace.tracee.ancestors.file.filesystem":
		return &eval.StringArrayEvaluator{
			EvalFnc: func(ctx *eval.Context) []string {
				var results []string
				iterator := &ProcessAncestorsIterator{}
				value := iterator.Front(ctx)
				for value != nil {
					element := (*ProcessCacheEntry)(value)
					result := element.ProcessContext.Process.FileEvent.Filesystem
					results = append(results, result)
					value = iterator.Next()
				}
				return results
			}, Field: field,
			Weight: eval.IteratorWeight,
		}, nil
	case "ptrace.tracee.ancestors.file.gid":
		return &eval.IntArrayEvaluator{
			EvalFnc: func(ctx *eval.Context) []int {
				var results []int
				iterator := &ProcessAncestorsIterator{}
				value := iterator.Front(ctx)
				for value != nil {
					element := (*ProcessCacheEntry)(value)
					result := int(element.ProcessContext.Process.FileEvent.FileFields.GID)
					results = append(results, result)
					value = iterator.Next()
				}
				return results
			}, Field: field,
			Weight: eval.IteratorWeight,
		}, nil
	case "ptrace.tracee.ancestors.file.group":
		return &eval.StringArrayEvaluator{
			EvalFnc: func(ctx *eval.Context) []string {
				var results []string
				iterator := &ProcessAncestorsIterator{}
				value := iterator.Front(ctx)
				for value != nil {
					element := (*ProcessCacheEntry)(value)
					result := element.ProcessContext.Process.FileEvent.FileFields.Group
					results = append(results, result)
					value = iterator.Next()
				}
				return results
			}, Field: field,
			Weight: eval.IteratorWeight,
		}, nil
	case "ptrace.tracee.ancestors.file.in_upper_layer":
		return &eval.BoolArrayEvaluator{
			EvalFnc: func(ctx *eval.Context) []bool {
				var results []bool
				iterator := &ProcessAncestorsIterator{}
				value := iterator.Front(ctx)
				for value != nil {
					element := (*ProcessCacheEntry)(value)
					result := element.ProcessContext.Process.FileEvent.FileFields.InUpperLayer
					results = append(results, result)
					value = iterator.Next()
				}
				return results
			}, Field: field,
			Weight: eval.IteratorWeight,
		}, nil
	case "ptrace.tracee.ancestors.file.inode":
		return &eval.IntArrayEvaluator{
			EvalFnc: func(ctx *eval.Context) []int {
				var results []int
				iterator := &ProcessAncestorsIterator{}
				value := iterator.Front(ctx)
				for value != nil {
					element := (*ProcessCacheEntry)(value)
					result := int(element.ProcessContext.Process.FileEvent.FileFields.Inode)
					results = append(results, result)
					value = iterator.Next()
				}
				return results
			}, Field: field,
			Weight: eval.IteratorWeight,
		}, nil
	case "ptrace.tracee.ancestors.file.mode":
		return &eval.IntArrayEvaluator{
			EvalFnc: func(ctx *eval.Context) []int {
				var results []int
				iterator := &ProcessAncestorsIterator{}
				value := iterator.Front(ctx)
				for value != nil {
					element := (*ProcessCacheEntry)(value)
					result := int(element.ProcessContext.Process.FileEvent.FileFields.Mode)
					results = append(results, result)
					value = iterator.Next()
				}
				return results
			}, Field: field,
			Weight: eval.IteratorWeight,
		}, nil
	case "ptrace.tracee.ancestors.file.modification_time":
		return &eval.IntArrayEvaluator{
			EvalFnc: func(ctx *eval.Context) []int {
				var results []int
				iterator := &ProcessAncestorsIterator{}
				value := iterator.Front(ctx)
				for value != nil {
					element := (*ProcessCacheEntry)(value)
					result := int(element.ProcessContext.Process.FileEvent.FileFields.MTime)
					results = append(results, result)
					value = iterator.Next()
				}
				return results
			}, Field: field,
			Weight: eval.IteratorWeight,
		}, nil
	case "ptrace.tracee.ancestors.file.mount_id":
		return &eval.IntArrayEvaluator{
			EvalFnc: func(ctx *eval.Context) []int {
				var results []int
				iterator := &ProcessAncestorsIterator{}
				value := iterator.Front(ctx)
				for value != nil {
					element := (*ProcessCacheEntry)(value)
					result := int(element.ProcessContext.Process.FileEvent.FileFields.MountID)
					results = append(results, result)
					value = iterator.Next()
				}
				return results
			}, Field: field,
			Weight: eval.IteratorWeight,
		}, nil
	case "ptrace.tracee.ancestors.file.name":
		return &eval.StringArrayEvaluator{
			OpOverrides: ProcessSymlinkBasename,
			EvalFnc: func(ctx *eval.Context) []string {
				var results []string
				iterator := &ProcessAncestorsIterator{}
				value := iterator.Front(ctx)
				for value != nil {
					element := (*ProcessCacheEntry)(value)
					result := element.ProcessContext.Process.FileEvent.BasenameStr
					results = append(results, result)
					value = iterator.Next()
				}
				return results
			}, Field: field,
			Weight: eval.IteratorWeight,
		}, nil
	case "ptrace.tracee.ancestors.file.path":
		return &eval.StringArrayEvaluator{
			OpOverrides: ProcessSymlinkPathname,
			EvalFnc: func(ctx *eval.Context) []string {
				var results []string
				iterator := &ProcessAncestorsIterator{}
				value := iterator.Front(ctx)
				for value != nil {
					element := (*ProcessCacheEntry)(value)
					result := element.ProcessContext.Process.FileEvent.PathnameStr
					results = append(results, result)
					value = iterator.Next()
				}
				return results
			}, Field: field,
			Weight: eval.IteratorWeight,
		}, nil
	case "ptrace.tracee.ancestors.file.rights":
		return &eval.IntArrayEvaluator{
			EvalFnc: func(ctx *eval.Context) []int {
				var results []int
				iterator := &ProcessAncestorsIterator{}
				value := iterator.Front(ctx)
				for value != nil {
					element := (*ProcessCacheEntry)(value)
					result := int(element.ProcessContext.Process.FileEvent.FileFields.Mode)
					results = append(results, result)
					value = iterator.Next()
				}
				return results
			}, Field: field,
			Weight: eval.IteratorWeight,
		}, nil
	case "ptrace.tracee.ancestors.file.uid":
		return &eval.IntArrayEvaluator{
			EvalFnc: func(ctx *eval.Context) []int {
				var results []int
				iterator := &ProcessAncestorsIterator{}
				value := iterator.Front(ctx)
				for value != nil {
					element := (*ProcessCacheEntry)(value)
					result := int(element.ProcessContext.Process.FileEvent.FileFields.UID)
					results = append(results, result)
					value = iterator.Next()
				}
				return results
			}, Field: field,
			Weight: eval.IteratorWeight,
		}, nil
	case "ptrace.tracee.ancestors.file.user":
		return &eval.StringArrayEvaluator{
			EvalFnc: func(ctx *eval.Context) []string {
				var results []string
				iterator := &ProcessAncestorsIterator{}
				value := iterator.Front(ctx)
				for value != nil {
					element := (*ProcessCacheEntry)(value)
					result := element.ProcessContext.Process.FileEvent.FileFields.User
					results = append(results, result)
					value = iterator.Next()
				}
				return results
			}, Field: field,
			Weight: eval.IteratorWeight,
		}, nil
	case "ptrace.tracee.ancestors.fsgid":
		return &eval.IntArrayEvaluator{
			EvalFnc: func(ctx *eval.Context) []int {
				var results []int
				iterator := &ProcessAncestorsIterator{}
				value := iterator.Front(ctx)
				for value != nil {
					element := (*ProcessCacheEntry)(value)
					result := int(element.ProcessContext.Process.Credentials.FSGID)
					results = append(results, result)
					value = iterator.Next()
				}
				return results
			}, Field: field,
			Weight: eval.IteratorWeight,
		}, nil
	case "ptrace.tracee.ancestors.fsgroup":
		return &eval.StringArrayEvaluator{
			EvalFnc: func(ctx *eval.Context) []string {
				var results []string
				iterator := &ProcessAncestorsIterator{}
				value := iterator.Front(ctx)
				for value != nil {
					element := (*ProcessCacheEntry)(value)
					result := element.ProcessContext.Process.Credentials.FSGroup
					results = append(results, result)
					value = iterator.Next()
				}
				return results
			}, Field: field,
			Weight: eval.IteratorWeight,
		}, nil
	case "ptrace.tracee.ancestors.fsuid":
		return &eval.IntArrayEvaluator{
			EvalFnc: func(ctx *eval.Context) []int {
				var results []int
				iterator := &ProcessAncestorsIterator{}
				value := iterator.Front(ctx)
				for value != nil {
					element := (*ProcessCacheEntry)(value)
					result := int(element.ProcessContext.Process.Credentials.FSUID)
					results = append(results, result)
					value = iterator.Next()
				}
				return results
			}, Field: field,
			Weight: eval.IteratorWeight,
		}, nil
	case "ptrace.tracee.ancestors.fsuser":
		return &eval.StringArrayEvaluator{
			EvalFnc: func(ctx *eval.Context) []string {
				var results []string
				iterator := &ProcessAncestorsIterator{}
				value := iterator.Front(ctx)
				for value != nil {
					element := (*ProcessCacheEntry)(value)
					result := element.ProcessContext.Process.Credentials.FSUser
					results = append(results, result)
					value = iterator.Next()
				}
				return results
			}, Field: field,
			Weight: eval.IteratorWeight,
		}, nil
	case "ptrace.tracee.ancestors.gid":
		return &eval.IntArrayEvaluator{
			EvalFnc: func(ctx *eval.Context) []int {
				var results []int
				iterator := &ProcessAncestorsIterator{}
				value := iterator.Front(ctx)
				for value != nil {
					element := (*ProcessCacheEntry)(value)
					result := int(element.ProcessContext.Process.Credentials.GID)
					results = append(results, result)
					value = iterator.Next()
				}
				return results
			}, Field: field,
			Weight: eval.IteratorWeight,
		}, nil
	case "ptrace.tracee.ancestors.group":
		return &eval.StringArrayEvaluator{
			EvalFnc: func(ctx *eval.Context) []string {
				var results []string
				iterator := &ProcessAncestorsIterator{}
				value := iterator.Front(ctx)
				for value != nil {
					element := (*ProcessCacheEntry)(value)
					result := element.ProcessContext.Process.Credentials.Group
					results = append(results, result)
					value = iterator.Next()
				}
				return results
			}, Field: field,
			Weight: eval.IteratorWeight,
		}, nil
	case "ptrace.tracee.ancestors.is_thread":
		return &eval.BoolArrayEvaluator{
			EvalFnc: func(ctx *eval.Context) []bool {
				var results []bool
				iterator := &ProcessAncestorsIterator{}
				value := iterator.Front(ctx)
				for value != nil {
					element := (*ProcessCacheEntry)(value)
					result := element.ProcessContext.Process.IsThread
					results = append(results, result)
					value = iterator.Next()
				}
				return results
			}, Field: field,
			Weight: eval.IteratorWeight,
		}, nil
	case "ptrace.tracee.ancestors.pid":
		return &eval.IntArrayEvaluator{
			EvalFnc: func(ctx *eval.Context) []int {
				var results []int
				iterator := &ProcessAncestorsIterator{}
				value := iterator.Front(ctx)
				for value != nil {
					element := (*ProcessCacheEntry)(value)
					result := int(element.ProcessContext.Process.PIDContext.Pid)
					results = append(results, result)
					value = iterator.Next()
				}
				return results
			}, Field: field,
			Weight: eval.IteratorWeight,
		}, nil
	case "ptrace.tracee.ancestors.ppid":
		return &eval.IntArrayEvaluator{
			EvalFnc: func(ctx *eval.Context) []int {
				var results []int
				iterator := &ProcessAncestorsIterator{}
				value := iterator.Front(ctx)
				for value != nil {
					element := (*ProcessCacheEntry)(value)
					result := int(element.ProcessContext.Process.PPid)
					results = append(results, result)
					value = iterator.Next()
				}
				return results
			}, Field: field,
			Weight: eval.IteratorWeight,
		}, nil
	case "ptrace.tracee.ancestors.tid":
		return &eval.IntArrayEvaluator{
			EvalFnc: func(ctx *eval.Context) []int {
				var results []int
				iterator := &ProcessAncestorsIterator{}
				value := iterator.Front(ctx)
				for value != nil {
					element := (*ProcessCacheEntry)(value)
					result := int(element.ProcessContext.Process.PIDContext.Tid)
					results = append(results, result)
					value = iterator.Next()
				}
				return results
			}, Field: field,
			Weight: eval.IteratorWeight,
		}, nil
	case "ptrace.tracee.ancestors.tty_name":
		return &eval.StringArrayEvaluator{
			EvalFnc: func(ctx *eval.Context) []string {
				var results []string
				iterator := &ProcessAncestorsIterator{}
				value := iterator.Front(ctx)
				for value != nil {
					element := (*ProcessCacheEntry)(value)
					result := element.ProcessContext.Process.TTYName
					results = append(results, result)
					value = iterator.Next()
				}
				return results
			}, Field: field,
			Weight: eval.IteratorWeight,
		}, nil
	case "ptrace.tracee.ancestors.uid":
		return &eval.IntArrayEvaluator{
			EvalFnc: func(ctx *eval.Context) []int {
				var results []int
				iterator := &ProcessAncestorsIterator{}
				value := iterator.Front(ctx)
				for value != nil {
					element := (*ProcessCacheEntry)(value)
					result := int(element.ProcessContext.Process.Credentials.UID)
					results = append(results, result)
					value = iterator.Next()
				}
				return results
			}, Field: field,
			Weight: eval.IteratorWeight,
		}, nil
	case "ptrace.tracee.ancestors.user":
		return &eval.StringArrayEvaluator{
			EvalFnc: func(ctx *eval.Context) []string {
				var results []string
				iterator := &ProcessAncestorsIterator{}
				value := iterator.Front(ctx)
				for value != nil {
					element := (*ProcessCacheEntry)(value)
					result := element.ProcessContext.Process.Credentials.User
					results = append(results, result)
					value = iterator.Next()
				}
				return results
			}, Field: field,
			Weight: eval.IteratorWeight,
		}, nil
	case "ptrace.tracee.args":
		return &eval.StringEvaluator{
			EvalFnc: func(ctx *eval.Context) string {
				event := GetEvent(ctx)
				return event.PTrace.Tracee.Process.Args
			},
			Field:  field,
			Weight: 100 * eval.HandlerWeight,
		}, nil
	case "ptrace.tracee.args_flags":
		return &eval.StringArrayEvaluator{
			EvalFnc: func(ctx *eval.Context) []string {
				event := GetEvent(ctx)
				return event.PTrace.Tracee.Process.Argv
			},
			Field:  field,
			Weight: eval.HandlerWeight,
		}, nil
	case "ptrace.tracee.args_options":
		return &eval.StringArrayEvaluator{
			EvalFnc: func(ctx *eval.Context) []string {
				event := GetEvent(ctx)
				return event.PTrace.Tracee.Process.Argv
			},
			Field:  field,
			Weight: eval.HandlerWeight,
		}, nil
	case "ptrace.tracee.args_truncated":
		return &eval.BoolEvaluator{
			EvalFnc: func(ctx *eval.Context) bool {
				event := GetEvent(ctx)
				return event.PTrace.Tracee.Process.ArgsTruncated
			},
			Field:  field,
			Weight: eval.HandlerWeight,
		}, nil
	case "ptrace.tracee.argv":
		return &eval.StringArrayEvaluator{
			EvalFnc: func(ctx *eval.Context) []string {
				event := GetEvent(ctx)
				return event.PTrace.Tracee.Process.Argv
			},
			Field:  field,
			Weight: 100 * eval.HandlerWeight,
		}, nil
	case "ptrace.tracee.argv0":
		return &eval.StringEvaluator{
			EvalFnc: func(ctx *eval.Context) string {
				event := GetEvent(ctx)
				return event.PTrace.Tracee.Process.Argv0
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
				return int(event.PTrace.Tracee.Process.CreatedAt)
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
				return event.PTrace.Tracee.Process.Envp
			},
			Field:  field,
			Weight: eval.HandlerWeight,
		}, nil
	case "ptrace.tracee.envs":
		return &eval.StringArrayEvaluator{
			EvalFnc: func(ctx *eval.Context) []string {
				event := GetEvent(ctx)
				return event.PTrace.Tracee.Process.Envs
			},
			Field:  field,
			Weight: eval.HandlerWeight,
		}, nil
	case "ptrace.tracee.envs_truncated":
		return &eval.BoolEvaluator{
			EvalFnc: func(ctx *eval.Context) bool {
				event := GetEvent(ctx)
				return event.PTrace.Tracee.Process.EnvsTruncated
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
				return event.PTrace.Tracee.Process.FileEvent.Filesystem
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
				return event.PTrace.Tracee.Process.FileEvent.FileFields.Group
			},
			Field:  field,
			Weight: eval.HandlerWeight,
		}, nil
	case "ptrace.tracee.file.in_upper_layer":
		return &eval.BoolEvaluator{
			EvalFnc: func(ctx *eval.Context) bool {
				event := GetEvent(ctx)
				return event.PTrace.Tracee.Process.FileEvent.FileFields.InUpperLayer
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
			OpOverrides: ProcessSymlinkBasename,
			EvalFnc: func(ctx *eval.Context) string {
				event := GetEvent(ctx)
				return event.PTrace.Tracee.Process.FileEvent.BasenameStr
			},
			Field:  field,
			Weight: eval.HandlerWeight,
		}, nil
	case "ptrace.tracee.file.path":
		return &eval.StringEvaluator{
			OpOverrides: ProcessSymlinkPathname,
			EvalFnc: func(ctx *eval.Context) string {
				event := GetEvent(ctx)
				return event.PTrace.Tracee.Process.FileEvent.PathnameStr
			},
			Field:  field,
			Weight: eval.HandlerWeight,
		}, nil
	case "ptrace.tracee.file.rights":
		return &eval.IntEvaluator{
			EvalFnc: func(ctx *eval.Context) int {
				event := GetEvent(ctx)
				return int(event.PTrace.Tracee.Process.FileEvent.FileFields.Mode)
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
				return event.PTrace.Tracee.Process.FileEvent.FileFields.User
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
				return event.RemoveXAttr.Name
			},
			Field:  field,
			Weight: eval.HandlerWeight,
		}, nil
	case "removexattr.file.destination.namespace":
		return &eval.StringEvaluator{
			EvalFnc: func(ctx *eval.Context) string {
				event := GetEvent(ctx)
				return event.RemoveXAttr.Namespace
			},
			Field:  field,
			Weight: eval.HandlerWeight,
		}, nil
	case "removexattr.file.filesystem":
		return &eval.StringEvaluator{
			EvalFnc: func(ctx *eval.Context) string {
				event := GetEvent(ctx)
				return event.RemoveXAttr.File.Filesystem
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
				return event.RemoveXAttr.File.FileFields.Group
			},
			Field:  field,
			Weight: eval.HandlerWeight,
		}, nil
	case "removexattr.file.in_upper_layer":
		return &eval.BoolEvaluator{
			EvalFnc: func(ctx *eval.Context) bool {
				event := GetEvent(ctx)
				return event.RemoveXAttr.File.FileFields.InUpperLayer
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
			OpOverrides: ProcessSymlinkBasename,
			EvalFnc: func(ctx *eval.Context) string {
				event := GetEvent(ctx)
				return event.RemoveXAttr.File.BasenameStr
			},
			Field:  field,
			Weight: eval.HandlerWeight,
		}, nil
	case "removexattr.file.path":
		return &eval.StringEvaluator{
			OpOverrides: ProcessSymlinkPathname,
			EvalFnc: func(ctx *eval.Context) string {
				event := GetEvent(ctx)
				return event.RemoveXAttr.File.PathnameStr
			},
			Field:  field,
			Weight: eval.HandlerWeight,
		}, nil
	case "removexattr.file.rights":
		return &eval.IntEvaluator{
			EvalFnc: func(ctx *eval.Context) int {
				event := GetEvent(ctx)
				return int(event.RemoveXAttr.File.FileFields.Mode)
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
				return event.RemoveXAttr.File.FileFields.User
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
				return event.Rename.New.Filesystem
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
				return event.Rename.New.FileFields.Group
			},
			Field:  field,
			Weight: eval.HandlerWeight,
		}, nil
	case "rename.file.destination.in_upper_layer":
		return &eval.BoolEvaluator{
			EvalFnc: func(ctx *eval.Context) bool {
				event := GetEvent(ctx)
				return event.Rename.New.FileFields.InUpperLayer
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
			OpOverrides: ProcessSymlinkBasename,
			EvalFnc: func(ctx *eval.Context) string {
				event := GetEvent(ctx)
				return event.Rename.New.BasenameStr
			},
			Field:  field,
			Weight: eval.HandlerWeight,
		}, nil
	case "rename.file.destination.path":
		return &eval.StringEvaluator{
			OpOverrides: ProcessSymlinkPathname,
			EvalFnc: func(ctx *eval.Context) string {
				event := GetEvent(ctx)
				return event.Rename.New.PathnameStr
			},
			Field:  field,
			Weight: eval.HandlerWeight,
		}, nil
	case "rename.file.destination.rights":
		return &eval.IntEvaluator{
			EvalFnc: func(ctx *eval.Context) int {
				event := GetEvent(ctx)
				return int(event.Rename.New.FileFields.Mode)
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
				return event.Rename.New.FileFields.User
			},
			Field:  field,
			Weight: eval.HandlerWeight,
		}, nil
	case "rename.file.filesystem":
		return &eval.StringEvaluator{
			EvalFnc: func(ctx *eval.Context) string {
				event := GetEvent(ctx)
				return event.Rename.Old.Filesystem
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
				return event.Rename.Old.FileFields.Group
			},
			Field:  field,
			Weight: eval.HandlerWeight,
		}, nil
	case "rename.file.in_upper_layer":
		return &eval.BoolEvaluator{
			EvalFnc: func(ctx *eval.Context) bool {
				event := GetEvent(ctx)
				return event.Rename.Old.FileFields.InUpperLayer
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
			OpOverrides: ProcessSymlinkBasename,
			EvalFnc: func(ctx *eval.Context) string {
				event := GetEvent(ctx)
				return event.Rename.Old.BasenameStr
			},
			Field:  field,
			Weight: eval.HandlerWeight,
		}, nil
	case "rename.file.path":
		return &eval.StringEvaluator{
			OpOverrides: ProcessSymlinkPathname,
			EvalFnc: func(ctx *eval.Context) string {
				event := GetEvent(ctx)
				return event.Rename.Old.PathnameStr
			},
			Field:  field,
			Weight: eval.HandlerWeight,
		}, nil
	case "rename.file.rights":
		return &eval.IntEvaluator{
			EvalFnc: func(ctx *eval.Context) int {
				event := GetEvent(ctx)
				return int(event.Rename.Old.FileFields.Mode)
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
				return event.Rename.Old.FileFields.User
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
				return event.Rmdir.File.Filesystem
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
				return event.Rmdir.File.FileFields.Group
			},
			Field:  field,
			Weight: eval.HandlerWeight,
		}, nil
	case "rmdir.file.in_upper_layer":
		return &eval.BoolEvaluator{
			EvalFnc: func(ctx *eval.Context) bool {
				event := GetEvent(ctx)
				return event.Rmdir.File.FileFields.InUpperLayer
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
			OpOverrides: ProcessSymlinkBasename,
			EvalFnc: func(ctx *eval.Context) string {
				event := GetEvent(ctx)
				return event.Rmdir.File.BasenameStr
			},
			Field:  field,
			Weight: eval.HandlerWeight,
		}, nil
	case "rmdir.file.path":
		return &eval.StringEvaluator{
			OpOverrides: ProcessSymlinkPathname,
			EvalFnc: func(ctx *eval.Context) string {
				event := GetEvent(ctx)
				return event.Rmdir.File.PathnameStr
			},
			Field:  field,
			Weight: eval.HandlerWeight,
		}, nil
	case "rmdir.file.rights":
		return &eval.IntEvaluator{
			EvalFnc: func(ctx *eval.Context) int {
				event := GetEvent(ctx)
				return int(event.Rmdir.File.FileFields.Mode)
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
				return event.Rmdir.File.FileFields.User
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
				return event.SELinux.BoolName
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
				return event.SetGID.EGroup
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
				return event.SetGID.FSGroup
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
				return event.SetGID.Group
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
				return event.SetUID.EUser
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
				return event.SetUID.FSUser
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
				return event.SetUID.User
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
				return event.SetXAttr.Name
			},
			Field:  field,
			Weight: eval.HandlerWeight,
		}, nil
	case "setxattr.file.destination.namespace":
		return &eval.StringEvaluator{
			EvalFnc: func(ctx *eval.Context) string {
				event := GetEvent(ctx)
				return event.SetXAttr.Namespace
			},
			Field:  field,
			Weight: eval.HandlerWeight,
		}, nil
	case "setxattr.file.filesystem":
		return &eval.StringEvaluator{
			EvalFnc: func(ctx *eval.Context) string {
				event := GetEvent(ctx)
				return event.SetXAttr.File.Filesystem
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
				return event.SetXAttr.File.FileFields.Group
			},
			Field:  field,
			Weight: eval.HandlerWeight,
		}, nil
	case "setxattr.file.in_upper_layer":
		return &eval.BoolEvaluator{
			EvalFnc: func(ctx *eval.Context) bool {
				event := GetEvent(ctx)
				return event.SetXAttr.File.FileFields.InUpperLayer
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
			OpOverrides: ProcessSymlinkBasename,
			EvalFnc: func(ctx *eval.Context) string {
				event := GetEvent(ctx)
				return event.SetXAttr.File.BasenameStr
			},
			Field:  field,
			Weight: eval.HandlerWeight,
		}, nil
	case "setxattr.file.path":
		return &eval.StringEvaluator{
			OpOverrides: ProcessSymlinkPathname,
			EvalFnc: func(ctx *eval.Context) string {
				event := GetEvent(ctx)
				return event.SetXAttr.File.PathnameStr
			},
			Field:  field,
			Weight: eval.HandlerWeight,
		}, nil
	case "setxattr.file.rights":
		return &eval.IntEvaluator{
			EvalFnc: func(ctx *eval.Context) int {
				event := GetEvent(ctx)
				return int(event.SetXAttr.File.FileFields.Mode)
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
				return event.SetXAttr.File.FileFields.User
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
				var results []string
				iterator := &ProcessAncestorsIterator{}
				value := iterator.Front(ctx)
				for value != nil {
					element := (*ProcessCacheEntry)(value)
					result := element.ProcessContext.Process.Args
					results = append(results, result)
					value = iterator.Next()
				}
				return results
			}, Field: field,
			Weight: 100 * eval.IteratorWeight,
		}, nil
	case "signal.target.ancestors.args_flags":
		return &eval.StringArrayEvaluator{
			EvalFnc: func(ctx *eval.Context) []string {
				var results []string
				iterator := &ProcessAncestorsIterator{}
				value := iterator.Front(ctx)
				for value != nil {
					element := (*ProcessCacheEntry)(value)
					result := element.ProcessContext.Process.Argv
					results = append(results, result...)
					value = iterator.Next()
				}
				return results
			}, Field: field,
			Weight: eval.IteratorWeight,
		}, nil
	case "signal.target.ancestors.args_options":
		return &eval.StringArrayEvaluator{
			EvalFnc: func(ctx *eval.Context) []string {
				var results []string
				iterator := &ProcessAncestorsIterator{}
				value := iterator.Front(ctx)
				for value != nil {
					element := (*ProcessCacheEntry)(value)
					result := element.ProcessContext.Process.Argv
					results = append(results, result...)
					value = iterator.Next()
				}
				return results
			}, Field: field,
			Weight: eval.IteratorWeight,
		}, nil
	case "signal.target.ancestors.args_truncated":
		return &eval.BoolArrayEvaluator{
			EvalFnc: func(ctx *eval.Context) []bool {
				var results []bool
				iterator := &ProcessAncestorsIterator{}
				value := iterator.Front(ctx)
				for value != nil {
					element := (*ProcessCacheEntry)(value)
					result := element.ProcessContext.Process.ArgsTruncated
					results = append(results, result)
					value = iterator.Next()
				}
				return results
			}, Field: field,
			Weight: eval.IteratorWeight,
		}, nil
	case "signal.target.ancestors.argv":
		return &eval.StringArrayEvaluator{
			EvalFnc: func(ctx *eval.Context) []string {
				var results []string
				iterator := &ProcessAncestorsIterator{}
				value := iterator.Front(ctx)
				for value != nil {
					element := (*ProcessCacheEntry)(value)
					result := element.ProcessContext.Process.Argv
					results = append(results, result...)
					value = iterator.Next()
				}
				return results
			}, Field: field,
			Weight: 100 * eval.IteratorWeight,
		}, nil
	case "signal.target.ancestors.argv0":
		return &eval.StringArrayEvaluator{
			EvalFnc: func(ctx *eval.Context) []string {
				var results []string
				iterator := &ProcessAncestorsIterator{}
				value := iterator.Front(ctx)
				for value != nil {
					element := (*ProcessCacheEntry)(value)
					result := element.ProcessContext.Process.Argv0
					results = append(results, result)
					value = iterator.Next()
				}
				return results
			}, Field: field,
			Weight: 100 * eval.IteratorWeight,
		}, nil
	case "signal.target.ancestors.cap_effective":
		return &eval.IntArrayEvaluator{
			EvalFnc: func(ctx *eval.Context) []int {
				var results []int
				iterator := &ProcessAncestorsIterator{}
				value := iterator.Front(ctx)
				for value != nil {
					element := (*ProcessCacheEntry)(value)
					result := int(element.ProcessContext.Process.Credentials.CapEffective)
					results = append(results, result)
					value = iterator.Next()
				}
				return results
			}, Field: field,
			Weight: eval.IteratorWeight,
		}, nil
	case "signal.target.ancestors.cap_permitted":
		return &eval.IntArrayEvaluator{
			EvalFnc: func(ctx *eval.Context) []int {
				var results []int
				iterator := &ProcessAncestorsIterator{}
				value := iterator.Front(ctx)
				for value != nil {
					element := (*ProcessCacheEntry)(value)
					result := int(element.ProcessContext.Process.Credentials.CapPermitted)
					results = append(results, result)
					value = iterator.Next()
				}
				return results
			}, Field: field,
			Weight: eval.IteratorWeight,
		}, nil
	case "signal.target.ancestors.comm":
		return &eval.StringArrayEvaluator{
			EvalFnc: func(ctx *eval.Context) []string {
				var results []string
				iterator := &ProcessAncestorsIterator{}
				value := iterator.Front(ctx)
				for value != nil {
					element := (*ProcessCacheEntry)(value)
					result := element.ProcessContext.Process.Comm
					results = append(results, result)
					value = iterator.Next()
				}
				return results
			}, Field: field,
			Weight: eval.IteratorWeight,
		}, nil
	case "signal.target.ancestors.container.id":
		return &eval.StringArrayEvaluator{
			EvalFnc: func(ctx *eval.Context) []string {
				var results []string
				iterator := &ProcessAncestorsIterator{}
				value := iterator.Front(ctx)
				for value != nil {
					element := (*ProcessCacheEntry)(value)
					result := element.ProcessContext.Process.ContainerID
					results = append(results, result)
					value = iterator.Next()
				}
				return results
			}, Field: field,
			Weight: eval.IteratorWeight,
		}, nil
	case "signal.target.ancestors.cookie":
		return &eval.IntArrayEvaluator{
			EvalFnc: func(ctx *eval.Context) []int {
				var results []int
				iterator := &ProcessAncestorsIterator{}
				value := iterator.Front(ctx)
				for value != nil {
					element := (*ProcessCacheEntry)(value)
					result := int(element.ProcessContext.Process.Cookie)
					results = append(results, result)
					value = iterator.Next()
				}
				return results
			}, Field: field,
			Weight: eval.IteratorWeight,
		}, nil
	case "signal.target.ancestors.created_at":
		return &eval.IntArrayEvaluator{
			EvalFnc: func(ctx *eval.Context) []int {
				var results []int
				iterator := &ProcessAncestorsIterator{}
				value := iterator.Front(ctx)
				for value != nil {
					element := (*ProcessCacheEntry)(value)
					result := int(element.ProcessContext.Process.CreatedAt)
					results = append(results, result)
					value = iterator.Next()
				}
				return results
			}, Field: field,
			Weight: eval.IteratorWeight,
		}, nil
	case "signal.target.ancestors.egid":
		return &eval.IntArrayEvaluator{
			EvalFnc: func(ctx *eval.Context) []int {
				var results []int
				iterator := &ProcessAncestorsIterator{}
				value := iterator.Front(ctx)
				for value != nil {
					element := (*ProcessCacheEntry)(value)
					result := int(element.ProcessContext.Process.Credentials.EGID)
					results = append(results, result)
					value = iterator.Next()
				}
				return results
			}, Field: field,
			Weight: eval.IteratorWeight,
		}, nil
	case "signal.target.ancestors.egroup":
		return &eval.StringArrayEvaluator{
			EvalFnc: func(ctx *eval.Context) []string {
				var results []string
				iterator := &ProcessAncestorsIterator{}
				value := iterator.Front(ctx)
				for value != nil {
					element := (*ProcessCacheEntry)(value)
					result := element.ProcessContext.Process.Credentials.EGroup
					results = append(results, result)
					value = iterator.Next()
				}
				return results
			}, Field: field,
			Weight: eval.IteratorWeight,
		}, nil
	case "signal.target.ancestors.envp":
		return &eval.StringArrayEvaluator{
			EvalFnc: func(ctx *eval.Context) []string {
				var results []string
				iterator := &ProcessAncestorsIterator{}
				value := iterator.Front(ctx)
				for value != nil {
					element := (*ProcessCacheEntry)(value)
					result := element.ProcessContext.Process.Envp
					results = append(results, result...)
					value = iterator.Next()
				}
				return results
			}, Field: field,
			Weight: eval.IteratorWeight,
		}, nil
	case "signal.target.ancestors.envs":
		return &eval.StringArrayEvaluator{
			EvalFnc: func(ctx *eval.Context) []string {
				var results []string
				iterator := &ProcessAncestorsIterator{}
				value := iterator.Front(ctx)
				for value != nil {
					element := (*ProcessCacheEntry)(value)
					result := element.ProcessContext.Process.Envs
					results = append(results, result...)
					value = iterator.Next()
				}
				return results
			}, Field: field,
			Weight: eval.IteratorWeight,
		}, nil
	case "signal.target.ancestors.envs_truncated":
		return &eval.BoolArrayEvaluator{
			EvalFnc: func(ctx *eval.Context) []bool {
				var results []bool
				iterator := &ProcessAncestorsIterator{}
				value := iterator.Front(ctx)
				for value != nil {
					element := (*ProcessCacheEntry)(value)
					result := element.ProcessContext.Process.EnvsTruncated
					results = append(results, result)
					value = iterator.Next()
				}
				return results
			}, Field: field,
			Weight: eval.IteratorWeight,
		}, nil
	case "signal.target.ancestors.euid":
		return &eval.IntArrayEvaluator{
			EvalFnc: func(ctx *eval.Context) []int {
				var results []int
				iterator := &ProcessAncestorsIterator{}
				value := iterator.Front(ctx)
				for value != nil {
					element := (*ProcessCacheEntry)(value)
					result := int(element.ProcessContext.Process.Credentials.EUID)
					results = append(results, result)
					value = iterator.Next()
				}
				return results
			}, Field: field,
			Weight: eval.IteratorWeight,
		}, nil
	case "signal.target.ancestors.euser":
		return &eval.StringArrayEvaluator{
			EvalFnc: func(ctx *eval.Context) []string {
				var results []string
				iterator := &ProcessAncestorsIterator{}
				value := iterator.Front(ctx)
				for value != nil {
					element := (*ProcessCacheEntry)(value)
					result := element.ProcessContext.Process.Credentials.EUser
					results = append(results, result)
					value = iterator.Next()
				}
				return results
			}, Field: field,
			Weight: eval.IteratorWeight,
		}, nil
	case "signal.target.ancestors.file.change_time":
		return &eval.IntArrayEvaluator{
			EvalFnc: func(ctx *eval.Context) []int {
				var results []int
				iterator := &ProcessAncestorsIterator{}
				value := iterator.Front(ctx)
				for value != nil {
					element := (*ProcessCacheEntry)(value)
					result := int(element.ProcessContext.Process.FileEvent.FileFields.CTime)
					results = append(results, result)
					value = iterator.Next()
				}
				return results
			}, Field: field,
			Weight: eval.IteratorWeight,
		}, nil
	case "signal.target.ancestors.file.filesystem":
		return &eval.StringArrayEvaluator{
			EvalFnc: func(ctx *eval.Context) []string {
				var results []string
				iterator := &ProcessAncestorsIterator{}
				value := iterator.Front(ctx)
				for value != nil {
					element := (*ProcessCacheEntry)(value)
					result := element.ProcessContext.Process.FileEvent.Filesystem
					results = append(results, result)
					value = iterator.Next()
				}
				return results
			}, Field: field,
			Weight: eval.IteratorWeight,
		}, nil
	case "signal.target.ancestors.file.gid":
		return &eval.IntArrayEvaluator{
			EvalFnc: func(ctx *eval.Context) []int {
				var results []int
				iterator := &ProcessAncestorsIterator{}
				value := iterator.Front(ctx)
				for value != nil {
					element := (*ProcessCacheEntry)(value)
					result := int(element.ProcessContext.Process.FileEvent.FileFields.GID)
					results = append(results, result)
					value = iterator.Next()
				}
				return results
			}, Field: field,
			Weight: eval.IteratorWeight,
		}, nil
	case "signal.target.ancestors.file.group":
		return &eval.StringArrayEvaluator{
			EvalFnc: func(ctx *eval.Context) []string {
				var results []string
				iterator := &ProcessAncestorsIterator{}
				value := iterator.Front(ctx)
				for value != nil {
					element := (*ProcessCacheEntry)(value)
					result := element.ProcessContext.Process.FileEvent.FileFields.Group
					results = append(results, result)
					value = iterator.Next()
				}
				return results
			}, Field: field,
			Weight: eval.IteratorWeight,
		}, nil
	case "signal.target.ancestors.file.in_upper_layer":
		return &eval.BoolArrayEvaluator{
			EvalFnc: func(ctx *eval.Context) []bool {
				var results []bool
				iterator := &ProcessAncestorsIterator{}
				value := iterator.Front(ctx)
				for value != nil {
					element := (*ProcessCacheEntry)(value)
					result := element.ProcessContext.Process.FileEvent.FileFields.InUpperLayer
					results = append(results, result)
					value = iterator.Next()
				}
				return results
			}, Field: field,
			Weight: eval.IteratorWeight,
		}, nil
	case "signal.target.ancestors.file.inode":
		return &eval.IntArrayEvaluator{
			EvalFnc: func(ctx *eval.Context) []int {
				var results []int
				iterator := &ProcessAncestorsIterator{}
				value := iterator.Front(ctx)
				for value != nil {
					element := (*ProcessCacheEntry)(value)
					result := int(element.ProcessContext.Process.FileEvent.FileFields.Inode)
					results = append(results, result)
					value = iterator.Next()
				}
				return results
			}, Field: field,
			Weight: eval.IteratorWeight,
		}, nil
	case "signal.target.ancestors.file.mode":
		return &eval.IntArrayEvaluator{
			EvalFnc: func(ctx *eval.Context) []int {
				var results []int
				iterator := &ProcessAncestorsIterator{}
				value := iterator.Front(ctx)
				for value != nil {
					element := (*ProcessCacheEntry)(value)
					result := int(element.ProcessContext.Process.FileEvent.FileFields.Mode)
					results = append(results, result)
					value = iterator.Next()
				}
				return results
			}, Field: field,
			Weight: eval.IteratorWeight,
		}, nil
	case "signal.target.ancestors.file.modification_time":
		return &eval.IntArrayEvaluator{
			EvalFnc: func(ctx *eval.Context) []int {
				var results []int
				iterator := &ProcessAncestorsIterator{}
				value := iterator.Front(ctx)
				for value != nil {
					element := (*ProcessCacheEntry)(value)
					result := int(element.ProcessContext.Process.FileEvent.FileFields.MTime)
					results = append(results, result)
					value = iterator.Next()
				}
				return results
			}, Field: field,
			Weight: eval.IteratorWeight,
		}, nil
	case "signal.target.ancestors.file.mount_id":
		return &eval.IntArrayEvaluator{
			EvalFnc: func(ctx *eval.Context) []int {
				var results []int
				iterator := &ProcessAncestorsIterator{}
				value := iterator.Front(ctx)
				for value != nil {
					element := (*ProcessCacheEntry)(value)
					result := int(element.ProcessContext.Process.FileEvent.FileFields.MountID)
					results = append(results, result)
					value = iterator.Next()
				}
				return results
			}, Field: field,
			Weight: eval.IteratorWeight,
		}, nil
	case "signal.target.ancestors.file.name":
		return &eval.StringArrayEvaluator{
			OpOverrides: ProcessSymlinkBasename,
			EvalFnc: func(ctx *eval.Context) []string {
				var results []string
				iterator := &ProcessAncestorsIterator{}
				value := iterator.Front(ctx)
				for value != nil {
					element := (*ProcessCacheEntry)(value)
					result := element.ProcessContext.Process.FileEvent.BasenameStr
					results = append(results, result)
					value = iterator.Next()
				}
				return results
			}, Field: field,
			Weight: eval.IteratorWeight,
		}, nil
	case "signal.target.ancestors.file.path":
		return &eval.StringArrayEvaluator{
			OpOverrides: ProcessSymlinkPathname,
			EvalFnc: func(ctx *eval.Context) []string {
				var results []string
				iterator := &ProcessAncestorsIterator{}
				value := iterator.Front(ctx)
				for value != nil {
					element := (*ProcessCacheEntry)(value)
					result := element.ProcessContext.Process.FileEvent.PathnameStr
					results = append(results, result)
					value = iterator.Next()
				}
				return results
			}, Field: field,
			Weight: eval.IteratorWeight,
		}, nil
	case "signal.target.ancestors.file.rights":
		return &eval.IntArrayEvaluator{
			EvalFnc: func(ctx *eval.Context) []int {
				var results []int
				iterator := &ProcessAncestorsIterator{}
				value := iterator.Front(ctx)
				for value != nil {
					element := (*ProcessCacheEntry)(value)
					result := int(element.ProcessContext.Process.FileEvent.FileFields.Mode)
					results = append(results, result)
					value = iterator.Next()
				}
				return results
			}, Field: field,
			Weight: eval.IteratorWeight,
		}, nil
	case "signal.target.ancestors.file.uid":
		return &eval.IntArrayEvaluator{
			EvalFnc: func(ctx *eval.Context) []int {
				var results []int
				iterator := &ProcessAncestorsIterator{}
				value := iterator.Front(ctx)
				for value != nil {
					element := (*ProcessCacheEntry)(value)
					result := int(element.ProcessContext.Process.FileEvent.FileFields.UID)
					results = append(results, result)
					value = iterator.Next()
				}
				return results
			}, Field: field,
			Weight: eval.IteratorWeight,
		}, nil
	case "signal.target.ancestors.file.user":
		return &eval.StringArrayEvaluator{
			EvalFnc: func(ctx *eval.Context) []string {
				var results []string
				iterator := &ProcessAncestorsIterator{}
				value := iterator.Front(ctx)
				for value != nil {
					element := (*ProcessCacheEntry)(value)
					result := element.ProcessContext.Process.FileEvent.FileFields.User
					results = append(results, result)
					value = iterator.Next()
				}
				return results
			}, Field: field,
			Weight: eval.IteratorWeight,
		}, nil
	case "signal.target.ancestors.fsgid":
		return &eval.IntArrayEvaluator{
			EvalFnc: func(ctx *eval.Context) []int {
				var results []int
				iterator := &ProcessAncestorsIterator{}
				value := iterator.Front(ctx)
				for value != nil {
					element := (*ProcessCacheEntry)(value)
					result := int(element.ProcessContext.Process.Credentials.FSGID)
					results = append(results, result)
					value = iterator.Next()
				}
				return results
			}, Field: field,
			Weight: eval.IteratorWeight,
		}, nil
	case "signal.target.ancestors.fsgroup":
		return &eval.StringArrayEvaluator{
			EvalFnc: func(ctx *eval.Context) []string {
				var results []string
				iterator := &ProcessAncestorsIterator{}
				value := iterator.Front(ctx)
				for value != nil {
					element := (*ProcessCacheEntry)(value)
					result := element.ProcessContext.Process.Credentials.FSGroup
					results = append(results, result)
					value = iterator.Next()
				}
				return results
			}, Field: field,
			Weight: eval.IteratorWeight,
		}, nil
	case "signal.target.ancestors.fsuid":
		return &eval.IntArrayEvaluator{
			EvalFnc: func(ctx *eval.Context) []int {
				var results []int
				iterator := &ProcessAncestorsIterator{}
				value := iterator.Front(ctx)
				for value != nil {
					element := (*ProcessCacheEntry)(value)
					result := int(element.ProcessContext.Process.Credentials.FSUID)
					results = append(results, result)
					value = iterator.Next()
				}
				return results
			}, Field: field,
			Weight: eval.IteratorWeight,
		}, nil
	case "signal.target.ancestors.fsuser":
		return &eval.StringArrayEvaluator{
			EvalFnc: func(ctx *eval.Context) []string {
				var results []string
				iterator := &ProcessAncestorsIterator{}
				value := iterator.Front(ctx)
				for value != nil {
					element := (*ProcessCacheEntry)(value)
					result := element.ProcessContext.Process.Credentials.FSUser
					results = append(results, result)
					value = iterator.Next()
				}
				return results
			}, Field: field,
			Weight: eval.IteratorWeight,
		}, nil
	case "signal.target.ancestors.gid":
		return &eval.IntArrayEvaluator{
			EvalFnc: func(ctx *eval.Context) []int {
				var results []int
				iterator := &ProcessAncestorsIterator{}
				value := iterator.Front(ctx)
				for value != nil {
					element := (*ProcessCacheEntry)(value)
					result := int(element.ProcessContext.Process.Credentials.GID)
					results = append(results, result)
					value = iterator.Next()
				}
				return results
			}, Field: field,
			Weight: eval.IteratorWeight,
		}, nil
	case "signal.target.ancestors.group":
		return &eval.StringArrayEvaluator{
			EvalFnc: func(ctx *eval.Context) []string {
				var results []string
				iterator := &ProcessAncestorsIterator{}
				value := iterator.Front(ctx)
				for value != nil {
					element := (*ProcessCacheEntry)(value)
					result := element.ProcessContext.Process.Credentials.Group
					results = append(results, result)
					value = iterator.Next()
				}
				return results
			}, Field: field,
			Weight: eval.IteratorWeight,
		}, nil
	case "signal.target.ancestors.is_thread":
		return &eval.BoolArrayEvaluator{
			EvalFnc: func(ctx *eval.Context) []bool {
				var results []bool
				iterator := &ProcessAncestorsIterator{}
				value := iterator.Front(ctx)
				for value != nil {
					element := (*ProcessCacheEntry)(value)
					result := element.ProcessContext.Process.IsThread
					results = append(results, result)
					value = iterator.Next()
				}
				return results
			}, Field: field,
			Weight: eval.IteratorWeight,
		}, nil
	case "signal.target.ancestors.pid":
		return &eval.IntArrayEvaluator{
			EvalFnc: func(ctx *eval.Context) []int {
				var results []int
				iterator := &ProcessAncestorsIterator{}
				value := iterator.Front(ctx)
				for value != nil {
					element := (*ProcessCacheEntry)(value)
					result := int(element.ProcessContext.Process.PIDContext.Pid)
					results = append(results, result)
					value = iterator.Next()
				}
				return results
			}, Field: field,
			Weight: eval.IteratorWeight,
		}, nil
	case "signal.target.ancestors.ppid":
		return &eval.IntArrayEvaluator{
			EvalFnc: func(ctx *eval.Context) []int {
				var results []int
				iterator := &ProcessAncestorsIterator{}
				value := iterator.Front(ctx)
				for value != nil {
					element := (*ProcessCacheEntry)(value)
					result := int(element.ProcessContext.Process.PPid)
					results = append(results, result)
					value = iterator.Next()
				}
				return results
			}, Field: field,
			Weight: eval.IteratorWeight,
		}, nil
	case "signal.target.ancestors.tid":
		return &eval.IntArrayEvaluator{
			EvalFnc: func(ctx *eval.Context) []int {
				var results []int
				iterator := &ProcessAncestorsIterator{}
				value := iterator.Front(ctx)
				for value != nil {
					element := (*ProcessCacheEntry)(value)
					result := int(element.ProcessContext.Process.PIDContext.Tid)
					results = append(results, result)
					value = iterator.Next()
				}
				return results
			}, Field: field,
			Weight: eval.IteratorWeight,
		}, nil
	case "signal.target.ancestors.tty_name":
		return &eval.StringArrayEvaluator{
			EvalFnc: func(ctx *eval.Context) []string {
				var results []string
				iterator := &ProcessAncestorsIterator{}
				value := iterator.Front(ctx)
				for value != nil {
					element := (*ProcessCacheEntry)(value)
					result := element.ProcessContext.Process.TTYName
					results = append(results, result)
					value = iterator.Next()
				}
				return results
			}, Field: field,
			Weight: eval.IteratorWeight,
		}, nil
	case "signal.target.ancestors.uid":
		return &eval.IntArrayEvaluator{
			EvalFnc: func(ctx *eval.Context) []int {
				var results []int
				iterator := &ProcessAncestorsIterator{}
				value := iterator.Front(ctx)
				for value != nil {
					element := (*ProcessCacheEntry)(value)
					result := int(element.ProcessContext.Process.Credentials.UID)
					results = append(results, result)
					value = iterator.Next()
				}
				return results
			}, Field: field,
			Weight: eval.IteratorWeight,
		}, nil
	case "signal.target.ancestors.user":
		return &eval.StringArrayEvaluator{
			EvalFnc: func(ctx *eval.Context) []string {
				var results []string
				iterator := &ProcessAncestorsIterator{}
				value := iterator.Front(ctx)
				for value != nil {
					element := (*ProcessCacheEntry)(value)
					result := element.ProcessContext.Process.Credentials.User
					results = append(results, result)
					value = iterator.Next()
				}
				return results
			}, Field: field,
			Weight: eval.IteratorWeight,
		}, nil
	case "signal.target.args":
		return &eval.StringEvaluator{
			EvalFnc: func(ctx *eval.Context) string {
				event := GetEvent(ctx)
				return event.Signal.Target.Process.Args
			},
			Field:  field,
			Weight: 100 * eval.HandlerWeight,
		}, nil
	case "signal.target.args_flags":
		return &eval.StringArrayEvaluator{
			EvalFnc: func(ctx *eval.Context) []string {
				event := GetEvent(ctx)
				return event.Signal.Target.Process.Argv
			},
			Field:  field,
			Weight: eval.HandlerWeight,
		}, nil
	case "signal.target.args_options":
		return &eval.StringArrayEvaluator{
			EvalFnc: func(ctx *eval.Context) []string {
				event := GetEvent(ctx)
				return event.Signal.Target.Process.Argv
			},
			Field:  field,
			Weight: eval.HandlerWeight,
		}, nil
	case "signal.target.args_truncated":
		return &eval.BoolEvaluator{
			EvalFnc: func(ctx *eval.Context) bool {
				event := GetEvent(ctx)
				return event.Signal.Target.Process.ArgsTruncated
			},
			Field:  field,
			Weight: eval.HandlerWeight,
		}, nil
	case "signal.target.argv":
		return &eval.StringArrayEvaluator{
			EvalFnc: func(ctx *eval.Context) []string {
				event := GetEvent(ctx)
				return event.Signal.Target.Process.Argv
			},
			Field:  field,
			Weight: 100 * eval.HandlerWeight,
		}, nil
	case "signal.target.argv0":
		return &eval.StringEvaluator{
			EvalFnc: func(ctx *eval.Context) string {
				event := GetEvent(ctx)
				return event.Signal.Target.Process.Argv0
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
				return int(event.Signal.Target.Process.CreatedAt)
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
				return event.Signal.Target.Process.Envp
			},
			Field:  field,
			Weight: eval.HandlerWeight,
		}, nil
	case "signal.target.envs":
		return &eval.StringArrayEvaluator{
			EvalFnc: func(ctx *eval.Context) []string {
				event := GetEvent(ctx)
				return event.Signal.Target.Process.Envs
			},
			Field:  field,
			Weight: eval.HandlerWeight,
		}, nil
	case "signal.target.envs_truncated":
		return &eval.BoolEvaluator{
			EvalFnc: func(ctx *eval.Context) bool {
				event := GetEvent(ctx)
				return event.Signal.Target.Process.EnvsTruncated
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
				return event.Signal.Target.Process.FileEvent.Filesystem
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
				return event.Signal.Target.Process.FileEvent.FileFields.Group
			},
			Field:  field,
			Weight: eval.HandlerWeight,
		}, nil
	case "signal.target.file.in_upper_layer":
		return &eval.BoolEvaluator{
			EvalFnc: func(ctx *eval.Context) bool {
				event := GetEvent(ctx)
				return event.Signal.Target.Process.FileEvent.FileFields.InUpperLayer
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
			OpOverrides: ProcessSymlinkBasename,
			EvalFnc: func(ctx *eval.Context) string {
				event := GetEvent(ctx)
				return event.Signal.Target.Process.FileEvent.BasenameStr
			},
			Field:  field,
			Weight: eval.HandlerWeight,
		}, nil
	case "signal.target.file.path":
		return &eval.StringEvaluator{
			OpOverrides: ProcessSymlinkPathname,
			EvalFnc: func(ctx *eval.Context) string {
				event := GetEvent(ctx)
				return event.Signal.Target.Process.FileEvent.PathnameStr
			},
			Field:  field,
			Weight: eval.HandlerWeight,
		}, nil
	case "signal.target.file.rights":
		return &eval.IntEvaluator{
			EvalFnc: func(ctx *eval.Context) int {
				event := GetEvent(ctx)
				return int(event.Signal.Target.Process.FileEvent.FileFields.Mode)
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
				return event.Signal.Target.Process.FileEvent.FileFields.User
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
				return event.Splice.File.Filesystem
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
				return event.Splice.File.FileFields.Group
			},
			Field:  field,
			Weight: eval.HandlerWeight,
		}, nil
	case "splice.file.in_upper_layer":
		return &eval.BoolEvaluator{
			EvalFnc: func(ctx *eval.Context) bool {
				event := GetEvent(ctx)
				return event.Splice.File.FileFields.InUpperLayer
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
			OpOverrides: ProcessSymlinkBasename,
			EvalFnc: func(ctx *eval.Context) string {
				event := GetEvent(ctx)
				return event.Splice.File.BasenameStr
			},
			Field:  field,
			Weight: eval.HandlerWeight,
		}, nil
	case "splice.file.path":
		return &eval.StringEvaluator{
			OpOverrides: ProcessSymlinkPathname,
			EvalFnc: func(ctx *eval.Context) string {
				event := GetEvent(ctx)
				return event.Splice.File.PathnameStr
			},
			Field:  field,
			Weight: eval.HandlerWeight,
		}, nil
	case "splice.file.rights":
		return &eval.IntEvaluator{
			EvalFnc: func(ctx *eval.Context) int {
				event := GetEvent(ctx)
				return int(event.Splice.File.FileFields.Mode)
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
				return event.Splice.File.FileFields.User
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
				return event.Unlink.File.Filesystem
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
				return event.Unlink.File.FileFields.Group
			},
			Field:  field,
			Weight: eval.HandlerWeight,
		}, nil
	case "unlink.file.in_upper_layer":
		return &eval.BoolEvaluator{
			EvalFnc: func(ctx *eval.Context) bool {
				event := GetEvent(ctx)
				return event.Unlink.File.FileFields.InUpperLayer
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
			OpOverrides: ProcessSymlinkBasename,
			EvalFnc: func(ctx *eval.Context) string {
				event := GetEvent(ctx)
				return event.Unlink.File.BasenameStr
			},
			Field:  field,
			Weight: eval.HandlerWeight,
		}, nil
	case "unlink.file.path":
		return &eval.StringEvaluator{
			OpOverrides: ProcessSymlinkPathname,
			EvalFnc: func(ctx *eval.Context) string {
				event := GetEvent(ctx)
				return event.Unlink.File.PathnameStr
			},
			Field:  field,
			Weight: eval.HandlerWeight,
		}, nil
	case "unlink.file.rights":
		return &eval.IntEvaluator{
			EvalFnc: func(ctx *eval.Context) int {
				event := GetEvent(ctx)
				return int(event.Unlink.File.FileFields.Mode)
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
				return event.Unlink.File.FileFields.User
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
				return event.Utimes.File.Filesystem
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
				return event.Utimes.File.FileFields.Group
			},
			Field:  field,
			Weight: eval.HandlerWeight,
		}, nil
	case "utimes.file.in_upper_layer":
		return &eval.BoolEvaluator{
			EvalFnc: func(ctx *eval.Context) bool {
				event := GetEvent(ctx)
				return event.Utimes.File.FileFields.InUpperLayer
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
			OpOverrides: ProcessSymlinkBasename,
			EvalFnc: func(ctx *eval.Context) string {
				event := GetEvent(ctx)
				return event.Utimes.File.BasenameStr
			},
			Field:  field,
			Weight: eval.HandlerWeight,
		}, nil
	case "utimes.file.path":
		return &eval.StringEvaluator{
			OpOverrides: ProcessSymlinkPathname,
			EvalFnc: func(ctx *eval.Context) string {
				event := GetEvent(ctx)
				return event.Utimes.File.PathnameStr
			},
			Field:  field,
			Weight: eval.HandlerWeight,
		}, nil
	case "utimes.file.rights":
		return &eval.IntEvaluator{
			EvalFnc: func(ctx *eval.Context) int {
				event := GetEvent(ctx)
				return int(event.Utimes.File.FileFields.Mode)
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
				return event.Utimes.File.FileFields.User
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
func GetFieldValue(ctx *eval.Context, field eval.Field) (interface{}, error) {
	event := GetEvent(ctx)
	switch field {
	case "async":
		return event.Async, nil
	case "bind.addr.family":
		return int(event.Bind.AddrFamily), nil
	case "bind.addr.ip":
		return event.Bind.Addr.IPNet, nil
	case "bind.addr.port":
		return int(event.Bind.Addr.Port), nil
	case "bind.retval":
		return int(event.Bind.SyscallEvent.Retval), nil
	case "bpf.cmd":
		return int(event.BPF.Cmd), nil
	case "bpf.map.name":
		return event.BPF.Map.Name, nil
	case "bpf.map.type":
		return int(event.BPF.Map.Type), nil
	case "bpf.prog.attach_type":
		return int(event.BPF.Program.AttachType), nil
	case "bpf.prog.helpers":
		result := make([]int, len(event.BPF.Program.Helpers))
		for i, v := range event.BPF.Program.Helpers {
			result[i] = int(v)
		}
		return result, nil
	case "bpf.prog.name":
		return event.BPF.Program.Name, nil
	case "bpf.prog.tag":
		return event.BPF.Program.Tag, nil
	case "bpf.prog.type":
		return int(event.BPF.Program.Type), nil
	case "bpf.retval":
		return int(event.BPF.SyscallEvent.Retval), nil
	case "capset.cap_effective":
		return int(event.Capset.CapEffective), nil
	case "capset.cap_permitted":
		return int(event.Capset.CapPermitted), nil
	case "chmod.file.change_time":
		return int(event.Chmod.File.FileFields.CTime), nil
	case "chmod.file.destination.mode":
		return int(event.Chmod.Mode), nil
	case "chmod.file.destination.rights":
		return int(event.Chmod.Mode), nil
	case "chmod.file.filesystem":
		return event.Chmod.File.Filesystem, nil
	case "chmod.file.gid":
		return int(event.Chmod.File.FileFields.GID), nil
	case "chmod.file.group":
		return event.Chmod.File.FileFields.Group, nil
	case "chmod.file.in_upper_layer":
		return event.Chmod.File.FileFields.InUpperLayer, nil
	case "chmod.file.inode":
		return int(event.Chmod.File.FileFields.Inode), nil
	case "chmod.file.mode":
		return int(event.Chmod.File.FileFields.Mode), nil
	case "chmod.file.modification_time":
		return int(event.Chmod.File.FileFields.MTime), nil
	case "chmod.file.mount_id":
		return int(event.Chmod.File.FileFields.MountID), nil
	case "chmod.file.name":
		return event.Chmod.File.BasenameStr, nil
	case "chmod.file.path":
		return event.Chmod.File.PathnameStr, nil
	case "chmod.file.rights":
		return int(event.Chmod.File.FileFields.Mode), nil
	case "chmod.file.uid":
		return int(event.Chmod.File.FileFields.UID), nil
	case "chmod.file.user":
		return event.Chmod.File.FileFields.User, nil
	case "chmod.retval":
		return int(event.Chmod.SyscallEvent.Retval), nil
	case "chown.file.change_time":
		return int(event.Chown.File.FileFields.CTime), nil
	case "chown.file.destination.gid":
		return int(event.Chown.GID), nil
	case "chown.file.destination.group":
		return event.Chown.Group, nil
	case "chown.file.destination.uid":
		return int(event.Chown.UID), nil
	case "chown.file.destination.user":
		return event.Chown.User, nil
	case "chown.file.filesystem":
		return event.Chown.File.Filesystem, nil
	case "chown.file.gid":
		return int(event.Chown.File.FileFields.GID), nil
	case "chown.file.group":
		return event.Chown.File.FileFields.Group, nil
	case "chown.file.in_upper_layer":
		return event.Chown.File.FileFields.InUpperLayer, nil
	case "chown.file.inode":
		return int(event.Chown.File.FileFields.Inode), nil
	case "chown.file.mode":
		return int(event.Chown.File.FileFields.Mode), nil
	case "chown.file.modification_time":
		return int(event.Chown.File.FileFields.MTime), nil
	case "chown.file.mount_id":
		return int(event.Chown.File.FileFields.MountID), nil
	case "chown.file.name":
		return event.Chown.File.BasenameStr, nil
	case "chown.file.path":
		return event.Chown.File.PathnameStr, nil
	case "chown.file.rights":
		return int(event.Chown.File.FileFields.Mode), nil
	case "chown.file.uid":
		return int(event.Chown.File.FileFields.UID), nil
	case "chown.file.user":
		return event.Chown.File.FileFields.User, nil
	case "chown.retval":
		return int(event.Chown.SyscallEvent.Retval), nil
	case "container.id":
		return event.ContainerContext.ID, nil
	case "container.tags":
		return event.ContainerContext.Tags, nil
	case "dns.question.class":
		return int(event.DNS.Class), nil
	case "dns.question.count":
		return int(event.DNS.Count), nil
	case "dns.question.name":
		return event.DNS.Name, nil
	case "dns.question.size":
		return int(event.DNS.Size), nil
	case "dns.question.type":
		return int(event.DNS.Type), nil
	case "exec.args":
		return event.Exec.Process.Args, nil
	case "exec.args_flags":
		return event.Exec.Process.Argv, nil
	case "exec.args_options":
		return event.Exec.Process.Argv, nil
	case "exec.args_truncated":
		return event.Exec.Process.ArgsTruncated, nil
	case "exec.argv":
		return event.Exec.Process.Argv, nil
	case "exec.argv0":
		return event.Exec.Process.Argv0, nil
	case "exec.cap_effective":
		return int(event.Exec.Process.Credentials.CapEffective), nil
	case "exec.cap_permitted":
		return int(event.Exec.Process.Credentials.CapPermitted), nil
	case "exec.comm":
		return event.Exec.Process.Comm, nil
	case "exec.container.id":
		return event.Exec.Process.ContainerID, nil
	case "exec.cookie":
		return int(event.Exec.Process.Cookie), nil
	case "exec.created_at":
		return int(event.Exec.Process.CreatedAt), nil
	case "exec.egid":
		return int(event.Exec.Process.Credentials.EGID), nil
	case "exec.egroup":
		return event.Exec.Process.Credentials.EGroup, nil
	case "exec.envp":
		return event.Exec.Process.Envp, nil
	case "exec.envs":
		return event.Exec.Process.Envs, nil
	case "exec.envs_truncated":
		return event.Exec.Process.EnvsTruncated, nil
	case "exec.euid":
		return int(event.Exec.Process.Credentials.EUID), nil
	case "exec.euser":
		return event.Exec.Process.Credentials.EUser, nil
	case "exec.file.change_time":
		return int(event.Exec.Process.FileEvent.FileFields.CTime), nil
	case "exec.file.filesystem":
		return event.Exec.Process.FileEvent.Filesystem, nil
	case "exec.file.gid":
		return int(event.Exec.Process.FileEvent.FileFields.GID), nil
	case "exec.file.group":
		return event.Exec.Process.FileEvent.FileFields.Group, nil
	case "exec.file.in_upper_layer":
		return event.Exec.Process.FileEvent.FileFields.InUpperLayer, nil
	case "exec.file.inode":
		return int(event.Exec.Process.FileEvent.FileFields.Inode), nil
	case "exec.file.mode":
		return int(event.Exec.Process.FileEvent.FileFields.Mode), nil
	case "exec.file.modification_time":
		return int(event.Exec.Process.FileEvent.FileFields.MTime), nil
	case "exec.file.mount_id":
		return int(event.Exec.Process.FileEvent.FileFields.MountID), nil
	case "exec.file.name":
		return event.Exec.Process.FileEvent.BasenameStr, nil
	case "exec.file.path":
		return event.Exec.Process.FileEvent.PathnameStr, nil
	case "exec.file.rights":
		return int(event.Exec.Process.FileEvent.FileFields.Mode), nil
	case "exec.file.uid":
		return int(event.Exec.Process.FileEvent.FileFields.UID), nil
	case "exec.file.user":
		return event.Exec.Process.FileEvent.FileFields.User, nil
	case "exec.fsgid":
		return int(event.Exec.Process.Credentials.FSGID), nil
	case "exec.fsgroup":
		return event.Exec.Process.Credentials.FSGroup, nil
	case "exec.fsuid":
		return int(event.Exec.Process.Credentials.FSUID), nil
	case "exec.fsuser":
		return event.Exec.Process.Credentials.FSUser, nil
	case "exec.gid":
		return int(event.Exec.Process.Credentials.GID), nil
	case "exec.group":
		return event.Exec.Process.Credentials.Group, nil
	case "exec.is_thread":
		return event.Exec.Process.IsThread, nil
	case "exec.pid":
		return int(event.Exec.Process.PIDContext.Pid), nil
	case "exec.ppid":
		return int(event.Exec.Process.PPid), nil
	case "exec.tid":
		return int(event.Exec.Process.PIDContext.Tid), nil
	case "exec.tty_name":
		return event.Exec.Process.TTYName, nil
	case "exec.uid":
		return int(event.Exec.Process.Credentials.UID), nil
	case "exec.user":
		return event.Exec.Process.Credentials.User, nil
	case "exit.args":
		return event.Exit.Process.Args, nil
	case "exit.args_flags":
		return event.Exit.Process.Argv, nil
	case "exit.args_options":
		return event.Exit.Process.Argv, nil
	case "exit.args_truncated":
		return event.Exit.Process.ArgsTruncated, nil
	case "exit.argv":
		return event.Exit.Process.Argv, nil
	case "exit.argv0":
		return event.Exit.Process.Argv0, nil
	case "exit.cap_effective":
		return int(event.Exit.Process.Credentials.CapEffective), nil
	case "exit.cap_permitted":
		return int(event.Exit.Process.Credentials.CapPermitted), nil
	case "exit.cause":
		return int(event.Exit.Cause), nil
	case "exit.code":
		return int(event.Exit.Code), nil
	case "exit.comm":
		return event.Exit.Process.Comm, nil
	case "exit.container.id":
		return event.Exit.Process.ContainerID, nil
	case "exit.cookie":
		return int(event.Exit.Process.Cookie), nil
	case "exit.created_at":
		return int(event.Exit.Process.CreatedAt), nil
	case "exit.egid":
		return int(event.Exit.Process.Credentials.EGID), nil
	case "exit.egroup":
		return event.Exit.Process.Credentials.EGroup, nil
	case "exit.envp":
		return event.Exit.Process.Envp, nil
	case "exit.envs":
		return event.Exit.Process.Envs, nil
	case "exit.envs_truncated":
		return event.Exit.Process.EnvsTruncated, nil
	case "exit.euid":
		return int(event.Exit.Process.Credentials.EUID), nil
	case "exit.euser":
		return event.Exit.Process.Credentials.EUser, nil
	case "exit.file.change_time":
		return int(event.Exit.Process.FileEvent.FileFields.CTime), nil
	case "exit.file.filesystem":
		return event.Exit.Process.FileEvent.Filesystem, nil
	case "exit.file.gid":
		return int(event.Exit.Process.FileEvent.FileFields.GID), nil
	case "exit.file.group":
		return event.Exit.Process.FileEvent.FileFields.Group, nil
	case "exit.file.in_upper_layer":
		return event.Exit.Process.FileEvent.FileFields.InUpperLayer, nil
	case "exit.file.inode":
		return int(event.Exit.Process.FileEvent.FileFields.Inode), nil
	case "exit.file.mode":
		return int(event.Exit.Process.FileEvent.FileFields.Mode), nil
	case "exit.file.modification_time":
		return int(event.Exit.Process.FileEvent.FileFields.MTime), nil
	case "exit.file.mount_id":
		return int(event.Exit.Process.FileEvent.FileFields.MountID), nil
	case "exit.file.name":
		return event.Exit.Process.FileEvent.BasenameStr, nil
	case "exit.file.path":
		return event.Exit.Process.FileEvent.PathnameStr, nil
	case "exit.file.rights":
		return int(event.Exit.Process.FileEvent.FileFields.Mode), nil
	case "exit.file.uid":
		return int(event.Exit.Process.FileEvent.FileFields.UID), nil
	case "exit.file.user":
		return event.Exit.Process.FileEvent.FileFields.User, nil
	case "exit.fsgid":
		return int(event.Exit.Process.Credentials.FSGID), nil
	case "exit.fsgroup":
		return event.Exit.Process.Credentials.FSGroup, nil
	case "exit.fsuid":
		return int(event.Exit.Process.Credentials.FSUID), nil
	case "exit.fsuser":
		return event.Exit.Process.Credentials.FSUser, nil
	case "exit.gid":
		return int(event.Exit.Process.Credentials.GID), nil
	case "exit.group":
		return event.Exit.Process.Credentials.Group, nil
	case "exit.is_thread":
		return event.Exit.Process.IsThread, nil
	case "exit.pid":
		return int(event.Exit.Process.PIDContext.Pid), nil
	case "exit.ppid":
		return int(event.Exit.Process.PPid), nil
	case "exit.tid":
		return int(event.Exit.Process.PIDContext.Tid), nil
	case "exit.tty_name":
		return event.Exit.Process.TTYName, nil
	case "exit.uid":
		return int(event.Exit.Process.Credentials.UID), nil
	case "exit.user":
		return event.Exit.Process.Credentials.User, nil
	case "link.file.change_time":
		return int(event.Link.Source.FileFields.CTime), nil
	case "link.file.destination.change_time":
		return int(event.Link.Target.FileFields.CTime), nil
	case "link.file.destination.filesystem":
		return event.Link.Target.Filesystem, nil
	case "link.file.destination.gid":
		return int(event.Link.Target.FileFields.GID), nil
	case "link.file.destination.group":
		return event.Link.Target.FileFields.Group, nil
	case "link.file.destination.in_upper_layer":
		return event.Link.Target.FileFields.InUpperLayer, nil
	case "link.file.destination.inode":
		return int(event.Link.Target.FileFields.Inode), nil
	case "link.file.destination.mode":
		return int(event.Link.Target.FileFields.Mode), nil
	case "link.file.destination.modification_time":
		return int(event.Link.Target.FileFields.MTime), nil
	case "link.file.destination.mount_id":
		return int(event.Link.Target.FileFields.MountID), nil
	case "link.file.destination.name":
		return event.Link.Target.BasenameStr, nil
	case "link.file.destination.path":
		return event.Link.Target.PathnameStr, nil
	case "link.file.destination.rights":
		return int(event.Link.Target.FileFields.Mode), nil
	case "link.file.destination.uid":
		return int(event.Link.Target.FileFields.UID), nil
	case "link.file.destination.user":
		return event.Link.Target.FileFields.User, nil
	case "link.file.filesystem":
		return event.Link.Source.Filesystem, nil
	case "link.file.gid":
		return int(event.Link.Source.FileFields.GID), nil
	case "link.file.group":
		return event.Link.Source.FileFields.Group, nil
	case "link.file.in_upper_layer":
		return event.Link.Source.FileFields.InUpperLayer, nil
	case "link.file.inode":
		return int(event.Link.Source.FileFields.Inode), nil
	case "link.file.mode":
		return int(event.Link.Source.FileFields.Mode), nil
	case "link.file.modification_time":
		return int(event.Link.Source.FileFields.MTime), nil
	case "link.file.mount_id":
		return int(event.Link.Source.FileFields.MountID), nil
	case "link.file.name":
		return event.Link.Source.BasenameStr, nil
	case "link.file.path":
		return event.Link.Source.PathnameStr, nil
	case "link.file.rights":
		return int(event.Link.Source.FileFields.Mode), nil
	case "link.file.uid":
		return int(event.Link.Source.FileFields.UID), nil
	case "link.file.user":
		return event.Link.Source.FileFields.User, nil
	case "link.retval":
		return int(event.Link.SyscallEvent.Retval), nil
	case "load_module.file.change_time":
		return int(event.LoadModule.File.FileFields.CTime), nil
	case "load_module.file.filesystem":
		return event.LoadModule.File.Filesystem, nil
	case "load_module.file.gid":
		return int(event.LoadModule.File.FileFields.GID), nil
	case "load_module.file.group":
		return event.LoadModule.File.FileFields.Group, nil
	case "load_module.file.in_upper_layer":
		return event.LoadModule.File.FileFields.InUpperLayer, nil
	case "load_module.file.inode":
		return int(event.LoadModule.File.FileFields.Inode), nil
	case "load_module.file.mode":
		return int(event.LoadModule.File.FileFields.Mode), nil
	case "load_module.file.modification_time":
		return int(event.LoadModule.File.FileFields.MTime), nil
	case "load_module.file.mount_id":
		return int(event.LoadModule.File.FileFields.MountID), nil
	case "load_module.file.name":
		return event.LoadModule.File.BasenameStr, nil
	case "load_module.file.path":
		return event.LoadModule.File.PathnameStr, nil
	case "load_module.file.rights":
		return int(event.LoadModule.File.FileFields.Mode), nil
	case "load_module.file.uid":
		return int(event.LoadModule.File.FileFields.UID), nil
	case "load_module.file.user":
		return event.LoadModule.File.FileFields.User, nil
	case "load_module.loaded_from_memory":
		return event.LoadModule.LoadedFromMemory, nil
	case "load_module.name":
		return event.LoadModule.Name, nil
	case "load_module.retval":
		return int(event.LoadModule.SyscallEvent.Retval), nil
	case "mkdir.file.change_time":
		return int(event.Mkdir.File.FileFields.CTime), nil
	case "mkdir.file.destination.mode":
		return int(event.Mkdir.Mode), nil
	case "mkdir.file.destination.rights":
		return int(event.Mkdir.Mode), nil
	case "mkdir.file.filesystem":
		return event.Mkdir.File.Filesystem, nil
	case "mkdir.file.gid":
		return int(event.Mkdir.File.FileFields.GID), nil
	case "mkdir.file.group":
		return event.Mkdir.File.FileFields.Group, nil
	case "mkdir.file.in_upper_layer":
		return event.Mkdir.File.FileFields.InUpperLayer, nil
	case "mkdir.file.inode":
		return int(event.Mkdir.File.FileFields.Inode), nil
	case "mkdir.file.mode":
		return int(event.Mkdir.File.FileFields.Mode), nil
	case "mkdir.file.modification_time":
		return int(event.Mkdir.File.FileFields.MTime), nil
	case "mkdir.file.mount_id":
		return int(event.Mkdir.File.FileFields.MountID), nil
	case "mkdir.file.name":
		return event.Mkdir.File.BasenameStr, nil
	case "mkdir.file.path":
		return event.Mkdir.File.PathnameStr, nil
	case "mkdir.file.rights":
		return int(event.Mkdir.File.FileFields.Mode), nil
	case "mkdir.file.uid":
		return int(event.Mkdir.File.FileFields.UID), nil
	case "mkdir.file.user":
		return event.Mkdir.File.FileFields.User, nil
	case "mkdir.retval":
		return int(event.Mkdir.SyscallEvent.Retval), nil
	case "mmap.file.change_time":
		return int(event.MMap.File.FileFields.CTime), nil
	case "mmap.file.filesystem":
		return event.MMap.File.Filesystem, nil
	case "mmap.file.gid":
		return int(event.MMap.File.FileFields.GID), nil
	case "mmap.file.group":
		return event.MMap.File.FileFields.Group, nil
	case "mmap.file.in_upper_layer":
		return event.MMap.File.FileFields.InUpperLayer, nil
	case "mmap.file.inode":
		return int(event.MMap.File.FileFields.Inode), nil
	case "mmap.file.mode":
		return int(event.MMap.File.FileFields.Mode), nil
	case "mmap.file.modification_time":
		return int(event.MMap.File.FileFields.MTime), nil
	case "mmap.file.mount_id":
		return int(event.MMap.File.FileFields.MountID), nil
	case "mmap.file.name":
		return event.MMap.File.BasenameStr, nil
	case "mmap.file.path":
		return event.MMap.File.PathnameStr, nil
	case "mmap.file.rights":
		return int(event.MMap.File.FileFields.Mode), nil
	case "mmap.file.uid":
		return int(event.MMap.File.FileFields.UID), nil
	case "mmap.file.user":
		return event.MMap.File.FileFields.User, nil
	case "mmap.flags":
		return event.MMap.Flags, nil
	case "mmap.protection":
		return event.MMap.Protection, nil
	case "mmap.retval":
		return int(event.MMap.SyscallEvent.Retval), nil
	case "mprotect.req_protection":
		return event.MProtect.ReqProtection, nil
	case "mprotect.retval":
		return int(event.MProtect.SyscallEvent.Retval), nil
	case "mprotect.vm_protection":
		return event.MProtect.VMProtection, nil
	case "network.destination.ip":
		return event.NetworkContext.Destination.IPNet, nil
	case "network.destination.port":
		return int(event.NetworkContext.Destination.Port), nil
	case "network.device.ifindex":
		return int(event.NetworkContext.Device.IfIndex), nil
	case "network.device.ifname":
		return event.NetworkContext.Device.IfName, nil
	case "network.l3_protocol":
		return int(event.NetworkContext.L3Protocol), nil
	case "network.l4_protocol":
		return int(event.NetworkContext.L4Protocol), nil
	case "network.size":
		return int(event.NetworkContext.Size), nil
	case "network.source.ip":
		return event.NetworkContext.Source.IPNet, nil
	case "network.source.port":
		return int(event.NetworkContext.Source.Port), nil
	case "open.file.change_time":
		return int(event.Open.File.FileFields.CTime), nil
	case "open.file.destination.mode":
		return int(event.Open.Mode), nil
	case "open.file.filesystem":
		return event.Open.File.Filesystem, nil
	case "open.file.gid":
		return int(event.Open.File.FileFields.GID), nil
	case "open.file.group":
		return event.Open.File.FileFields.Group, nil
	case "open.file.in_upper_layer":
		return event.Open.File.FileFields.InUpperLayer, nil
	case "open.file.inode":
		return int(event.Open.File.FileFields.Inode), nil
	case "open.file.mode":
		return int(event.Open.File.FileFields.Mode), nil
	case "open.file.modification_time":
		return int(event.Open.File.FileFields.MTime), nil
	case "open.file.mount_id":
		return int(event.Open.File.FileFields.MountID), nil
	case "open.file.name":
		return event.Open.File.BasenameStr, nil
	case "open.file.path":
		return event.Open.File.PathnameStr, nil
	case "open.file.rights":
		return int(event.Open.File.FileFields.Mode), nil
	case "open.file.uid":
		return int(event.Open.File.FileFields.UID), nil
	case "open.file.user":
		return event.Open.File.FileFields.User, nil
	case "open.flags":
		return int(event.Open.Flags), nil
	case "open.retval":
		return int(event.Open.SyscallEvent.Retval), nil
	case "process.ancestors.args":
		var values []string
		iterator := &ProcessAncestorsIterator{}
		ptr := iterator.Front(ctx)
		for ptr != nil {
			element := (*ProcessCacheEntry)(ptr)
			result := element.ProcessContext.Process.Args
			values = append(values, result)
			ptr = iterator.Next()
		}
		return values, nil
	case "process.ancestors.args_flags":
		var values []string
		iterator := &ProcessAncestorsIterator{}
		ptr := iterator.Front(ctx)
		for ptr != nil {
			element := (*ProcessCacheEntry)(ptr)
			result := element.ProcessContext.Process.Argv
			values = append(values, result...)
			ptr = iterator.Next()
		}
		return values, nil
	case "process.ancestors.args_options":
		var values []string
		iterator := &ProcessAncestorsIterator{}
		ptr := iterator.Front(ctx)
		for ptr != nil {
			element := (*ProcessCacheEntry)(ptr)
			result := element.ProcessContext.Process.Argv
			values = append(values, result...)
			ptr = iterator.Next()
		}
		return values, nil
	case "process.ancestors.args_truncated":
		var values []bool
		iterator := &ProcessAncestorsIterator{}
		ptr := iterator.Front(ctx)
		for ptr != nil {
			element := (*ProcessCacheEntry)(ptr)
			result := element.ProcessContext.Process.ArgsTruncated
			values = append(values, result)
			ptr = iterator.Next()
		}
		return values, nil
	case "process.ancestors.argv":
		var values []string
		iterator := &ProcessAncestorsIterator{}
		ptr := iterator.Front(ctx)
		for ptr != nil {
			element := (*ProcessCacheEntry)(ptr)
			result := element.ProcessContext.Process.Argv
			values = append(values, result...)
			ptr = iterator.Next()
		}
		return values, nil
	case "process.ancestors.argv0":
		var values []string
		iterator := &ProcessAncestorsIterator{}
		ptr := iterator.Front(ctx)
		for ptr != nil {
			element := (*ProcessCacheEntry)(ptr)
			result := element.ProcessContext.Process.Argv0
			values = append(values, result)
			ptr = iterator.Next()
		}
		return values, nil
	case "process.ancestors.cap_effective":
		var values []int
		iterator := &ProcessAncestorsIterator{}
		ptr := iterator.Front(ctx)
		for ptr != nil {
			element := (*ProcessCacheEntry)(ptr)
			result := int(element.ProcessContext.Process.Credentials.CapEffective)
			values = append(values, result)
			ptr = iterator.Next()
		}
		return values, nil
	case "process.ancestors.cap_permitted":
		var values []int
		iterator := &ProcessAncestorsIterator{}
		ptr := iterator.Front(ctx)
		for ptr != nil {
			element := (*ProcessCacheEntry)(ptr)
			result := int(element.ProcessContext.Process.Credentials.CapPermitted)
			values = append(values, result)
			ptr = iterator.Next()
		}
		return values, nil
	case "process.ancestors.comm":
		var values []string
		iterator := &ProcessAncestorsIterator{}
		ptr := iterator.Front(ctx)
		for ptr != nil {
			element := (*ProcessCacheEntry)(ptr)
			result := element.ProcessContext.Process.Comm
			values = append(values, result)
			ptr = iterator.Next()
		}
		return values, nil
	case "process.ancestors.container.id":
		var values []string
		iterator := &ProcessAncestorsIterator{}
		ptr := iterator.Front(ctx)
		for ptr != nil {
			element := (*ProcessCacheEntry)(ptr)
			result := element.ProcessContext.Process.ContainerID
			values = append(values, result)
			ptr = iterator.Next()
		}
		return values, nil
	case "process.ancestors.cookie":
		var values []int
		iterator := &ProcessAncestorsIterator{}
		ptr := iterator.Front(ctx)
		for ptr != nil {
			element := (*ProcessCacheEntry)(ptr)
			result := int(element.ProcessContext.Process.Cookie)
			values = append(values, result)
			ptr = iterator.Next()
		}
		return values, nil
	case "process.ancestors.created_at":
		var values []int
		iterator := &ProcessAncestorsIterator{}
		ptr := iterator.Front(ctx)
		for ptr != nil {
			element := (*ProcessCacheEntry)(ptr)
			result := int(element.ProcessContext.Process.CreatedAt)
			values = append(values, result)
			ptr = iterator.Next()
		}
		return values, nil
	case "process.ancestors.egid":
		var values []int
		iterator := &ProcessAncestorsIterator{}
		ptr := iterator.Front(ctx)
		for ptr != nil {
			element := (*ProcessCacheEntry)(ptr)
			result := int(element.ProcessContext.Process.Credentials.EGID)
			values = append(values, result)
			ptr = iterator.Next()
		}
		return values, nil
	case "process.ancestors.egroup":
		var values []string
		iterator := &ProcessAncestorsIterator{}
		ptr := iterator.Front(ctx)
		for ptr != nil {
			element := (*ProcessCacheEntry)(ptr)
			result := element.ProcessContext.Process.Credentials.EGroup
			values = append(values, result)
			ptr = iterator.Next()
		}
		return values, nil
	case "process.ancestors.envp":
		var values []string
		iterator := &ProcessAncestorsIterator{}
		ptr := iterator.Front(ctx)
		for ptr != nil {
			element := (*ProcessCacheEntry)(ptr)
			result := element.ProcessContext.Process.Envp
			values = append(values, result...)
			ptr = iterator.Next()
		}
		return values, nil
	case "process.ancestors.envs":
		var values []string
		iterator := &ProcessAncestorsIterator{}
		ptr := iterator.Front(ctx)
		for ptr != nil {
			element := (*ProcessCacheEntry)(ptr)
			result := element.ProcessContext.Process.Envs
			values = append(values, result...)
			ptr = iterator.Next()
		}
		return values, nil
	case "process.ancestors.envs_truncated":
		var values []bool
		iterator := &ProcessAncestorsIterator{}
		ptr := iterator.Front(ctx)
		for ptr != nil {
			element := (*ProcessCacheEntry)(ptr)
			result := element.ProcessContext.Process.EnvsTruncated
			values = append(values, result)
			ptr = iterator.Next()
		}
		return values, nil
	case "process.ancestors.euid":
		var values []int
		iterator := &ProcessAncestorsIterator{}
		ptr := iterator.Front(ctx)
		for ptr != nil {
			element := (*ProcessCacheEntry)(ptr)
			result := int(element.ProcessContext.Process.Credentials.EUID)
			values = append(values, result)
			ptr = iterator.Next()
		}
		return values, nil
	case "process.ancestors.euser":
		var values []string
		iterator := &ProcessAncestorsIterator{}
		ptr := iterator.Front(ctx)
		for ptr != nil {
			element := (*ProcessCacheEntry)(ptr)
			result := element.ProcessContext.Process.Credentials.EUser
			values = append(values, result)
			ptr = iterator.Next()
		}
		return values, nil
	case "process.ancestors.file.change_time":
		var values []int
		iterator := &ProcessAncestorsIterator{}
		ptr := iterator.Front(ctx)
		for ptr != nil {
			element := (*ProcessCacheEntry)(ptr)
			result := int(element.ProcessContext.Process.FileEvent.FileFields.CTime)
			values = append(values, result)
			ptr = iterator.Next()
		}
		return values, nil
	case "process.ancestors.file.filesystem":
		var values []string
		iterator := &ProcessAncestorsIterator{}
		ptr := iterator.Front(ctx)
		for ptr != nil {
			element := (*ProcessCacheEntry)(ptr)
			result := element.ProcessContext.Process.FileEvent.Filesystem
			values = append(values, result)
			ptr = iterator.Next()
		}
		return values, nil
	case "process.ancestors.file.gid":
		var values []int
		iterator := &ProcessAncestorsIterator{}
		ptr := iterator.Front(ctx)
		for ptr != nil {
			element := (*ProcessCacheEntry)(ptr)
			result := int(element.ProcessContext.Process.FileEvent.FileFields.GID)
			values = append(values, result)
			ptr = iterator.Next()
		}
		return values, nil
	case "process.ancestors.file.group":
		var values []string
		iterator := &ProcessAncestorsIterator{}
		ptr := iterator.Front(ctx)
		for ptr != nil {
			element := (*ProcessCacheEntry)(ptr)
			result := element.ProcessContext.Process.FileEvent.FileFields.Group
			values = append(values, result)
			ptr = iterator.Next()
		}
		return values, nil
	case "process.ancestors.file.in_upper_layer":
		var values []bool
		iterator := &ProcessAncestorsIterator{}
		ptr := iterator.Front(ctx)
		for ptr != nil {
			element := (*ProcessCacheEntry)(ptr)
			result := element.ProcessContext.Process.FileEvent.FileFields.InUpperLayer
			values = append(values, result)
			ptr = iterator.Next()
		}
		return values, nil
	case "process.ancestors.file.inode":
		var values []int
		iterator := &ProcessAncestorsIterator{}
		ptr := iterator.Front(ctx)
		for ptr != nil {
			element := (*ProcessCacheEntry)(ptr)
			result := int(element.ProcessContext.Process.FileEvent.FileFields.Inode)
			values = append(values, result)
			ptr = iterator.Next()
		}
		return values, nil
	case "process.ancestors.file.mode":
		var values []int
		iterator := &ProcessAncestorsIterator{}
		ptr := iterator.Front(ctx)
		for ptr != nil {
			element := (*ProcessCacheEntry)(ptr)
			result := int(element.ProcessContext.Process.FileEvent.FileFields.Mode)
			values = append(values, result)
			ptr = iterator.Next()
		}
		return values, nil
	case "process.ancestors.file.modification_time":
		var values []int
		iterator := &ProcessAncestorsIterator{}
		ptr := iterator.Front(ctx)
		for ptr != nil {
			element := (*ProcessCacheEntry)(ptr)
			result := int(element.ProcessContext.Process.FileEvent.FileFields.MTime)
			values = append(values, result)
			ptr = iterator.Next()
		}
		return values, nil
	case "process.ancestors.file.mount_id":
		var values []int
		iterator := &ProcessAncestorsIterator{}
		ptr := iterator.Front(ctx)
		for ptr != nil {
			element := (*ProcessCacheEntry)(ptr)
			result := int(element.ProcessContext.Process.FileEvent.FileFields.MountID)
			values = append(values, result)
			ptr = iterator.Next()
		}
		return values, nil
	case "process.ancestors.file.name":
		var values []string
		iterator := &ProcessAncestorsIterator{}
		ptr := iterator.Front(ctx)
		for ptr != nil {
			element := (*ProcessCacheEntry)(ptr)
			result := element.ProcessContext.Process.FileEvent.BasenameStr
			values = append(values, result)
			ptr = iterator.Next()
		}
		return values, nil
	case "process.ancestors.file.path":
		var values []string
		iterator := &ProcessAncestorsIterator{}
		ptr := iterator.Front(ctx)
		for ptr != nil {
			element := (*ProcessCacheEntry)(ptr)
			result := element.ProcessContext.Process.FileEvent.PathnameStr
			values = append(values, result)
			ptr = iterator.Next()
		}
		return values, nil
	case "process.ancestors.file.rights":
		var values []int
		iterator := &ProcessAncestorsIterator{}
		ptr := iterator.Front(ctx)
		for ptr != nil {
			element := (*ProcessCacheEntry)(ptr)
			result := int(element.ProcessContext.Process.FileEvent.FileFields.Mode)
			values = append(values, result)
			ptr = iterator.Next()
		}
		return values, nil
	case "process.ancestors.file.uid":
		var values []int
		iterator := &ProcessAncestorsIterator{}
		ptr := iterator.Front(ctx)
		for ptr != nil {
			element := (*ProcessCacheEntry)(ptr)
			result := int(element.ProcessContext.Process.FileEvent.FileFields.UID)
			values = append(values, result)
			ptr = iterator.Next()
		}
		return values, nil
	case "process.ancestors.file.user":
		var values []string
		iterator := &ProcessAncestorsIterator{}
		ptr := iterator.Front(ctx)
		for ptr != nil {
			element := (*ProcessCacheEntry)(ptr)
			result := element.ProcessContext.Process.FileEvent.FileFields.User
			values = append(values, result)
			ptr = iterator.Next()
		}
		return values, nil
	case "process.ancestors.fsgid":
		var values []int
		iterator := &ProcessAncestorsIterator{}
		ptr := iterator.Front(ctx)
		for ptr != nil {
			element := (*ProcessCacheEntry)(ptr)
			result := int(element.ProcessContext.Process.Credentials.FSGID)
			values = append(values, result)
			ptr = iterator.Next()
		}
		return values, nil
	case "process.ancestors.fsgroup":
		var values []string
		iterator := &ProcessAncestorsIterator{}
		ptr := iterator.Front(ctx)
		for ptr != nil {
			element := (*ProcessCacheEntry)(ptr)
			result := element.ProcessContext.Process.Credentials.FSGroup
			values = append(values, result)
			ptr = iterator.Next()
		}
		return values, nil
	case "process.ancestors.fsuid":
		var values []int
		iterator := &ProcessAncestorsIterator{}
		ptr := iterator.Front(ctx)
		for ptr != nil {
			element := (*ProcessCacheEntry)(ptr)
			result := int(element.ProcessContext.Process.Credentials.FSUID)
			values = append(values, result)
			ptr = iterator.Next()
		}
		return values, nil
	case "process.ancestors.fsuser":
		var values []string
		iterator := &ProcessAncestorsIterator{}
		ptr := iterator.Front(ctx)
		for ptr != nil {
			element := (*ProcessCacheEntry)(ptr)
			result := element.ProcessContext.Process.Credentials.FSUser
			values = append(values, result)
			ptr = iterator.Next()
		}
		return values, nil
	case "process.ancestors.gid":
		var values []int
		iterator := &ProcessAncestorsIterator{}
		ptr := iterator.Front(ctx)
		for ptr != nil {
			element := (*ProcessCacheEntry)(ptr)
			result := int(element.ProcessContext.Process.Credentials.GID)
			values = append(values, result)
			ptr = iterator.Next()
		}
		return values, nil
	case "process.ancestors.group":
		var values []string
		iterator := &ProcessAncestorsIterator{}
		ptr := iterator.Front(ctx)
		for ptr != nil {
			element := (*ProcessCacheEntry)(ptr)
			result := element.ProcessContext.Process.Credentials.Group
			values = append(values, result)
			ptr = iterator.Next()
		}
		return values, nil
	case "process.ancestors.is_thread":
		var values []bool
		iterator := &ProcessAncestorsIterator{}
		ptr := iterator.Front(ctx)
		for ptr != nil {
			element := (*ProcessCacheEntry)(ptr)
			result := element.ProcessContext.Process.IsThread
			values = append(values, result)
			ptr = iterator.Next()
		}
		return values, nil
	case "process.ancestors.pid":
		var values []int
		iterator := &ProcessAncestorsIterator{}
		ptr := iterator.Front(ctx)
		for ptr != nil {
			element := (*ProcessCacheEntry)(ptr)
			result := int(element.ProcessContext.Process.PIDContext.Pid)
			values = append(values, result)
			ptr = iterator.Next()
		}
		return values, nil
	case "process.ancestors.ppid":
		var values []int
		iterator := &ProcessAncestorsIterator{}
		ptr := iterator.Front(ctx)
		for ptr != nil {
			element := (*ProcessCacheEntry)(ptr)
			result := int(element.ProcessContext.Process.PPid)
			values = append(values, result)
			ptr = iterator.Next()
		}
		return values, nil
	case "process.ancestors.tid":
		var values []int
		iterator := &ProcessAncestorsIterator{}
		ptr := iterator.Front(ctx)
		for ptr != nil {
			element := (*ProcessCacheEntry)(ptr)
			result := int(element.ProcessContext.Process.PIDContext.Tid)
			values = append(values, result)
			ptr = iterator.Next()
		}
		return values, nil
	case "process.ancestors.tty_name":
		var values []string
		iterator := &ProcessAncestorsIterator{}
		ptr := iterator.Front(ctx)
		for ptr != nil {
			element := (*ProcessCacheEntry)(ptr)
			result := element.ProcessContext.Process.TTYName
			values = append(values, result)
			ptr = iterator.Next()
		}
		return values, nil
	case "process.ancestors.uid":
		var values []int
		iterator := &ProcessAncestorsIterator{}
		ptr := iterator.Front(ctx)
		for ptr != nil {
			element := (*ProcessCacheEntry)(ptr)
			result := int(element.ProcessContext.Process.Credentials.UID)
			values = append(values, result)
			ptr = iterator.Next()
		}
		return values, nil
	case "process.ancestors.user":
		var values []string
		iterator := &ProcessAncestorsIterator{}
		ptr := iterator.Front(ctx)
		for ptr != nil {
			element := (*ProcessCacheEntry)(ptr)
			result := element.ProcessContext.Process.Credentials.User
			values = append(values, result)
			ptr = iterator.Next()
		}
		return values, nil
	case "process.args":
		return event.ProcessContext.Process.Args, nil
	case "process.args_flags":
		return event.ProcessContext.Process.Argv, nil
	case "process.args_options":
		return event.ProcessContext.Process.Argv, nil
	case "process.args_truncated":
		return event.ProcessContext.Process.ArgsTruncated, nil
	case "process.argv":
		return event.ProcessContext.Process.Argv, nil
	case "process.argv0":
		return event.ProcessContext.Process.Argv0, nil
	case "process.cap_effective":
		return int(event.ProcessContext.Process.Credentials.CapEffective), nil
	case "process.cap_permitted":
		return int(event.ProcessContext.Process.Credentials.CapPermitted), nil
	case "process.comm":
		return event.ProcessContext.Process.Comm, nil
	case "process.container.id":
		return event.ProcessContext.Process.ContainerID, nil
	case "process.cookie":
		return int(event.ProcessContext.Process.Cookie), nil
	case "process.created_at":
		return int(event.ProcessContext.Process.CreatedAt), nil
	case "process.egid":
		return int(event.ProcessContext.Process.Credentials.EGID), nil
	case "process.egroup":
		return event.ProcessContext.Process.Credentials.EGroup, nil
	case "process.envp":
		return event.ProcessContext.Process.Envp, nil
	case "process.envs":
		return event.ProcessContext.Process.Envs, nil
	case "process.envs_truncated":
		return event.ProcessContext.Process.EnvsTruncated, nil
	case "process.euid":
		return int(event.ProcessContext.Process.Credentials.EUID), nil
	case "process.euser":
		return event.ProcessContext.Process.Credentials.EUser, nil
	case "process.file.change_time":
		return int(event.ProcessContext.Process.FileEvent.FileFields.CTime), nil
	case "process.file.filesystem":
		return event.ProcessContext.Process.FileEvent.Filesystem, nil
	case "process.file.gid":
		return int(event.ProcessContext.Process.FileEvent.FileFields.GID), nil
	case "process.file.group":
		return event.ProcessContext.Process.FileEvent.FileFields.Group, nil
	case "process.file.in_upper_layer":
		return event.ProcessContext.Process.FileEvent.FileFields.InUpperLayer, nil
	case "process.file.inode":
		return int(event.ProcessContext.Process.FileEvent.FileFields.Inode), nil
	case "process.file.mode":
		return int(event.ProcessContext.Process.FileEvent.FileFields.Mode), nil
	case "process.file.modification_time":
		return int(event.ProcessContext.Process.FileEvent.FileFields.MTime), nil
	case "process.file.mount_id":
		return int(event.ProcessContext.Process.FileEvent.FileFields.MountID), nil
	case "process.file.name":
		return event.ProcessContext.Process.FileEvent.BasenameStr, nil
	case "process.file.path":
		return event.ProcessContext.Process.FileEvent.PathnameStr, nil
	case "process.file.rights":
		return int(event.ProcessContext.Process.FileEvent.FileFields.Mode), nil
	case "process.file.uid":
		return int(event.ProcessContext.Process.FileEvent.FileFields.UID), nil
	case "process.file.user":
		return event.ProcessContext.Process.FileEvent.FileFields.User, nil
	case "process.fsgid":
		return int(event.ProcessContext.Process.Credentials.FSGID), nil
	case "process.fsgroup":
		return event.ProcessContext.Process.Credentials.FSGroup, nil
	case "process.fsuid":
		return int(event.ProcessContext.Process.Credentials.FSUID), nil
	case "process.fsuser":
		return event.ProcessContext.Process.Credentials.FSUser, nil
	case "process.gid":
		return int(event.ProcessContext.Process.Credentials.GID), nil
	case "process.group":
		return event.ProcessContext.Process.Credentials.Group, nil
	case "process.is_thread":
		return event.ProcessContext.Process.IsThread, nil
	case "process.pid":
		return int(event.ProcessContext.Process.PIDContext.Pid), nil
	case "process.ppid":
		return int(event.ProcessContext.Process.PPid), nil
	case "process.tid":
		return int(event.ProcessContext.Process.PIDContext.Tid), nil
	case "process.tty_name":
		return event.ProcessContext.Process.TTYName, nil
	case "process.uid":
		return int(event.ProcessContext.Process.Credentials.UID), nil
	case "process.user":
		return event.ProcessContext.Process.Credentials.User, nil
	case "ptrace.request":
		return int(event.PTrace.Request), nil
	case "ptrace.retval":
		return int(event.PTrace.SyscallEvent.Retval), nil
	case "ptrace.tracee.ancestors.args":
		var values []string
		iterator := &ProcessAncestorsIterator{}
		ptr := iterator.Front(ctx)
		for ptr != nil {
			element := (*ProcessCacheEntry)(ptr)
			result := element.ProcessContext.Process.Args
			values = append(values, result)
			ptr = iterator.Next()
		}
		return values, nil
	case "ptrace.tracee.ancestors.args_flags":
		var values []string
		iterator := &ProcessAncestorsIterator{}
		ptr := iterator.Front(ctx)
		for ptr != nil {
			element := (*ProcessCacheEntry)(ptr)
			result := element.ProcessContext.Process.Argv
			values = append(values, result...)
			ptr = iterator.Next()
		}
		return values, nil
	case "ptrace.tracee.ancestors.args_options":
		var values []string
		iterator := &ProcessAncestorsIterator{}
		ptr := iterator.Front(ctx)
		for ptr != nil {
			element := (*ProcessCacheEntry)(ptr)
			result := element.ProcessContext.Process.Argv
			values = append(values, result...)
			ptr = iterator.Next()
		}
		return values, nil
	case "ptrace.tracee.ancestors.args_truncated":
		var values []bool
		iterator := &ProcessAncestorsIterator{}
		ptr := iterator.Front(ctx)
		for ptr != nil {
			element := (*ProcessCacheEntry)(ptr)
			result := element.ProcessContext.Process.ArgsTruncated
			values = append(values, result)
			ptr = iterator.Next()
		}
		return values, nil
	case "ptrace.tracee.ancestors.argv":
		var values []string
		iterator := &ProcessAncestorsIterator{}
		ptr := iterator.Front(ctx)
		for ptr != nil {
			element := (*ProcessCacheEntry)(ptr)
			result := element.ProcessContext.Process.Argv
			values = append(values, result...)
			ptr = iterator.Next()
		}
		return values, nil
	case "ptrace.tracee.ancestors.argv0":
		var values []string
		iterator := &ProcessAncestorsIterator{}
		ptr := iterator.Front(ctx)
		for ptr != nil {
			element := (*ProcessCacheEntry)(ptr)
			result := element.ProcessContext.Process.Argv0
			values = append(values, result)
			ptr = iterator.Next()
		}
		return values, nil
	case "ptrace.tracee.ancestors.cap_effective":
		var values []int
		iterator := &ProcessAncestorsIterator{}
		ptr := iterator.Front(ctx)
		for ptr != nil {
			element := (*ProcessCacheEntry)(ptr)
			result := int(element.ProcessContext.Process.Credentials.CapEffective)
			values = append(values, result)
			ptr = iterator.Next()
		}
		return values, nil
	case "ptrace.tracee.ancestors.cap_permitted":
		var values []int
		iterator := &ProcessAncestorsIterator{}
		ptr := iterator.Front(ctx)
		for ptr != nil {
			element := (*ProcessCacheEntry)(ptr)
			result := int(element.ProcessContext.Process.Credentials.CapPermitted)
			values = append(values, result)
			ptr = iterator.Next()
		}
		return values, nil
	case "ptrace.tracee.ancestors.comm":
		var values []string
		iterator := &ProcessAncestorsIterator{}
		ptr := iterator.Front(ctx)
		for ptr != nil {
			element := (*ProcessCacheEntry)(ptr)
			result := element.ProcessContext.Process.Comm
			values = append(values, result)
			ptr = iterator.Next()
		}
		return values, nil
	case "ptrace.tracee.ancestors.container.id":
		var values []string
		iterator := &ProcessAncestorsIterator{}
		ptr := iterator.Front(ctx)
		for ptr != nil {
			element := (*ProcessCacheEntry)(ptr)
			result := element.ProcessContext.Process.ContainerID
			values = append(values, result)
			ptr = iterator.Next()
		}
		return values, nil
	case "ptrace.tracee.ancestors.cookie":
		var values []int
		iterator := &ProcessAncestorsIterator{}
		ptr := iterator.Front(ctx)
		for ptr != nil {
			element := (*ProcessCacheEntry)(ptr)
			result := int(element.ProcessContext.Process.Cookie)
			values = append(values, result)
			ptr = iterator.Next()
		}
		return values, nil
	case "ptrace.tracee.ancestors.created_at":
		var values []int
		iterator := &ProcessAncestorsIterator{}
		ptr := iterator.Front(ctx)
		for ptr != nil {
			element := (*ProcessCacheEntry)(ptr)
			result := int(element.ProcessContext.Process.CreatedAt)
			values = append(values, result)
			ptr = iterator.Next()
		}
		return values, nil
	case "ptrace.tracee.ancestors.egid":
		var values []int
		iterator := &ProcessAncestorsIterator{}
		ptr := iterator.Front(ctx)
		for ptr != nil {
			element := (*ProcessCacheEntry)(ptr)
			result := int(element.ProcessContext.Process.Credentials.EGID)
			values = append(values, result)
			ptr = iterator.Next()
		}
		return values, nil
	case "ptrace.tracee.ancestors.egroup":
		var values []string
		iterator := &ProcessAncestorsIterator{}
		ptr := iterator.Front(ctx)
		for ptr != nil {
			element := (*ProcessCacheEntry)(ptr)
			result := element.ProcessContext.Process.Credentials.EGroup
			values = append(values, result)
			ptr = iterator.Next()
		}
		return values, nil
	case "ptrace.tracee.ancestors.envp":
		var values []string
		iterator := &ProcessAncestorsIterator{}
		ptr := iterator.Front(ctx)
		for ptr != nil {
			element := (*ProcessCacheEntry)(ptr)
			result := element.ProcessContext.Process.Envp
			values = append(values, result...)
			ptr = iterator.Next()
		}
		return values, nil
	case "ptrace.tracee.ancestors.envs":
		var values []string
		iterator := &ProcessAncestorsIterator{}
		ptr := iterator.Front(ctx)
		for ptr != nil {
			element := (*ProcessCacheEntry)(ptr)
			result := element.ProcessContext.Process.Envs
			values = append(values, result...)
			ptr = iterator.Next()
		}
		return values, nil
	case "ptrace.tracee.ancestors.envs_truncated":
		var values []bool
		iterator := &ProcessAncestorsIterator{}
		ptr := iterator.Front(ctx)
		for ptr != nil {
			element := (*ProcessCacheEntry)(ptr)
			result := element.ProcessContext.Process.EnvsTruncated
			values = append(values, result)
			ptr = iterator.Next()
		}
		return values, nil
	case "ptrace.tracee.ancestors.euid":
		var values []int
		iterator := &ProcessAncestorsIterator{}
		ptr := iterator.Front(ctx)
		for ptr != nil {
			element := (*ProcessCacheEntry)(ptr)
			result := int(element.ProcessContext.Process.Credentials.EUID)
			values = append(values, result)
			ptr = iterator.Next()
		}
		return values, nil
	case "ptrace.tracee.ancestors.euser":
		var values []string
		iterator := &ProcessAncestorsIterator{}
		ptr := iterator.Front(ctx)
		for ptr != nil {
			element := (*ProcessCacheEntry)(ptr)
			result := element.ProcessContext.Process.Credentials.EUser
			values = append(values, result)
			ptr = iterator.Next()
		}
		return values, nil
	case "ptrace.tracee.ancestors.file.change_time":
		var values []int
		iterator := &ProcessAncestorsIterator{}
		ptr := iterator.Front(ctx)
		for ptr != nil {
			element := (*ProcessCacheEntry)(ptr)
			result := int(element.ProcessContext.Process.FileEvent.FileFields.CTime)
			values = append(values, result)
			ptr = iterator.Next()
		}
		return values, nil
	case "ptrace.tracee.ancestors.file.filesystem":
		var values []string
		iterator := &ProcessAncestorsIterator{}
		ptr := iterator.Front(ctx)
		for ptr != nil {
			element := (*ProcessCacheEntry)(ptr)
			result := element.ProcessContext.Process.FileEvent.Filesystem
			values = append(values, result)
			ptr = iterator.Next()
		}
		return values, nil
	case "ptrace.tracee.ancestors.file.gid":
		var values []int
		iterator := &ProcessAncestorsIterator{}
		ptr := iterator.Front(ctx)
		for ptr != nil {
			element := (*ProcessCacheEntry)(ptr)
			result := int(element.ProcessContext.Process.FileEvent.FileFields.GID)
			values = append(values, result)
			ptr = iterator.Next()
		}
		return values, nil
	case "ptrace.tracee.ancestors.file.group":
		var values []string
		iterator := &ProcessAncestorsIterator{}
		ptr := iterator.Front(ctx)
		for ptr != nil {
			element := (*ProcessCacheEntry)(ptr)
			result := element.ProcessContext.Process.FileEvent.FileFields.Group
			values = append(values, result)
			ptr = iterator.Next()
		}
		return values, nil
	case "ptrace.tracee.ancestors.file.in_upper_layer":
		var values []bool
		iterator := &ProcessAncestorsIterator{}
		ptr := iterator.Front(ctx)
		for ptr != nil {
			element := (*ProcessCacheEntry)(ptr)
			result := element.ProcessContext.Process.FileEvent.FileFields.InUpperLayer
			values = append(values, result)
			ptr = iterator.Next()
		}
		return values, nil
	case "ptrace.tracee.ancestors.file.inode":
		var values []int
		iterator := &ProcessAncestorsIterator{}
		ptr := iterator.Front(ctx)
		for ptr != nil {
			element := (*ProcessCacheEntry)(ptr)
			result := int(element.ProcessContext.Process.FileEvent.FileFields.Inode)
			values = append(values, result)
			ptr = iterator.Next()
		}
		return values, nil
	case "ptrace.tracee.ancestors.file.mode":
		var values []int
		iterator := &ProcessAncestorsIterator{}
		ptr := iterator.Front(ctx)
		for ptr != nil {
			element := (*ProcessCacheEntry)(ptr)
			result := int(element.ProcessContext.Process.FileEvent.FileFields.Mode)
			values = append(values, result)
			ptr = iterator.Next()
		}
		return values, nil
	case "ptrace.tracee.ancestors.file.modification_time":
		var values []int
		iterator := &ProcessAncestorsIterator{}
		ptr := iterator.Front(ctx)
		for ptr != nil {
			element := (*ProcessCacheEntry)(ptr)
			result := int(element.ProcessContext.Process.FileEvent.FileFields.MTime)
			values = append(values, result)
			ptr = iterator.Next()
		}
		return values, nil
	case "ptrace.tracee.ancestors.file.mount_id":
		var values []int
		iterator := &ProcessAncestorsIterator{}
		ptr := iterator.Front(ctx)
		for ptr != nil {
			element := (*ProcessCacheEntry)(ptr)
			result := int(element.ProcessContext.Process.FileEvent.FileFields.MountID)
			values = append(values, result)
			ptr = iterator.Next()
		}
		return values, nil
	case "ptrace.tracee.ancestors.file.name":
		var values []string
		iterator := &ProcessAncestorsIterator{}
		ptr := iterator.Front(ctx)
		for ptr != nil {
			element := (*ProcessCacheEntry)(ptr)
			result := element.ProcessContext.Process.FileEvent.BasenameStr
			values = append(values, result)
			ptr = iterator.Next()
		}
		return values, nil
	case "ptrace.tracee.ancestors.file.path":
		var values []string
		iterator := &ProcessAncestorsIterator{}
		ptr := iterator.Front(ctx)
		for ptr != nil {
			element := (*ProcessCacheEntry)(ptr)
			result := element.ProcessContext.Process.FileEvent.PathnameStr
			values = append(values, result)
			ptr = iterator.Next()
		}
		return values, nil
	case "ptrace.tracee.ancestors.file.rights":
		var values []int
		iterator := &ProcessAncestorsIterator{}
		ptr := iterator.Front(ctx)
		for ptr != nil {
			element := (*ProcessCacheEntry)(ptr)
			result := int(element.ProcessContext.Process.FileEvent.FileFields.Mode)
			values = append(values, result)
			ptr = iterator.Next()
		}
		return values, nil
	case "ptrace.tracee.ancestors.file.uid":
		var values []int
		iterator := &ProcessAncestorsIterator{}
		ptr := iterator.Front(ctx)
		for ptr != nil {
			element := (*ProcessCacheEntry)(ptr)
			result := int(element.ProcessContext.Process.FileEvent.FileFields.UID)
			values = append(values, result)
			ptr = iterator.Next()
		}
		return values, nil
	case "ptrace.tracee.ancestors.file.user":
		var values []string
		iterator := &ProcessAncestorsIterator{}
		ptr := iterator.Front(ctx)
		for ptr != nil {
			element := (*ProcessCacheEntry)(ptr)
			result := element.ProcessContext.Process.FileEvent.FileFields.User
			values = append(values, result)
			ptr = iterator.Next()
		}
		return values, nil
	case "ptrace.tracee.ancestors.fsgid":
		var values []int
		iterator := &ProcessAncestorsIterator{}
		ptr := iterator.Front(ctx)
		for ptr != nil {
			element := (*ProcessCacheEntry)(ptr)
			result := int(element.ProcessContext.Process.Credentials.FSGID)
			values = append(values, result)
			ptr = iterator.Next()
		}
		return values, nil
	case "ptrace.tracee.ancestors.fsgroup":
		var values []string
		iterator := &ProcessAncestorsIterator{}
		ptr := iterator.Front(ctx)
		for ptr != nil {
			element := (*ProcessCacheEntry)(ptr)
			result := element.ProcessContext.Process.Credentials.FSGroup
			values = append(values, result)
			ptr = iterator.Next()
		}
		return values, nil
	case "ptrace.tracee.ancestors.fsuid":
		var values []int
		iterator := &ProcessAncestorsIterator{}
		ptr := iterator.Front(ctx)
		for ptr != nil {
			element := (*ProcessCacheEntry)(ptr)
			result := int(element.ProcessContext.Process.Credentials.FSUID)
			values = append(values, result)
			ptr = iterator.Next()
		}
		return values, nil
	case "ptrace.tracee.ancestors.fsuser":
		var values []string
		iterator := &ProcessAncestorsIterator{}
		ptr := iterator.Front(ctx)
		for ptr != nil {
			element := (*ProcessCacheEntry)(ptr)
			result := element.ProcessContext.Process.Credentials.FSUser
			values = append(values, result)
			ptr = iterator.Next()
		}
		return values, nil
	case "ptrace.tracee.ancestors.gid":
		var values []int
		iterator := &ProcessAncestorsIterator{}
		ptr := iterator.Front(ctx)
		for ptr != nil {
			element := (*ProcessCacheEntry)(ptr)
			result := int(element.ProcessContext.Process.Credentials.GID)
			values = append(values, result)
			ptr = iterator.Next()
		}
		return values, nil
	case "ptrace.tracee.ancestors.group":
		var values []string
		iterator := &ProcessAncestorsIterator{}
		ptr := iterator.Front(ctx)
		for ptr != nil {
			element := (*ProcessCacheEntry)(ptr)
			result := element.ProcessContext.Process.Credentials.Group
			values = append(values, result)
			ptr = iterator.Next()
		}
		return values, nil
	case "ptrace.tracee.ancestors.is_thread":
		var values []bool
		iterator := &ProcessAncestorsIterator{}
		ptr := iterator.Front(ctx)
		for ptr != nil {
			element := (*ProcessCacheEntry)(ptr)
			result := element.ProcessContext.Process.IsThread
			values = append(values, result)
			ptr = iterator.Next()
		}
		return values, nil
	case "ptrace.tracee.ancestors.pid":
		var values []int
		iterator := &ProcessAncestorsIterator{}
		ptr := iterator.Front(ctx)
		for ptr != nil {
			element := (*ProcessCacheEntry)(ptr)
			result := int(element.ProcessContext.Process.PIDContext.Pid)
			values = append(values, result)
			ptr = iterator.Next()
		}
		return values, nil
	case "ptrace.tracee.ancestors.ppid":
		var values []int
		iterator := &ProcessAncestorsIterator{}
		ptr := iterator.Front(ctx)
		for ptr != nil {
			element := (*ProcessCacheEntry)(ptr)
			result := int(element.ProcessContext.Process.PPid)
			values = append(values, result)
			ptr = iterator.Next()
		}
		return values, nil
	case "ptrace.tracee.ancestors.tid":
		var values []int
		iterator := &ProcessAncestorsIterator{}
		ptr := iterator.Front(ctx)
		for ptr != nil {
			element := (*ProcessCacheEntry)(ptr)
			result := int(element.ProcessContext.Process.PIDContext.Tid)
			values = append(values, result)
			ptr = iterator.Next()
		}
		return values, nil
	case "ptrace.tracee.ancestors.tty_name":
		var values []string
		iterator := &ProcessAncestorsIterator{}
		ptr := iterator.Front(ctx)
		for ptr != nil {
			element := (*ProcessCacheEntry)(ptr)
			result := element.ProcessContext.Process.TTYName
			values = append(values, result)
			ptr = iterator.Next()
		}
		return values, nil
	case "ptrace.tracee.ancestors.uid":
		var values []int
		iterator := &ProcessAncestorsIterator{}
		ptr := iterator.Front(ctx)
		for ptr != nil {
			element := (*ProcessCacheEntry)(ptr)
			result := int(element.ProcessContext.Process.Credentials.UID)
			values = append(values, result)
			ptr = iterator.Next()
		}
		return values, nil
	case "ptrace.tracee.ancestors.user":
		var values []string
		iterator := &ProcessAncestorsIterator{}
		ptr := iterator.Front(ctx)
		for ptr != nil {
			element := (*ProcessCacheEntry)(ptr)
			result := element.ProcessContext.Process.Credentials.User
			values = append(values, result)
			ptr = iterator.Next()
		}
		return values, nil
	case "ptrace.tracee.args":
		return event.PTrace.Tracee.Process.Args, nil
	case "ptrace.tracee.args_flags":
		return event.PTrace.Tracee.Process.Argv, nil
	case "ptrace.tracee.args_options":
		return event.PTrace.Tracee.Process.Argv, nil
	case "ptrace.tracee.args_truncated":
		return event.PTrace.Tracee.Process.ArgsTruncated, nil
	case "ptrace.tracee.argv":
		return event.PTrace.Tracee.Process.Argv, nil
	case "ptrace.tracee.argv0":
		return event.PTrace.Tracee.Process.Argv0, nil
	case "ptrace.tracee.cap_effective":
		return int(event.PTrace.Tracee.Process.Credentials.CapEffective), nil
	case "ptrace.tracee.cap_permitted":
		return int(event.PTrace.Tracee.Process.Credentials.CapPermitted), nil
	case "ptrace.tracee.comm":
		return event.PTrace.Tracee.Process.Comm, nil
	case "ptrace.tracee.container.id":
		return event.PTrace.Tracee.Process.ContainerID, nil
	case "ptrace.tracee.cookie":
		return int(event.PTrace.Tracee.Process.Cookie), nil
	case "ptrace.tracee.created_at":
		return int(event.PTrace.Tracee.Process.CreatedAt), nil
	case "ptrace.tracee.egid":
		return int(event.PTrace.Tracee.Process.Credentials.EGID), nil
	case "ptrace.tracee.egroup":
		return event.PTrace.Tracee.Process.Credentials.EGroup, nil
	case "ptrace.tracee.envp":
		return event.PTrace.Tracee.Process.Envp, nil
	case "ptrace.tracee.envs":
		return event.PTrace.Tracee.Process.Envs, nil
	case "ptrace.tracee.envs_truncated":
		return event.PTrace.Tracee.Process.EnvsTruncated, nil
	case "ptrace.tracee.euid":
		return int(event.PTrace.Tracee.Process.Credentials.EUID), nil
	case "ptrace.tracee.euser":
		return event.PTrace.Tracee.Process.Credentials.EUser, nil
	case "ptrace.tracee.file.change_time":
		return int(event.PTrace.Tracee.Process.FileEvent.FileFields.CTime), nil
	case "ptrace.tracee.file.filesystem":
		return event.PTrace.Tracee.Process.FileEvent.Filesystem, nil
	case "ptrace.tracee.file.gid":
		return int(event.PTrace.Tracee.Process.FileEvent.FileFields.GID), nil
	case "ptrace.tracee.file.group":
		return event.PTrace.Tracee.Process.FileEvent.FileFields.Group, nil
	case "ptrace.tracee.file.in_upper_layer":
		return event.PTrace.Tracee.Process.FileEvent.FileFields.InUpperLayer, nil
	case "ptrace.tracee.file.inode":
		return int(event.PTrace.Tracee.Process.FileEvent.FileFields.Inode), nil
	case "ptrace.tracee.file.mode":
		return int(event.PTrace.Tracee.Process.FileEvent.FileFields.Mode), nil
	case "ptrace.tracee.file.modification_time":
		return int(event.PTrace.Tracee.Process.FileEvent.FileFields.MTime), nil
	case "ptrace.tracee.file.mount_id":
		return int(event.PTrace.Tracee.Process.FileEvent.FileFields.MountID), nil
	case "ptrace.tracee.file.name":
		return event.PTrace.Tracee.Process.FileEvent.BasenameStr, nil
	case "ptrace.tracee.file.path":
		return event.PTrace.Tracee.Process.FileEvent.PathnameStr, nil
	case "ptrace.tracee.file.rights":
		return int(event.PTrace.Tracee.Process.FileEvent.FileFields.Mode), nil
	case "ptrace.tracee.file.uid":
		return int(event.PTrace.Tracee.Process.FileEvent.FileFields.UID), nil
	case "ptrace.tracee.file.user":
		return event.PTrace.Tracee.Process.FileEvent.FileFields.User, nil
	case "ptrace.tracee.fsgid":
		return int(event.PTrace.Tracee.Process.Credentials.FSGID), nil
	case "ptrace.tracee.fsgroup":
		return event.PTrace.Tracee.Process.Credentials.FSGroup, nil
	case "ptrace.tracee.fsuid":
		return int(event.PTrace.Tracee.Process.Credentials.FSUID), nil
	case "ptrace.tracee.fsuser":
		return event.PTrace.Tracee.Process.Credentials.FSUser, nil
	case "ptrace.tracee.gid":
		return int(event.PTrace.Tracee.Process.Credentials.GID), nil
	case "ptrace.tracee.group":
		return event.PTrace.Tracee.Process.Credentials.Group, nil
	case "ptrace.tracee.is_thread":
		return event.PTrace.Tracee.Process.IsThread, nil
	case "ptrace.tracee.pid":
		return int(event.PTrace.Tracee.Process.PIDContext.Pid), nil
	case "ptrace.tracee.ppid":
		return int(event.PTrace.Tracee.Process.PPid), nil
	case "ptrace.tracee.tid":
		return int(event.PTrace.Tracee.Process.PIDContext.Tid), nil
	case "ptrace.tracee.tty_name":
		return event.PTrace.Tracee.Process.TTYName, nil
	case "ptrace.tracee.uid":
		return int(event.PTrace.Tracee.Process.Credentials.UID), nil
	case "ptrace.tracee.user":
		return event.PTrace.Tracee.Process.Credentials.User, nil
	case "removexattr.file.change_time":
		return int(event.RemoveXAttr.File.FileFields.CTime), nil
	case "removexattr.file.destination.name":
		return event.RemoveXAttr.Name, nil
	case "removexattr.file.destination.namespace":
		return event.RemoveXAttr.Namespace, nil
	case "removexattr.file.filesystem":
		return event.RemoveXAttr.File.Filesystem, nil
	case "removexattr.file.gid":
		return int(event.RemoveXAttr.File.FileFields.GID), nil
	case "removexattr.file.group":
		return event.RemoveXAttr.File.FileFields.Group, nil
	case "removexattr.file.in_upper_layer":
		return event.RemoveXAttr.File.FileFields.InUpperLayer, nil
	case "removexattr.file.inode":
		return int(event.RemoveXAttr.File.FileFields.Inode), nil
	case "removexattr.file.mode":
		return int(event.RemoveXAttr.File.FileFields.Mode), nil
	case "removexattr.file.modification_time":
		return int(event.RemoveXAttr.File.FileFields.MTime), nil
	case "removexattr.file.mount_id":
		return int(event.RemoveXAttr.File.FileFields.MountID), nil
	case "removexattr.file.name":
		return event.RemoveXAttr.File.BasenameStr, nil
	case "removexattr.file.path":
		return event.RemoveXAttr.File.PathnameStr, nil
	case "removexattr.file.rights":
		return int(event.RemoveXAttr.File.FileFields.Mode), nil
	case "removexattr.file.uid":
		return int(event.RemoveXAttr.File.FileFields.UID), nil
	case "removexattr.file.user":
		return event.RemoveXAttr.File.FileFields.User, nil
	case "removexattr.retval":
		return int(event.RemoveXAttr.SyscallEvent.Retval), nil
	case "rename.file.change_time":
		return int(event.Rename.Old.FileFields.CTime), nil
	case "rename.file.destination.change_time":
		return int(event.Rename.New.FileFields.CTime), nil
	case "rename.file.destination.filesystem":
		return event.Rename.New.Filesystem, nil
	case "rename.file.destination.gid":
		return int(event.Rename.New.FileFields.GID), nil
	case "rename.file.destination.group":
		return event.Rename.New.FileFields.Group, nil
	case "rename.file.destination.in_upper_layer":
		return event.Rename.New.FileFields.InUpperLayer, nil
	case "rename.file.destination.inode":
		return int(event.Rename.New.FileFields.Inode), nil
	case "rename.file.destination.mode":
		return int(event.Rename.New.FileFields.Mode), nil
	case "rename.file.destination.modification_time":
		return int(event.Rename.New.FileFields.MTime), nil
	case "rename.file.destination.mount_id":
		return int(event.Rename.New.FileFields.MountID), nil
	case "rename.file.destination.name":
		return event.Rename.New.BasenameStr, nil
	case "rename.file.destination.path":
		return event.Rename.New.PathnameStr, nil
	case "rename.file.destination.rights":
		return int(event.Rename.New.FileFields.Mode), nil
	case "rename.file.destination.uid":
		return int(event.Rename.New.FileFields.UID), nil
	case "rename.file.destination.user":
		return event.Rename.New.FileFields.User, nil
	case "rename.file.filesystem":
		return event.Rename.Old.Filesystem, nil
	case "rename.file.gid":
		return int(event.Rename.Old.FileFields.GID), nil
	case "rename.file.group":
		return event.Rename.Old.FileFields.Group, nil
	case "rename.file.in_upper_layer":
		return event.Rename.Old.FileFields.InUpperLayer, nil
	case "rename.file.inode":
		return int(event.Rename.Old.FileFields.Inode), nil
	case "rename.file.mode":
		return int(event.Rename.Old.FileFields.Mode), nil
	case "rename.file.modification_time":
		return int(event.Rename.Old.FileFields.MTime), nil
	case "rename.file.mount_id":
		return int(event.Rename.Old.FileFields.MountID), nil
	case "rename.file.name":
		return event.Rename.Old.BasenameStr, nil
	case "rename.file.path":
		return event.Rename.Old.PathnameStr, nil
	case "rename.file.rights":
		return int(event.Rename.Old.FileFields.Mode), nil
	case "rename.file.uid":
		return int(event.Rename.Old.FileFields.UID), nil
	case "rename.file.user":
		return event.Rename.Old.FileFields.User, nil
	case "rename.retval":
		return int(event.Rename.SyscallEvent.Retval), nil
	case "rmdir.file.change_time":
		return int(event.Rmdir.File.FileFields.CTime), nil
	case "rmdir.file.filesystem":
		return event.Rmdir.File.Filesystem, nil
	case "rmdir.file.gid":
		return int(event.Rmdir.File.FileFields.GID), nil
	case "rmdir.file.group":
		return event.Rmdir.File.FileFields.Group, nil
	case "rmdir.file.in_upper_layer":
		return event.Rmdir.File.FileFields.InUpperLayer, nil
	case "rmdir.file.inode":
		return int(event.Rmdir.File.FileFields.Inode), nil
	case "rmdir.file.mode":
		return int(event.Rmdir.File.FileFields.Mode), nil
	case "rmdir.file.modification_time":
		return int(event.Rmdir.File.FileFields.MTime), nil
	case "rmdir.file.mount_id":
		return int(event.Rmdir.File.FileFields.MountID), nil
	case "rmdir.file.name":
		return event.Rmdir.File.BasenameStr, nil
	case "rmdir.file.path":
		return event.Rmdir.File.PathnameStr, nil
	case "rmdir.file.rights":
		return int(event.Rmdir.File.FileFields.Mode), nil
	case "rmdir.file.uid":
		return int(event.Rmdir.File.FileFields.UID), nil
	case "rmdir.file.user":
		return event.Rmdir.File.FileFields.User, nil
	case "rmdir.retval":
		return int(event.Rmdir.SyscallEvent.Retval), nil
	case "selinux.bool.name":
		return event.SELinux.BoolName, nil
	case "selinux.bool.state":
		return event.SELinux.BoolChangeValue, nil
	case "selinux.bool_commit.state":
		return event.SELinux.BoolCommitValue, nil
	case "selinux.enforce.status":
		return event.SELinux.EnforceStatus, nil
	case "setgid.egid":
		return int(event.SetGID.EGID), nil
	case "setgid.egroup":
		return event.SetGID.EGroup, nil
	case "setgid.fsgid":
		return int(event.SetGID.FSGID), nil
	case "setgid.fsgroup":
		return event.SetGID.FSGroup, nil
	case "setgid.gid":
		return int(event.SetGID.GID), nil
	case "setgid.group":
		return event.SetGID.Group, nil
	case "setuid.euid":
		return int(event.SetUID.EUID), nil
	case "setuid.euser":
		return event.SetUID.EUser, nil
	case "setuid.fsuid":
		return int(event.SetUID.FSUID), nil
	case "setuid.fsuser":
		return event.SetUID.FSUser, nil
	case "setuid.uid":
		return int(event.SetUID.UID), nil
	case "setuid.user":
		return event.SetUID.User, nil
	case "setxattr.file.change_time":
		return int(event.SetXAttr.File.FileFields.CTime), nil
	case "setxattr.file.destination.name":
		return event.SetXAttr.Name, nil
	case "setxattr.file.destination.namespace":
		return event.SetXAttr.Namespace, nil
	case "setxattr.file.filesystem":
		return event.SetXAttr.File.Filesystem, nil
	case "setxattr.file.gid":
		return int(event.SetXAttr.File.FileFields.GID), nil
	case "setxattr.file.group":
		return event.SetXAttr.File.FileFields.Group, nil
	case "setxattr.file.in_upper_layer":
		return event.SetXAttr.File.FileFields.InUpperLayer, nil
	case "setxattr.file.inode":
		return int(event.SetXAttr.File.FileFields.Inode), nil
	case "setxattr.file.mode":
		return int(event.SetXAttr.File.FileFields.Mode), nil
	case "setxattr.file.modification_time":
		return int(event.SetXAttr.File.FileFields.MTime), nil
	case "setxattr.file.mount_id":
		return int(event.SetXAttr.File.FileFields.MountID), nil
	case "setxattr.file.name":
		return event.SetXAttr.File.BasenameStr, nil
	case "setxattr.file.path":
		return event.SetXAttr.File.PathnameStr, nil
	case "setxattr.file.rights":
		return int(event.SetXAttr.File.FileFields.Mode), nil
	case "setxattr.file.uid":
		return int(event.SetXAttr.File.FileFields.UID), nil
	case "setxattr.file.user":
		return event.SetXAttr.File.FileFields.User, nil
	case "setxattr.retval":
		return int(event.SetXAttr.SyscallEvent.Retval), nil
	case "signal.pid":
		return int(event.Signal.PID), nil
	case "signal.retval":
		return int(event.Signal.SyscallEvent.Retval), nil
	case "signal.target.ancestors.args":
		var values []string
		iterator := &ProcessAncestorsIterator{}
		ptr := iterator.Front(ctx)
		for ptr != nil {
			element := (*ProcessCacheEntry)(ptr)
			result := element.ProcessContext.Process.Args
			values = append(values, result)
			ptr = iterator.Next()
		}
		return values, nil
	case "signal.target.ancestors.args_flags":
		var values []string
		iterator := &ProcessAncestorsIterator{}
		ptr := iterator.Front(ctx)
		for ptr != nil {
			element := (*ProcessCacheEntry)(ptr)
			result := element.ProcessContext.Process.Argv
			values = append(values, result...)
			ptr = iterator.Next()
		}
		return values, nil
	case "signal.target.ancestors.args_options":
		var values []string
		iterator := &ProcessAncestorsIterator{}
		ptr := iterator.Front(ctx)
		for ptr != nil {
			element := (*ProcessCacheEntry)(ptr)
			result := element.ProcessContext.Process.Argv
			values = append(values, result...)
			ptr = iterator.Next()
		}
		return values, nil
	case "signal.target.ancestors.args_truncated":
		var values []bool
		iterator := &ProcessAncestorsIterator{}
		ptr := iterator.Front(ctx)
		for ptr != nil {
			element := (*ProcessCacheEntry)(ptr)
			result := element.ProcessContext.Process.ArgsTruncated
			values = append(values, result)
			ptr = iterator.Next()
		}
		return values, nil
	case "signal.target.ancestors.argv":
		var values []string
		iterator := &ProcessAncestorsIterator{}
		ptr := iterator.Front(ctx)
		for ptr != nil {
			element := (*ProcessCacheEntry)(ptr)
			result := element.ProcessContext.Process.Argv
			values = append(values, result...)
			ptr = iterator.Next()
		}
		return values, nil
	case "signal.target.ancestors.argv0":
		var values []string
		iterator := &ProcessAncestorsIterator{}
		ptr := iterator.Front(ctx)
		for ptr != nil {
			element := (*ProcessCacheEntry)(ptr)
			result := element.ProcessContext.Process.Argv0
			values = append(values, result)
			ptr = iterator.Next()
		}
		return values, nil
	case "signal.target.ancestors.cap_effective":
		var values []int
		iterator := &ProcessAncestorsIterator{}
		ptr := iterator.Front(ctx)
		for ptr != nil {
			element := (*ProcessCacheEntry)(ptr)
			result := int(element.ProcessContext.Process.Credentials.CapEffective)
			values = append(values, result)
			ptr = iterator.Next()
		}
		return values, nil
	case "signal.target.ancestors.cap_permitted":
		var values []int
		iterator := &ProcessAncestorsIterator{}
		ptr := iterator.Front(ctx)
		for ptr != nil {
			element := (*ProcessCacheEntry)(ptr)
			result := int(element.ProcessContext.Process.Credentials.CapPermitted)
			values = append(values, result)
			ptr = iterator.Next()
		}
		return values, nil
	case "signal.target.ancestors.comm":
		var values []string
		iterator := &ProcessAncestorsIterator{}
		ptr := iterator.Front(ctx)
		for ptr != nil {
			element := (*ProcessCacheEntry)(ptr)
			result := element.ProcessContext.Process.Comm
			values = append(values, result)
			ptr = iterator.Next()
		}
		return values, nil
	case "signal.target.ancestors.container.id":
		var values []string
		iterator := &ProcessAncestorsIterator{}
		ptr := iterator.Front(ctx)
		for ptr != nil {
			element := (*ProcessCacheEntry)(ptr)
			result := element.ProcessContext.Process.ContainerID
			values = append(values, result)
			ptr = iterator.Next()
		}
		return values, nil
	case "signal.target.ancestors.cookie":
		var values []int
		iterator := &ProcessAncestorsIterator{}
		ptr := iterator.Front(ctx)
		for ptr != nil {
			element := (*ProcessCacheEntry)(ptr)
			result := int(element.ProcessContext.Process.Cookie)
			values = append(values, result)
			ptr = iterator.Next()
		}
		return values, nil
	case "signal.target.ancestors.created_at":
		var values []int
		iterator := &ProcessAncestorsIterator{}
		ptr := iterator.Front(ctx)
		for ptr != nil {
			element := (*ProcessCacheEntry)(ptr)
			result := int(element.ProcessContext.Process.CreatedAt)
			values = append(values, result)
			ptr = iterator.Next()
		}
		return values, nil
	case "signal.target.ancestors.egid":
		var values []int
		iterator := &ProcessAncestorsIterator{}
		ptr := iterator.Front(ctx)
		for ptr != nil {
			element := (*ProcessCacheEntry)(ptr)
			result := int(element.ProcessContext.Process.Credentials.EGID)
			values = append(values, result)
			ptr = iterator.Next()
		}
		return values, nil
	case "signal.target.ancestors.egroup":
		var values []string
		iterator := &ProcessAncestorsIterator{}
		ptr := iterator.Front(ctx)
		for ptr != nil {
			element := (*ProcessCacheEntry)(ptr)
			result := element.ProcessContext.Process.Credentials.EGroup
			values = append(values, result)
			ptr = iterator.Next()
		}
		return values, nil
	case "signal.target.ancestors.envp":
		var values []string
		iterator := &ProcessAncestorsIterator{}
		ptr := iterator.Front(ctx)
		for ptr != nil {
			element := (*ProcessCacheEntry)(ptr)
			result := element.ProcessContext.Process.Envp
			values = append(values, result...)
			ptr = iterator.Next()
		}
		return values, nil
	case "signal.target.ancestors.envs":
		var values []string
		iterator := &ProcessAncestorsIterator{}
		ptr := iterator.Front(ctx)
		for ptr != nil {
			element := (*ProcessCacheEntry)(ptr)
			result := element.ProcessContext.Process.Envs
			values = append(values, result...)
			ptr = iterator.Next()
		}
		return values, nil
	case "signal.target.ancestors.envs_truncated":
		var values []bool
		iterator := &ProcessAncestorsIterator{}
		ptr := iterator.Front(ctx)
		for ptr != nil {
			element := (*ProcessCacheEntry)(ptr)
			result := element.ProcessContext.Process.EnvsTruncated
			values = append(values, result)
			ptr = iterator.Next()
		}
		return values, nil
	case "signal.target.ancestors.euid":
		var values []int
		iterator := &ProcessAncestorsIterator{}
		ptr := iterator.Front(ctx)
		for ptr != nil {
			element := (*ProcessCacheEntry)(ptr)
			result := int(element.ProcessContext.Process.Credentials.EUID)
			values = append(values, result)
			ptr = iterator.Next()
		}
		return values, nil
	case "signal.target.ancestors.euser":
		var values []string
		iterator := &ProcessAncestorsIterator{}
		ptr := iterator.Front(ctx)
		for ptr != nil {
			element := (*ProcessCacheEntry)(ptr)
			result := element.ProcessContext.Process.Credentials.EUser
			values = append(values, result)
			ptr = iterator.Next()
		}
		return values, nil
	case "signal.target.ancestors.file.change_time":
		var values []int
		iterator := &ProcessAncestorsIterator{}
		ptr := iterator.Front(ctx)
		for ptr != nil {
			element := (*ProcessCacheEntry)(ptr)
			result := int(element.ProcessContext.Process.FileEvent.FileFields.CTime)
			values = append(values, result)
			ptr = iterator.Next()
		}
		return values, nil
	case "signal.target.ancestors.file.filesystem":
		var values []string
		iterator := &ProcessAncestorsIterator{}
		ptr := iterator.Front(ctx)
		for ptr != nil {
			element := (*ProcessCacheEntry)(ptr)
			result := element.ProcessContext.Process.FileEvent.Filesystem
			values = append(values, result)
			ptr = iterator.Next()
		}
		return values, nil
	case "signal.target.ancestors.file.gid":
		var values []int
		iterator := &ProcessAncestorsIterator{}
		ptr := iterator.Front(ctx)
		for ptr != nil {
			element := (*ProcessCacheEntry)(ptr)
			result := int(element.ProcessContext.Process.FileEvent.FileFields.GID)
			values = append(values, result)
			ptr = iterator.Next()
		}
		return values, nil
	case "signal.target.ancestors.file.group":
		var values []string
		iterator := &ProcessAncestorsIterator{}
		ptr := iterator.Front(ctx)
		for ptr != nil {
			element := (*ProcessCacheEntry)(ptr)
			result := element.ProcessContext.Process.FileEvent.FileFields.Group
			values = append(values, result)
			ptr = iterator.Next()
		}
		return values, nil
	case "signal.target.ancestors.file.in_upper_layer":
		var values []bool
		iterator := &ProcessAncestorsIterator{}
		ptr := iterator.Front(ctx)
		for ptr != nil {
			element := (*ProcessCacheEntry)(ptr)
			result := element.ProcessContext.Process.FileEvent.FileFields.InUpperLayer
			values = append(values, result)
			ptr = iterator.Next()
		}
		return values, nil
	case "signal.target.ancestors.file.inode":
		var values []int
		iterator := &ProcessAncestorsIterator{}
		ptr := iterator.Front(ctx)
		for ptr != nil {
			element := (*ProcessCacheEntry)(ptr)
			result := int(element.ProcessContext.Process.FileEvent.FileFields.Inode)
			values = append(values, result)
			ptr = iterator.Next()
		}
		return values, nil
	case "signal.target.ancestors.file.mode":
		var values []int
		iterator := &ProcessAncestorsIterator{}
		ptr := iterator.Front(ctx)
		for ptr != nil {
			element := (*ProcessCacheEntry)(ptr)
			result := int(element.ProcessContext.Process.FileEvent.FileFields.Mode)
			values = append(values, result)
			ptr = iterator.Next()
		}
		return values, nil
	case "signal.target.ancestors.file.modification_time":
		var values []int
		iterator := &ProcessAncestorsIterator{}
		ptr := iterator.Front(ctx)
		for ptr != nil {
			element := (*ProcessCacheEntry)(ptr)
			result := int(element.ProcessContext.Process.FileEvent.FileFields.MTime)
			values = append(values, result)
			ptr = iterator.Next()
		}
		return values, nil
	case "signal.target.ancestors.file.mount_id":
		var values []int
		iterator := &ProcessAncestorsIterator{}
		ptr := iterator.Front(ctx)
		for ptr != nil {
			element := (*ProcessCacheEntry)(ptr)
			result := int(element.ProcessContext.Process.FileEvent.FileFields.MountID)
			values = append(values, result)
			ptr = iterator.Next()
		}
		return values, nil
	case "signal.target.ancestors.file.name":
		var values []string
		iterator := &ProcessAncestorsIterator{}
		ptr := iterator.Front(ctx)
		for ptr != nil {
			element := (*ProcessCacheEntry)(ptr)
			result := element.ProcessContext.Process.FileEvent.BasenameStr
			values = append(values, result)
			ptr = iterator.Next()
		}
		return values, nil
	case "signal.target.ancestors.file.path":
		var values []string
		iterator := &ProcessAncestorsIterator{}
		ptr := iterator.Front(ctx)
		for ptr != nil {
			element := (*ProcessCacheEntry)(ptr)
			result := element.ProcessContext.Process.FileEvent.PathnameStr
			values = append(values, result)
			ptr = iterator.Next()
		}
		return values, nil
	case "signal.target.ancestors.file.rights":
		var values []int
		iterator := &ProcessAncestorsIterator{}
		ptr := iterator.Front(ctx)
		for ptr != nil {
			element := (*ProcessCacheEntry)(ptr)
			result := int(element.ProcessContext.Process.FileEvent.FileFields.Mode)
			values = append(values, result)
			ptr = iterator.Next()
		}
		return values, nil
	case "signal.target.ancestors.file.uid":
		var values []int
		iterator := &ProcessAncestorsIterator{}
		ptr := iterator.Front(ctx)
		for ptr != nil {
			element := (*ProcessCacheEntry)(ptr)
			result := int(element.ProcessContext.Process.FileEvent.FileFields.UID)
			values = append(values, result)
			ptr = iterator.Next()
		}
		return values, nil
	case "signal.target.ancestors.file.user":
		var values []string
		iterator := &ProcessAncestorsIterator{}
		ptr := iterator.Front(ctx)
		for ptr != nil {
			element := (*ProcessCacheEntry)(ptr)
			result := element.ProcessContext.Process.FileEvent.FileFields.User
			values = append(values, result)
			ptr = iterator.Next()
		}
		return values, nil
	case "signal.target.ancestors.fsgid":
		var values []int
		iterator := &ProcessAncestorsIterator{}
		ptr := iterator.Front(ctx)
		for ptr != nil {
			element := (*ProcessCacheEntry)(ptr)
			result := int(element.ProcessContext.Process.Credentials.FSGID)
			values = append(values, result)
			ptr = iterator.Next()
		}
		return values, nil
	case "signal.target.ancestors.fsgroup":
		var values []string
		iterator := &ProcessAncestorsIterator{}
		ptr := iterator.Front(ctx)
		for ptr != nil {
			element := (*ProcessCacheEntry)(ptr)
			result := element.ProcessContext.Process.Credentials.FSGroup
			values = append(values, result)
			ptr = iterator.Next()
		}
		return values, nil
	case "signal.target.ancestors.fsuid":
		var values []int
		iterator := &ProcessAncestorsIterator{}
		ptr := iterator.Front(ctx)
		for ptr != nil {
			element := (*ProcessCacheEntry)(ptr)
			result := int(element.ProcessContext.Process.Credentials.FSUID)
			values = append(values, result)
			ptr = iterator.Next()
		}
		return values, nil
	case "signal.target.ancestors.fsuser":
		var values []string
		iterator := &ProcessAncestorsIterator{}
		ptr := iterator.Front(ctx)
		for ptr != nil {
			element := (*ProcessCacheEntry)(ptr)
			result := element.ProcessContext.Process.Credentials.FSUser
			values = append(values, result)
			ptr = iterator.Next()
		}
		return values, nil
	case "signal.target.ancestors.gid":
		var values []int
		iterator := &ProcessAncestorsIterator{}
		ptr := iterator.Front(ctx)
		for ptr != nil {
			element := (*ProcessCacheEntry)(ptr)
			result := int(element.ProcessContext.Process.Credentials.GID)
			values = append(values, result)
			ptr = iterator.Next()
		}
		return values, nil
	case "signal.target.ancestors.group":
		var values []string
		iterator := &ProcessAncestorsIterator{}
		ptr := iterator.Front(ctx)
		for ptr != nil {
			element := (*ProcessCacheEntry)(ptr)
			result := element.ProcessContext.Process.Credentials.Group
			values = append(values, result)
			ptr = iterator.Next()
		}
		return values, nil
	case "signal.target.ancestors.is_thread":
		var values []bool
		iterator := &ProcessAncestorsIterator{}
		ptr := iterator.Front(ctx)
		for ptr != nil {
			element := (*ProcessCacheEntry)(ptr)
			result := element.ProcessContext.Process.IsThread
			values = append(values, result)
			ptr = iterator.Next()
		}
		return values, nil
	case "signal.target.ancestors.pid":
		var values []int
		iterator := &ProcessAncestorsIterator{}
		ptr := iterator.Front(ctx)
		for ptr != nil {
			element := (*ProcessCacheEntry)(ptr)
			result := int(element.ProcessContext.Process.PIDContext.Pid)
			values = append(values, result)
			ptr = iterator.Next()
		}
		return values, nil
	case "signal.target.ancestors.ppid":
		var values []int
		iterator := &ProcessAncestorsIterator{}
		ptr := iterator.Front(ctx)
		for ptr != nil {
			element := (*ProcessCacheEntry)(ptr)
			result := int(element.ProcessContext.Process.PPid)
			values = append(values, result)
			ptr = iterator.Next()
		}
		return values, nil
	case "signal.target.ancestors.tid":
		var values []int
		iterator := &ProcessAncestorsIterator{}
		ptr := iterator.Front(ctx)
		for ptr != nil {
			element := (*ProcessCacheEntry)(ptr)
			result := int(element.ProcessContext.Process.PIDContext.Tid)
			values = append(values, result)
			ptr = iterator.Next()
		}
		return values, nil
	case "signal.target.ancestors.tty_name":
		var values []string
		iterator := &ProcessAncestorsIterator{}
		ptr := iterator.Front(ctx)
		for ptr != nil {
			element := (*ProcessCacheEntry)(ptr)
			result := element.ProcessContext.Process.TTYName
			values = append(values, result)
			ptr = iterator.Next()
		}
		return values, nil
	case "signal.target.ancestors.uid":
		var values []int
		iterator := &ProcessAncestorsIterator{}
		ptr := iterator.Front(ctx)
		for ptr != nil {
			element := (*ProcessCacheEntry)(ptr)
			result := int(element.ProcessContext.Process.Credentials.UID)
			values = append(values, result)
			ptr = iterator.Next()
		}
		return values, nil
	case "signal.target.ancestors.user":
		var values []string
		iterator := &ProcessAncestorsIterator{}
		ptr := iterator.Front(ctx)
		for ptr != nil {
			element := (*ProcessCacheEntry)(ptr)
			result := element.ProcessContext.Process.Credentials.User
			values = append(values, result)
			ptr = iterator.Next()
		}
		return values, nil
	case "signal.target.args":
		return event.Signal.Target.Process.Args, nil
	case "signal.target.args_flags":
		return event.Signal.Target.Process.Argv, nil
	case "signal.target.args_options":
		return event.Signal.Target.Process.Argv, nil
	case "signal.target.args_truncated":
		return event.Signal.Target.Process.ArgsTruncated, nil
	case "signal.target.argv":
		return event.Signal.Target.Process.Argv, nil
	case "signal.target.argv0":
		return event.Signal.Target.Process.Argv0, nil
	case "signal.target.cap_effective":
		return int(event.Signal.Target.Process.Credentials.CapEffective), nil
	case "signal.target.cap_permitted":
		return int(event.Signal.Target.Process.Credentials.CapPermitted), nil
	case "signal.target.comm":
		return event.Signal.Target.Process.Comm, nil
	case "signal.target.container.id":
		return event.Signal.Target.Process.ContainerID, nil
	case "signal.target.cookie":
		return int(event.Signal.Target.Process.Cookie), nil
	case "signal.target.created_at":
		return int(event.Signal.Target.Process.CreatedAt), nil
	case "signal.target.egid":
		return int(event.Signal.Target.Process.Credentials.EGID), nil
	case "signal.target.egroup":
		return event.Signal.Target.Process.Credentials.EGroup, nil
	case "signal.target.envp":
		return event.Signal.Target.Process.Envp, nil
	case "signal.target.envs":
		return event.Signal.Target.Process.Envs, nil
	case "signal.target.envs_truncated":
		return event.Signal.Target.Process.EnvsTruncated, nil
	case "signal.target.euid":
		return int(event.Signal.Target.Process.Credentials.EUID), nil
	case "signal.target.euser":
		return event.Signal.Target.Process.Credentials.EUser, nil
	case "signal.target.file.change_time":
		return int(event.Signal.Target.Process.FileEvent.FileFields.CTime), nil
	case "signal.target.file.filesystem":
		return event.Signal.Target.Process.FileEvent.Filesystem, nil
	case "signal.target.file.gid":
		return int(event.Signal.Target.Process.FileEvent.FileFields.GID), nil
	case "signal.target.file.group":
		return event.Signal.Target.Process.FileEvent.FileFields.Group, nil
	case "signal.target.file.in_upper_layer":
		return event.Signal.Target.Process.FileEvent.FileFields.InUpperLayer, nil
	case "signal.target.file.inode":
		return int(event.Signal.Target.Process.FileEvent.FileFields.Inode), nil
	case "signal.target.file.mode":
		return int(event.Signal.Target.Process.FileEvent.FileFields.Mode), nil
	case "signal.target.file.modification_time":
		return int(event.Signal.Target.Process.FileEvent.FileFields.MTime), nil
	case "signal.target.file.mount_id":
		return int(event.Signal.Target.Process.FileEvent.FileFields.MountID), nil
	case "signal.target.file.name":
		return event.Signal.Target.Process.FileEvent.BasenameStr, nil
	case "signal.target.file.path":
		return event.Signal.Target.Process.FileEvent.PathnameStr, nil
	case "signal.target.file.rights":
		return int(event.Signal.Target.Process.FileEvent.FileFields.Mode), nil
	case "signal.target.file.uid":
		return int(event.Signal.Target.Process.FileEvent.FileFields.UID), nil
	case "signal.target.file.user":
		return event.Signal.Target.Process.FileEvent.FileFields.User, nil
	case "signal.target.fsgid":
		return int(event.Signal.Target.Process.Credentials.FSGID), nil
	case "signal.target.fsgroup":
		return event.Signal.Target.Process.Credentials.FSGroup, nil
	case "signal.target.fsuid":
		return int(event.Signal.Target.Process.Credentials.FSUID), nil
	case "signal.target.fsuser":
		return event.Signal.Target.Process.Credentials.FSUser, nil
	case "signal.target.gid":
		return int(event.Signal.Target.Process.Credentials.GID), nil
	case "signal.target.group":
		return event.Signal.Target.Process.Credentials.Group, nil
	case "signal.target.is_thread":
		return event.Signal.Target.Process.IsThread, nil
	case "signal.target.pid":
		return int(event.Signal.Target.Process.PIDContext.Pid), nil
	case "signal.target.ppid":
		return int(event.Signal.Target.Process.PPid), nil
	case "signal.target.tid":
		return int(event.Signal.Target.Process.PIDContext.Tid), nil
	case "signal.target.tty_name":
		return event.Signal.Target.Process.TTYName, nil
	case "signal.target.uid":
		return int(event.Signal.Target.Process.Credentials.UID), nil
	case "signal.target.user":
		return event.Signal.Target.Process.Credentials.User, nil
	case "signal.type":
		return int(event.Signal.Type), nil
	case "splice.file.change_time":
		return int(event.Splice.File.FileFields.CTime), nil
	case "splice.file.filesystem":
		return event.Splice.File.Filesystem, nil
	case "splice.file.gid":
		return int(event.Splice.File.FileFields.GID), nil
	case "splice.file.group":
		return event.Splice.File.FileFields.Group, nil
	case "splice.file.in_upper_layer":
		return event.Splice.File.FileFields.InUpperLayer, nil
	case "splice.file.inode":
		return int(event.Splice.File.FileFields.Inode), nil
	case "splice.file.mode":
		return int(event.Splice.File.FileFields.Mode), nil
	case "splice.file.modification_time":
		return int(event.Splice.File.FileFields.MTime), nil
	case "splice.file.mount_id":
		return int(event.Splice.File.FileFields.MountID), nil
	case "splice.file.name":
		return event.Splice.File.BasenameStr, nil
	case "splice.file.path":
		return event.Splice.File.PathnameStr, nil
	case "splice.file.rights":
		return int(event.Splice.File.FileFields.Mode), nil
	case "splice.file.uid":
		return int(event.Splice.File.FileFields.UID), nil
	case "splice.file.user":
		return event.Splice.File.FileFields.User, nil
	case "splice.pipe_entry_flag":
		return int(event.Splice.PipeEntryFlag), nil
	case "splice.pipe_exit_flag":
		return int(event.Splice.PipeExitFlag), nil
	case "splice.retval":
		return int(event.Splice.SyscallEvent.Retval), nil
	case "unlink.file.change_time":
		return int(event.Unlink.File.FileFields.CTime), nil
	case "unlink.file.filesystem":
		return event.Unlink.File.Filesystem, nil
	case "unlink.file.gid":
		return int(event.Unlink.File.FileFields.GID), nil
	case "unlink.file.group":
		return event.Unlink.File.FileFields.Group, nil
	case "unlink.file.in_upper_layer":
		return event.Unlink.File.FileFields.InUpperLayer, nil
	case "unlink.file.inode":
		return int(event.Unlink.File.FileFields.Inode), nil
	case "unlink.file.mode":
		return int(event.Unlink.File.FileFields.Mode), nil
	case "unlink.file.modification_time":
		return int(event.Unlink.File.FileFields.MTime), nil
	case "unlink.file.mount_id":
		return int(event.Unlink.File.FileFields.MountID), nil
	case "unlink.file.name":
		return event.Unlink.File.BasenameStr, nil
	case "unlink.file.path":
		return event.Unlink.File.PathnameStr, nil
	case "unlink.file.rights":
		return int(event.Unlink.File.FileFields.Mode), nil
	case "unlink.file.uid":
		return int(event.Unlink.File.FileFields.UID), nil
	case "unlink.file.user":
		return event.Unlink.File.FileFields.User, nil
	case "unlink.flags":
		return int(event.Unlink.Flags), nil
	case "unlink.retval":
		return int(event.Unlink.SyscallEvent.Retval), nil
	case "unload_module.name":
		return event.UnloadModule.Name, nil
	case "unload_module.retval":
		return int(event.UnloadModule.SyscallEvent.Retval), nil
	case "utimes.file.change_time":
		return int(event.Utimes.File.FileFields.CTime), nil
	case "utimes.file.filesystem":
		return event.Utimes.File.Filesystem, nil
	case "utimes.file.gid":
		return int(event.Utimes.File.FileFields.GID), nil
	case "utimes.file.group":
		return event.Utimes.File.FileFields.Group, nil
	case "utimes.file.in_upper_layer":
		return event.Utimes.File.FileFields.InUpperLayer, nil
	case "utimes.file.inode":
		return int(event.Utimes.File.FileFields.Inode), nil
	case "utimes.file.mode":
		return int(event.Utimes.File.FileFields.Mode), nil
	case "utimes.file.modification_time":
		return int(event.Utimes.File.FileFields.MTime), nil
	case "utimes.file.mount_id":
		return int(event.Utimes.File.FileFields.MountID), nil
	case "utimes.file.name":
		return event.Utimes.File.BasenameStr, nil
	case "utimes.file.path":
		return event.Utimes.File.PathnameStr, nil
	case "utimes.file.rights":
		return int(event.Utimes.File.FileFields.Mode), nil
	case "utimes.file.uid":
		return int(event.Utimes.File.FileFields.UID), nil
	case "utimes.file.user":
		return event.Utimes.File.FileFields.User, nil
	case "utimes.retval":
		return int(event.Utimes.SyscallEvent.Retval), nil
	}
	return nil, &eval.ErrFieldNotFound{Field: field}
}
