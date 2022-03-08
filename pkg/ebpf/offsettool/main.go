package main

import (
	"context"
	"fmt"
	"io/ioutil"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"text/template"

	"golang.org/x/sync/errgroup"
)

const cFileTmpl = `
#include <stddef.h>
#include <stdio.h>
#include <linux/kconfig.h>
{{range .Includes}}
#include <{{.}}>
{{end}}

int main(void) {
  printf("%zu", offsetof(struct {{ .StructName }}, {{ .FieldName }}));
  return 0;
}
`

const gitRepo = "https://github.com/torvalds/linux"

var versions = []string{"4.4"}
var ct *template.Template

type OffsetSearch struct {
	Includes   []string
	StructName string
	FieldName  string
}

func init() {
	var err error
	ct, err = template.New("c").Parse(cFileTmpl)
	if err != nil {
		panic(err)
	}
}

func main() {
	if err := run(); err != nil {
		fmt.Fprintf(os.Stderr, "%s\n", err)
		os.Exit(1)
	}
}

func run() error {
	s := OffsetSearch{
		Includes:   []string{"linux/net.h"},
		StructName: "socket",
		FieldName:  "sk",
	}
	cFile, err := writeTemplate(s)
	if err != nil {
		return fmt.Errorf("tmpl: %s", err)
	}
	defer func() { _ = os.Remove(cFile) }()

	offsets := make(map[string]string)
	g, _ := errgroup.WithContext(context.Background())
	for _, v := range versions {
		g.Go(func() error {
			fmt.Fprintf(os.Stderr, "cloning %s...\n", v)
			dir, err := clone(v)
			if err != nil {
				return fmt.Errorf("clone %s: %s", v, err)
			}
			defer func() { _ = os.RemoveAll(dir) }()

			fmt.Fprintf(os.Stderr, "compiling %s...\n", v)
			exe, err := compile(cFile, dir)
			if err != nil {
				return fmt.Errorf("compile %s: %s", v, err)
			}

			fmt.Fprintf(os.Stderr, "executing %s...\n", v)
			offset, err := execute(exe)
			if err != nil {
				return fmt.Errorf("execute %s: %s", v, err)
			}

			offsets[v] = string(offset)
			fmt.Fprintf(os.Stderr, "%s\t%s\n", v, offsets[v])
			_ = os.RemoveAll(dir)
			return nil
		})
	}

	if err := g.Wait(); err != nil {
		return err
	}

	fmt.Printf("(struct %s)->%s %s\n", s.StructName, s.FieldName, runtime.GOARCH)
	fmt.Println("========")
	for v, o := range offsets {
		fmt.Printf("%s\t%s\n", v, o)
	}
	return nil
}

func execute(exe string) ([]byte, error) {
	return exec.Command(exe).Output()
}

func includeDirs(d string) []string {
	arch := "x86"
	return []string{
		fmt.Sprintf("-isystem%s/arch/%s/include", d, arch),
		fmt.Sprintf("-isystem%s/arch/%s/include/generated", d, arch),
		fmt.Sprintf("-isystem%s/include", d),
		fmt.Sprintf("-isystem%s/arch/%s/include/uapi", d, arch),
		fmt.Sprintf("-isystem%s/arch/%s/include/generated/uapi", d, arch),
		fmt.Sprintf("-isystem%s/include/uapi", d),
		fmt.Sprintf("-isystem%s/include/generated/uapi", d),
	}
}

func compile(cFile string, includeDir string) (string, error) {
	exeFile := strings.TrimSuffix(cFile, filepath.Ext(cFile))
	args := includeDirs(includeDir)
	args = append(args, cFile, "-o", exeFile)
	cmd := exec.Command("clang", args...)
	if out, err := cmd.CombinedOutput(); err != nil {
		return "", fmt.Errorf("clang: %s", out)
	}
	return exeFile, nil
}

func writeTemplate(s OffsetSearch) (string, error) {
	tf, err := ioutil.TempFile("", "*.c")
	if err != nil {
		return "", fmt.Errorf("temp file: %s", err)
	}

	err = ct.Execute(tf, s)
	if err != nil {
		_ = os.Remove(tf.Name())
		return "", fmt.Errorf("exec: %s", err)
	}
	if err := tf.Close(); err != nil {
		_ = os.Remove(tf.Name())
		return "", fmt.Errorf("close: %s", err)
	}
	return tf.Name(), nil
}

func clone(version string) (string, error) {
	dirName := fmt.Sprintf("linux%s", version)
	dir, err := filepath.Abs(dirName)
	if err != nil {
		return "", fmt.Errorf("dir abs: %w", err)
	}

	tag := fmt.Sprintf("v%s", version)
	cmds := []struct {
		Dir string
		Cmd string
	}{
		{Cmd: fmt.Sprintf("git clone -b %s --depth 1 --no-checkout %s %s", tag, gitRepo, dirName)},
		{Dir: dir, Cmd: "git sparse-checkout init --cone"},
		{Dir: dir, Cmd: "git sparse-checkout set include"},
	}
	for _, c := range cmds {
		parts := strings.Split(c.Cmd, " ")
		cmd := exec.Command(parts[0], parts[1:]...)
		cmd.Dir = c.Dir
		err = cmd.Run()
		if err != nil {
			_ = os.RemoveAll(dir)
			return "", fmt.Errorf("%s: %w", c, err)
		}
	}
	return dir, nil
}
