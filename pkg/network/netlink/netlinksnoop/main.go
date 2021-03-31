package main

import (
	"fmt"
	"log"
	"os"
	"os/signal"
	"strconv"
	"syscall"
	"unsafe"

	"github.com/mdlayher/netlink"

	"github.com/DataDog/datadog-agent/pkg/ebpf"
	"github.com/DataDog/ebpf/manager"
)

func main() {
	err := run()
	if err != nil {
		log.Fatal(err)
	}
}

func run() error {
	if len(os.Args) < 2 {
		return fmt.Errorf("invalid arguments")
	}
	pid, err := strconv.Atoi(os.Args[1])
	if err != nil {
		return fmt.Errorf("invalid PID")
	}

	buf, err := getRuntimeCompiledNetlinkSnoop(pid)
	if err != nil {
		return fmt.Errorf("unable to compile ebpf netlink snoop: %w", err)
	}

	msgHandler := ebpf.NewPerfHandler(100)
	defer msgHandler.Stop()

	m, err := getManager(buf, msgHandler)
	if err != nil {
		return err
	}
	defer m.Stop(manager.CleanAll)

	pm, found := m.GetPerfMap("nlmsgs")
	if !found {
		return fmt.Errorf("unable to find perf map")
	}

	err = pm.Start()
	if err != nil {
		return fmt.Errorf("failure starting perf map polling")
	}
	defer pm.Stop(manager.CleanAll)

	go func() {
		for {
			select {
			case msg, ok := <-msgHandler.DataChannel:
				if !ok {
					return
				}

				raw, err := syscall.ParseNetlinkMessage(msg.Data)
				if err != nil {
					log.Printf("error parsing netlink msg: %s\n", err)
					continue
				}

				msgs := make([]netlink.Message, 0, len(raw))
				for _, r := range raw {
					m := netlink.Message{
						Header: sysToHeader(r.Header),
						Data:   r.Data,
					}

					msgs = append(msgs, m)
				}

				ev := new(Event)
				err = ev.unmarshal(msgs[0])
				if err != nil {
					log.Printf("error unmarshaling netlink msg: %s\n", err)
					continue
				}

				log.Println(ev)

			case lostMsg, ok := <-msgHandler.LostChannel:
				if !ok {
					return
				}
				log.Printf("lost %d messages\n", lostMsg)
			}
		}
	}()

	err = m.Start()
	if err != nil {
		return fmt.Errorf("failed to start netlink snoop: %w", err)
	}

	c := make(chan os.Signal, 1)
	signal.Notify(c, os.Interrupt)
	<-c

	return nil
}

// sysToHeader converts a syscall.NlMsghdr to a Header.
func sysToHeader(r syscall.NlMsghdr) netlink.Header {
	// NB: the memory layout of Header and syscall.NlMsgHdr must be
	// exactly the same for this unsafe cast to work
	return *(*netlink.Header)(unsafe.Pointer(&r))
}
