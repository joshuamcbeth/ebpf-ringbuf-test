package main

import (
	"bytes"
	"encoding/binary"
	"fmt"
	"log"
	"os"
	"os/signal"

	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/link"
	"github.com/cilium/ebpf/ringbuf"
)

const (
	fileNameLen = 256
	taskCommLen = 256
)

type event struct {
	EPid      uint32
	EFilename [fileNameLen]byte
	EComm     [taskCommLen]byte
}

func main() {

	spec, err := ebpf.LoadCollectionSpec("trace.bpf.o")
	if err != nil {
		log.Fatalf("loading spec: %v", err)
	}

	coll, err := ebpf.NewCollection(spec)
	if err != nil {
		log.Fatalf("creating collection: %v", err)
	}
	defer coll.Close()

	prog := coll.Programs["kprobe__do_sys_openat2"]
	if prog == nil {
		log.Fatalf("program not found")
	}

	kp, err := link.Kprobe("do_sys_openat2", prog, nil)
	if err != nil {
		log.Fatalf("attaching kprobe: %v", err)
	}
	defer kp.Close()

	rb, found := coll.Maps["rb"]
	if !found {
		log.Fatalf("ring buffer map not found")
	}

	reader, err := ringbuf.NewReader(rb)
	if err != nil {
		log.Fatalf("creating ringbuf reader: %v", err)
	}
	defer reader.Close()

	log.Println("Waiting for events... Press Ctrl+C to exit.")

	sig := make(chan os.Signal, 1)
	signal.Notify(sig, os.Interrupt)

	go func() {
		for {
			record, err := reader.Read()
			if err != nil {
				if err == ringbuf.ErrClosed {
					return
				}
				log.Printf("reading ringbuf: %v", err)
				break
			}

			var evt event
			if err := binary.Read(bytes.NewBuffer(record.RawSample), binary.LittleEndian, &evt); err != nil {
				log.Printf("decoding event: %v", err)
				continue
			}

			fmt.Printf("PID: %d COMM: %s FILE: %s\n",
				evt.EPid,
				string(evt.EComm[:bytes.Index(evt.EComm[:], []byte("\x00"))]),
				string(evt.EFilename[:bytes.Index(evt.EFilename[:], []byte("\x00"))]))
		}
	}()

	<-sig
	log.Println("Exiting.")
}
