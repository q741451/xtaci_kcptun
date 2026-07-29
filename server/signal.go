// +build linux darwin freebsd

package main

import (
	"log"
	"os"
	"os/signal"
	"syscall"

	kcp "github.com/xtaci/kcp-go"
	"github.com/xtaci/kcptun/rawtcp"
)

func init() {
	go sigHandler()
}

func sigHandler() {
	ch := make(chan os.Signal, 1)
	signal.Notify(ch, syscall.SIGUSR1, os.Interrupt, syscall.SIGTERM, syscall.SIGHUP)
	signal.Ignore(syscall.SIGPIPE)

	for sig := range ch {
		switch sig {
		case syscall.SIGUSR1:
			log.Printf("KCP SNMP:%+v", kcp.DefaultSnmp.Copy())
		default:
			// SIGINT/SIGTERM/SIGHUP: release rawtcp's sockets before
			// exiting instead of letting process death do it implicitly.
			rawtcp.Cleanup()
			os.Exit(0)
		}
	}
}
