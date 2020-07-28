package agent

import (
	"log"
	"net"
	"os"
	"os/exec"
	"path"
)

func connectClientToAgent(listener net.Listener) {
	var err error
	var conn net.Conn

	if conn, err = listener.Accept(); err == nil {
		var pwd string
		if pwd, err = os.Getwd(); err == nil {
			gnupgHome := path.Clean(path.Join(pwd, "..", "testdata", "gnupg"))

			cmd := exec.Command("gpg-agent", "--server", "--homedir", gnupgHome)
			cmd.Stdin = conn
			cmd.Stdout = conn
			// uncomment to see warnings from gpg-agent
			// cmd.Stderr = log.Writer()

			err = cmd.Run()
		}

		_ = listener.Close()
	}

	if err != nil {
		log.Fatalln("unable to start gpg-agent: ", err)
	}
}

func StartGpgAgent() (socketFilename string, err error) {
	var listener net.Listener
	listener, err = net.Listen("unix", "")

	if err != nil {
		return
	}

	socketFilename = listener.Addr().String()
	go connectClientToAgent(listener)

	return
}
