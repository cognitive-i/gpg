// +build integration

package agent

import (
	. "github.com/onsi/gomega"
	"log"
	"strings"
	"testing"
)

func commonConn(t *testing.T) *Conn {
	RegisterTestingT(t)

	options := []string{
		"allow-pinentry-notify",
		"agent-awareness=2.1.0",
	}

	// Contact user's GPG-agent to talk to connected smart card.
	// Testdata gpg-agent conf disables smart card connectivity as
	// SCD does not permit concurrent gpg-agent access.
	conn, err := Dial("", options)
	if err != nil {
		log.Fatalln("commonConn", err)
	}

	return conn
}

func TestConn_CurrentCard(t *testing.T) {
	conn := commonConn(t)

	card, err := conn.CurrentCard()
	Expect(err).To(BeNil(), "have you connected a smart card?")
	defer conn.Close()

	Expect(card.Reader).ToNot(BeEmpty())
	Expect(card.Serial).ToNot(BeEmpty())
	Expect(card.AppType).To(Equal("OPENPGP"))
}
func parseCaps(extCaps string) map[string]string {
	result := map[string]string{}
	for _, capTuple := range strings.Split(extCaps, "+") {
		pair := strings.Split(capTuple, "=")
		ExpectWithOffset(1, pair).To(HaveLen(2))
		result[pair[0]] = pair[1]
	}

	return result
}

func TestConn_IfHasKdf(t *testing.T) {
	// https://gnupg.org/ftp/specs/OpenPGP-smart-card-application-3.4.1.pdf
	// 4.3.2 Key derived format

	conn := commonConn(t)
	card, err := conn.CurrentCard()
	Expect(err).To(BeNil(), "have you connected a smart card?")
	defer conn.Close()

	// https://en.wikipedia.org/wiki/OpenPGP_card
	// Vendor IDs
	Expect(card.Serial).To(HaveLen(32))
	manufacturer := card.Serial[16:20]
	Expect(manufacturer).To(Equal("0005"), "expecting ZeitControl cardsystems GmbH")

	caps := parseCaps(card.ExtCap)
	Expect(caps["kdf"]).To(Equal("1"))
	Expect(card.KeyDerivedFormat).To(BeTrue())

	Expect(card.MaxPINLength).To(HaveLen(3))
	Expect(card.MaxPINLength[0]).To(BeNumerically(">=", 64))
	Expect(card.MaxPINLength[1]).To(BeNumerically(">=", 64))
	Expect(card.MaxPINLength[2]).To(BeNumerically(">=", 64))
}

