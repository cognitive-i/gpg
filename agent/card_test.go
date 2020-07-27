package agent

import (
	. "github.com/onsi/gomega"
	"testing"
)

func commonTestParse(t *testing.T, data string) (card *Card, err error) {
	RegisterTestingT(t)
	card = &Card{}
	err = CardScan(card, data)
	return
}

func TestCard_CardscanSerialNumber(t *testing.T) {
	card, err := commonTestParse(t, "SERIALNO D2760001240103123C97E9170CD80000")
	Expect(err).To(BeNil())
	Expect(card.Serial).To(Equal("D2760001240103123C97E9170CD80000"))
}

func TestCard_CardscanSigCounter(t *testing.T) {
	card, err := commonTestParse(t, "SIG-COUNTER 6")
	Expect(err).To(BeNil())
	Expect(card.SignatureCounter).To(Equal(6))
}

func TestCard_CardscanKeyParameters(t *testing.T) {
	card, err := commonTestParse(t, "CHV-STATUS +1+12+13+9+3+1+2")
	Expect(err).To(BeNil())
	Expect(card.SignaturePINCached).To(BeTrue())
	Expect(card.MaxPINLength).To(Equal([3]int{12, 13, 9}))
	Expect(card.PINRetryCounter).To(Equal([3]int{3, 1, 2}))
}

func TestCard_CardscanSex(t *testing.T) {
	card, err := commonTestParse(t, "DISP-SEX 0")
	Expect(err).To(BeNil())
	Expect(card.DisplaySex).To(BeEquivalentTo(CardSexUnspecified))

	card, err = commonTestParse(t, "DISP-SEX 1")
	Expect(err).To(BeNil())
	Expect(card.DisplaySex).To(BeEquivalentTo(CardSexMale))

	card, err = commonTestParse(t, "DISP-SEX 2")
	Expect(err).To(BeNil())
	Expect(card.DisplaySex).To(BeEquivalentTo(CardSexFemale))

	card, err = commonTestParse(t, "DISP-SEX 9")
	Expect(err).To(BeNil())
	Expect(card.DisplaySex).To(BeEquivalentTo(CardSexNotApplicable))

	card, err = commonTestParse(t, "DISP-SEX 7")
	Expect(err).To(BeNil())
	Expect(card.DisplaySex).To(BeEquivalentTo(CardSexUnspecified))
}

func TestCard_CardscanReader(t *testing.T) {
	card, err := commonTestParse(t, "READER Ledger Nano S [Nano S] (0001) 00 00")
	Expect(err).To(BeNil())
	Expect(card.Reader).To(Equal("Ledger Nano S [Nano S] (0001) 00 00"))
}

func TestCard_CardscanAppType(t *testing.T) {
	card, err := commonTestParse(t, "APPTYPE OPENPGP")
	Expect(err).To(BeNil())
	Expect(card.AppType).To(Equal("OPENPGP"))
}

func TestCard_CardscanExtCaps(t *testing.T) {
	card, err := commonTestParse(t, "EXTCAP gc=1+ki=1+fc=1+pd=1+mcl3=2560+aac=1+sm=0+si=0+dec=1+bt=0+kdf=0")
	Expect(err).To(BeNil())
	Expect(card.ExtCap).To(Equal("gc=1+ki=1+fc=1+pd=1+mcl3=2560+aac=1+sm=0+si=0+dec=1+bt=0+kdf=0"))
}

func TestCard_CardscanIgnoresKDF(t *testing.T) {
	// OpenPGP Smart Card V3.3 supports
	// https://gnupg.org/ftp/specs/OpenPGP-smart-card-application-3.4.1.pdf
	// 4.3.2 Key derived format
	_, err := commonTestParse(t, "KDF �%01%00")
	Expect(err).To(BeNil())
}

func TestCard_CardscanUnsupportedField(t *testing.T) {
	_, err := commonTestParse(t, "GIBBERISH 12345")
	Expect(err).ToNot(BeNil())
}
