package agent

import (
	. "github.com/onsi/gomega"
	"testing"
)

func commonTestParse(t *testing.T, data string) (card *Card, err error) {
	RegisterTestingT(t)
	card = &Card{}
	err = cardScan(card, data)
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

func TestCard_CardscanIgnoresKdfFactoryReset(t *testing.T) {
	RegisterTestingT(t)

	// OpenPGP Smart Card V3.3 supports
	// https://gnupg.org/ftp/specs/OpenPGP-smart-card-application-3.4.1.pdf
	// 4.3.2 Key derived format

	// from a ZeitControl cardsystems GmbH: OpenPGP smart card
	data := string([]byte{
		0x4b, 0x44, 0x46, 0x20, // "KDF "
		0x81, 0x25, 0x30, 0x31, 0x25, 0x30, 0x30,
	})

	card, err := commonTestParse(t, data)

	Expect(err).To(BeNil())
	Expect(card.KeyDerivedFormat.Pw1).To(BeNil())
	Expect(card.KeyDerivedFormat.Pw1Reset).To(BeNil())
	Expect(card.KeyDerivedFormat.Pw3).To(BeNil())
}

func TestCard_CardscanIgnoresKdfConfigured(t *testing.T) {
	RegisterTestingT(t)

	// OpenPGP Smart Card V3.3 supports
	// https://gnupg.org/ftp/specs/OpenPGP-smart-card-application-3.4.1.pdf
	// 4.3.2 Key derived format

	// from a ZeitControl cardsystems GmbH: OpenPGP smart card
	data := string([]byte{
		0x4b, 0x44, 0x46, 0x20, // "KDF "
		0x81, 0x25, 0x30, 0x31, 0x25, 0x30, 0x33, // KDF algorithm byte
		0x82, 0x25, 0x30, 0x31, 0x25, 0x30, 0x38, // hash algorithm byte
		0x83, 0x25, 0x30, 0x34, 0x25, 0x30, 0x32, 0x2b, 0x25, 0x30, 0x30, 0x25, 0x30, 0x30, // iteration count
		0x84, 0x25, 0x30, 0x38, 0xb4, 0xc4, 0xa0, 0xb4, 0x28, 0xe0, 0xd2, 0x46, // salt for PW1
		0x85, 0x25, 0x30, 0x38, 0x33, 0x4b, 0x73, 0x32, 0xce, 0x2b, 0xf9, 0x25, 0x31, 0x36, // salt for resetting PW1
		0x86, 0x25, 0x30, 0x38, 0x51, 0x36, 0x4d, 0x9b, 0x5e, 0x48, 0x74, 0x25, 0x30, 0x41, // salt for admin PW3
		0x87, 0x2b, 0x3b, 0x9f, 0xd1, 0xe0, 0xb5, 0xb9, 0x89, 0x2d, 0x78, 0xd8, 0x25, 0x31, 0x33, 0x25, 0x30, 0x39, 0x37, 0xed, 0x7f, 0xa6, 0x32, 0xa3, 0xae, 0x83, 0x79, 0xb6, 0xb9, 0x25, 0x31, 0x42, 0x79, 0x5a, 0x74, 0x33, 0x55, 0xa7, 0x51, 0xfe,
		0x88, 0x2b, 0xce, 0x79, 0xfb, 0x44, 0x25, 0x30, 0x41, 0x25, 0x31, 0x31, 0xea, 0xbc, 0xb3, 0x3d, 0x3c, 0x25, 0x30, 0x35, 0x59, 0xc9, 0xde, 0x41, 0x63, 0x25, 0x30, 0x41, 0xbf, 0x2f, 0x85, 0x3f, 0x25, 0x30, 0x41, 0x32, 0x79, 0xe1, 0xac, 0x7d, 0x54, 0xc7, 0x2b, 0x34,
	})

	card, err := commonTestParse(t, data)

	Expect(err).To(BeNil())
	Expect(card.KeyDerivedFormat.Pw1).ToNot(BeNil())
	Expect(card.KeyDerivedFormat.Pw1Reset).ToNot(BeNil())
	Expect(card.KeyDerivedFormat.Pw3).ToNot(BeNil())

	tags := parseTags(decodeWithPlus(data), 4)
	Expect(card.KeyDerivedFormat.Pw1.HashPassword("123456")).To(Equal(tags[0x87]))
	Expect(card.KeyDerivedFormat.Pw3.HashPassword("12345678")).To(Equal(tags[0x88]))
}

func TestCard_CardscanParseKdfTags(t *testing.T) {
	RegisterTestingT(t)

	// OpenPGP Smart Card V3.3 supports
	// https://gnupg.org/ftp/specs/OpenPGP-smart-card-application-3.4.1.pdf
	// 4.3.2 Key derived format

	// from a ZeitControl cardsystems GmbH: OpenPGP smart card
	data := string([]byte{
		0x4b, 0x44, 0x46, 0x20, // "KDF "
		0x81, 0x25, 0x30, 0x31, 0x25, 0x30, 0x33, // KDF algorithm byte
		0x82, 0x25, 0x30, 0x31, 0x25, 0x30, 0x38, // hash algorithm byte
		0x83, 0x25, 0x30, 0x34, 0x25, 0x30, 0x32, 0x2b, 0x25, 0x30, 0x30, 0x25, 0x30, 0x30, // iteration count
		0x84, 0x25, 0x30, 0x38, 0xb4, 0xc4, 0xa0, 0xb4, 0x28, 0xe0, 0xd2, 0x46, // salt for PW1
		0x85, 0x25, 0x30, 0x38, 0x33, 0x4b, 0x73, 0x32, 0xce, 0x2b, 0xf9, 0x25, 0x31, 0x36, // salt for resetting PW1
		0x86, 0x25, 0x30, 0x38, 0x51, 0x36, 0x4d, 0x9b, 0x5e, 0x48, 0x74, 0x25, 0x30, 0x41, // salt for admin PW3
		0x87, 0x2b, 0x3b, 0x9f, 0xd1, 0xe0, 0xb5, 0xb9, 0x89, 0x2d, 0x78, 0xd8, 0x25, 0x31, 0x33, 0x25, 0x30, 0x39, 0x37, 0xed, 0x7f, 0xa6, 0x32, 0xa3, 0xae, 0x83, 0x79, 0xb6, 0xb9, 0x25, 0x31, 0x42, 0x79, 0x5a, 0x74, 0x33, 0x55, 0xa7, 0x51, 0xfe,
		0x88, 0x2b, 0xce, 0x79, 0xfb, 0x44, 0x25, 0x30, 0x41, 0x25, 0x31, 0x31, 0xea, 0xbc, 0xb3, 0x3d, 0x3c, 0x25, 0x30, 0x35, 0x59, 0xc9, 0xde, 0x41, 0x63, 0x25, 0x30, 0x41, 0xbf, 0x2f, 0x85, 0x3f, 0x25, 0x30, 0x41, 0x32, 0x79, 0xe1, 0xac, 0x7d, 0x54, 0xc7, 0x2b, 0x34,
	})

	tags := parseTags(decodeWithPlus(data), 4)

	kdf := NewKdfCollection(tags)
	Expect(kdf.Pw1).ToNot(BeNil())
	Expect(kdf.Pw1Reset).ToNot(BeNil())
	Expect(kdf.Pw3).ToNot(BeNil())

	Expect(kdf.Pw1.HashPassword("123456")).To(Equal(tags[0x87]))
	Expect(kdf.Pw3.HashPassword("12345678")).To(Equal(tags[0x88]))
}

func TestCard_CardscanUnsupportedField(t *testing.T) {
	_, err := commonTestParse(t, "GIBBERISH 12345")
	Expect(err).ToNot(BeNil())
}
