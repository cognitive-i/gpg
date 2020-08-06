package agent

import (
	"bytes"
	"fmt"
	. "github.com/onsi/gomega"
	"golang.org/x/crypto/openpgp/s2k"
	"io"
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

func parseTags(data string) map[byte][]byte {
	s := bytes.NewBufferString(data)
	result := map[byte][]byte{}

	for {
		if tag, err := s.ReadByte(); err == nil {
			if length, err := s.ReadByte(); err == nil {
				value := make([]byte, length)
				if n, _ := s.Read(value); n == int(length) {
					result[tag] = value
					continue
				}
			}
		}

		break
	}

	return result
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
	c := decodeWithPlus(data)
	parseTags(c[4:])

	card, err := commonTestParse(t, data)

	Expect(err).To(BeNil())
	Expect(card.KeyDerivedFormat).To(BeTrue())
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
	Expect(card.KeyDerivedFormat).To(BeTrue())
}

// golang.org/x/crypto/openpgp/s2k/s2k.go:70

// encodeCount converts an iterative "count" in the range 1024 to
// 65011712, inclusive, to an encoded count. The return value is the
// octet that is actually stored in the GPG file. encodeCount panics
// if i is not in the above range (encodedCount above takes care to
// pass i in the correct range). See RFC 4880 Section 3.7.7.1.
func encodeCount(i int) uint8 {
	if i < 1024 || i > 65011712 {
		panic("count arg i outside the required range")
	}

	for encoded := 0; encoded < 256; encoded++ {
		count := decodeCount(uint8(encoded))
		if count >= i {
			return uint8(encoded)
		}
	}

	return 255
}

// decodeCount returns the s2k mode 3 iterative "count" corresponding to
// the encoded octet c.
func decodeCount(c uint8) int {
	return (16 + int(c&15)) << (uint32(c>>4) + 6)
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

	c := decodeWithPlus(data)
	tags := parseTags(c[4:])

	var pw1Len, pw3Len, iteration = 0, 0, 0

	for t, v := range tags {
		d := "unknown"
		switch t {
		case 0x81:
			switch v[0] {
			case 0:
				d = "NONE"
			case 3:
				d = "KDF_ITERSALTED_S2K"
			}
			fmt.Println("KDF", d)

		case 0x82:
			n, ok := s2k.HashIdToString(v[0])
			fmt.Println("hash", n, ok)

		case 0x83:
			fmt.Println("iteration", v)
			Expect(v).To(HaveLen(4))
			for _, b := range v {
				iteration = (iteration << 8) | int(b)
			}

		case 0x84:
			fmt.Println("salt pw1")
		case 0x85:
			fmt.Println("reset salt pw1")
		case 0x86:
			fmt.Println("admin salt pw3")

		case 0x87:
			fmt.Println("initial hash pw1")
			pw1Len = len(v)

		case 0x88:
			fmt.Println("initial hash pw3")
			pw3Len = len(v)
		}
	}

	Expect(pw1Len).ToNot(Equal(0))
	Expect(pw3Len).ToNot(Equal(0))
	Expect(iteration).ToNot(Equal(0))

	iterationCount := encodeCount(iteration)

	s2kBuffer := io.MultiReader(
		bytes.NewBuffer(tags[0x81]), // golang.org/x/crypto/openpgp/s2k/s2k.go:173
		bytes.NewBuffer(tags[0x82]), // golang.org/x/crypto/openpgp/s2k/s2k.go:164
		bytes.NewBuffer(tags[0x84]), // golang.org/x/crypto/openpgp/s2k/s2k.go:189
		bytes.NewBuffer([]byte{iterationCount}),
	)

	pwHasher, err := s2k.Parse(s2kBuffer) // almost works, expects salt to be present, but iterated count seems wrong
	Expect(err).To(BeNil())

	pw1Hash := make([]byte, pw1Len, pw1Len)
	pwHasher(pw1Hash, []byte("123456"))

	Expect(pw1Hash).To(Equal(tags[0x87]))

	s2kBuffer = io.MultiReader(
		bytes.NewBuffer(tags[0x81]), // golang.org/x/crypto/openpgp/s2k/s2k.go:173
		bytes.NewBuffer(tags[0x82]), // golang.org/x/crypto/openpgp/s2k/s2k.go:164
		bytes.NewBuffer(tags[0x86]), // golang.org/x/crypto/openpgp/s2k/s2k.go:189
		bytes.NewBuffer([]byte{iterationCount}),
	)

	pwHasher, err = s2k.Parse(s2kBuffer) // almost works, expects salt to be present, but iterated count seems wrong
	Expect(err).To(BeNil())

	pw3Hash := make([]byte, pw3Len, pw3Len)
	pwHasher(pw3Hash, []byte("12345678"))

	Expect(pw3Hash).To(Equal(tags[0x88]))
}

const _ = `
#define S2K_DECODE_COUNT(_val) ((16ul + ((_val) & 15)) << (((_val) >> 4) + 6))



S2K_DECODE_COUNT 
* Generate KDF data.  */
static gpg_error_t
gen_kdf_data (unsigned char *data, int single_salt)
{
  const unsigned char h0[] = { 0x81, 0x01, 0x03,
                               0x82, 0x01, 0x08,
                               0x83, 0x04 };
  const unsigned char h1[] = { 0x84, 0x08 };
  const unsigned char h2[] = { 0x85, 0x08 };
  const unsigned char h3[] = { 0x86, 0x08 };
  const unsigned char h4[] = { 0x87, 0x20 };
  const unsigned char h5[] = { 0x88, 0x20 };
  unsigned char *p, *salt_user, *salt_admin;
  unsigned char s2k_char;
  unsigned int iterations;
  unsigned char count_4byte[4];
  gpg_error_t err = 0;

  p = data;

  s2k_char = encode_s2k_iterations (0);
  iterations = S2K_DECODE_COUNT (s2k_char);
  count_4byte[0] = (iterations >> 24) & 0xff;
  count_4byte[1] = (iterations >> 16) & 0xff;
  count_4byte[2] = (iterations >>  8) & 0xff;
  count_4byte[3] = (iterations & 0xff);

  memcpy (p, h0, sizeof h0);
  p += sizeof h0;
  memcpy (p, count_4byte, sizeof count_4byte);
  p += sizeof count_4byte;
  memcpy (p, h1, sizeof h1);
  salt_user = (p += sizeof h1);
  gcry_randomize (p, 8, GCRY_STRONG_RANDOM);
  p += 8;

  if (single_salt)
    salt_admin = salt_user;
  else
    {
      memcpy (p, h2, sizeof h2);
      p += sizeof h2;
      gcry_randomize (p, 8, GCRY_STRONG_RANDOM);
      p += 8;
      memcpy (p, h3, sizeof h3);
      salt_admin = (p += sizeof h3);
      gcry_randomize (p, 8, GCRY_STRONG_RANDOM);
      p += 8;
    }

  memcpy (p, h4, sizeof h4);
  p += sizeof h4;
  err = gcry_kdf_derive (USER_PIN_DEFAULT, strlen (USER_PIN_DEFAULT),
                         GCRY_KDF_ITERSALTED_S2K, DIGEST_ALGO_SHA256,
                         salt_user, 8, iterations, 32, p);
  p += 32;
  if (!err)
    {
      memcpy (p, h5, sizeof h5);
      p += sizeof h5;
      err = gcry_kdf_derive (ADMIN_PIN_DEFAULT, strlen (ADMIN_PIN_DEFAULT),
                             GCRY_KDF_ITERSALTED_S2K, DIGEST_ALGO_SHA256,
                             salt_admin, 8, iterations, 32, p);
    }

  return err;
}`

func TestCard_CardscanUnsupportedField(t *testing.T) {
	_, err := commonTestParse(t, "GIBBERISH 12345")
	Expect(err).ToNot(BeNil())
}
