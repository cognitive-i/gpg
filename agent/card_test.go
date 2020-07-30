package agent

import (
	"fmt"
	. "github.com/onsi/gomega"
	"strconv"
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


func parseTags(data []byte) {
	for p := 0; p < len(data); {
		record := data[p:]
		tag := record[0]
		length, _ := strconv.Atoi(string(record[2:4]))
		value := string(record[4:4 + (length * 3)])
		fmt.Printf("0x%02x %d %v\n", tag, length, value)
		p = (length * 2) + 5 + p
	}
}


// implement plus percent unescape


func TestCard_CardscanIgnoresKdfFactoryReset(t *testing.T) {
	// OpenPGP Smart Card V3.3 supports
	// https://gnupg.org/ftp/specs/OpenPGP-smart-card-application-3.4.1.pdf
	// 4.3.2 Key derived format

	// from a ZeitControl cardsystems GmbH: OpenPGP smart card
	data := []byte{
		0x4b, 0x44, 0x46, 0x20, // "KDF "
		0x81, 0x25, 0x30, 0x31, 0x25, 0x30, 0x30,
	}

	parseTags(data[4:])

	card, err := commonTestParse(t, string(data))

	Expect(err).To(BeNil())
	Expect(card.KeyDerivedFormat).To(BeTrue())
}

func TestCard_CardscanIgnoresKdfConfigured(t *testing.T) {
	// OpenPGP Smart Card V3.3 supports
	// https://gnupg.org/ftp/specs/OpenPGP-smart-card-application-3.4.1.pdf
	// 4.3.2 Key derived format

	// from a ZeitControl cardsystems GmbH: OpenPGP smart card
	data := []byte{
		0x4b, 0x44, 0x46, 0x20,  // "KDF "
		0x81, 0x25, 0x30, 0x31, 0x25, 0x30, 0x33, // KDF algorithm byte
		0x82, 0x25, 0x30, 0x31, 0x25, 0x30, 0x38, // hash algorithm byte
		0x83, 0x25, 0x30, 0x34, 0x25, 0x30, 0x32, 0x2b, 0x25, 0x30, 0x30, 0x25, 0x30, 0x30, // iteration count
		0x84, 0x25, 0x30, 0x38, 0xb4, 0xc4, 0xa0, 0xb4, 0x28, 0xe0, 0xd2, 0x46, // salt for PW1
		0x85, 0x25, 0x30, 0x38, 0x33, 0x4b, 0x73, 0x32, 0xce, 0x2b, 0xf9, 0x25, 0x31, 0x36, // salt for resetting PW1
		0x86, 0x25, 0x30, 0x38, 0x51, 0x36, 0x4d, 0x9b, 0x5e, 0x48, 0x74, 0x25, 0x30, 0x41, // salt for admin PW3
		0x87, 0x2b, 0x3b, 0x9f, 0xd1, 0xe0, 0xb5, 0xb9, 0x89, 0x2d, 0x78, 0xd8, 0x25, 0x31, 0x33, 0x25, 0x30, 0x39, 0x37, 0xed, 0x7f, 0xa6, 0x32, 0xa3, 0xae, 0x83, 0x79, 0xb6, 0xb9, 0x25, 0x31, 0x42, 0x79, 0x5a, 0x74, 0x33, 0x55, 0xa7, 0x51, 0xfe,
		0x88, 0x2b, 0xce, 0x79, 0xfb, 0x44, 0x25, 0x30, 0x41, 0x25, 0x31, 0x31, 0xea, 0xbc, 0xb3, 0x3d, 0x3c, 0x25, 0x30, 0x35, 0x59, 0xc9, 0xde, 0x41, 0x63, 0x25, 0x30, 0x41, 0xbf, 0x2f, 0x85, 0x3f, 0x25, 0x30, 0x41, 0x32, 0x79, 0xe1, 0xac, 0x7d, 0x54, 0xc7, 0x2b, 0x34,
	}

	//parseTags(data[4:])

	card, err := commonTestParse(t, string(data))

	Expect(err).To(BeNil())
	Expect(card.KeyDerivedFormat).To(BeTrue())
}

const bla = `
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
