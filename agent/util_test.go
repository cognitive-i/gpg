package agent

import (
	. "github.com/onsi/gomega"
	"testing"
)

func TestUtil_DecodePlainText(t *testing.T) {
	RegisterTestingT(t)

	input := "this should be unchanged"
	Expect(decode(input)).To(Equal(input))
}

func TestUtil_DecodeUsualEscapees(t *testing.T) {
	RegisterTestingT(t)

	input := "this shouldn't%25be%0Dunchanged%0A"
	output := "this shouldn't%be\runchanged\n"
	Expect(decode(input)).To(Equal(output))
}

func TestUtil_DecodeDataEscapes(t *testing.T) {
	RegisterTestingT(t)

	input := "%31%32%33%34"
	output := "1234"
	Expect(decode(input)).To(Equal(output))
}

func TestUtil_DecodeSpaces(t *testing.T) {
	RegisterTestingT(t)

	input := "[+%2b+%2b+]"
	output := "[ + + ]"
	Expect(decodeWithPlus(input)).To(Equal(output))
}

func TestUtil_EncodePlainText(t *testing.T) {
	RegisterTestingT(t)

	input := "this should be unchanged"
	Expect(encode(input)).To(Equal(input))
}

func TestUtil_EncodeUsualEscapees(t *testing.T) {
	RegisterTestingT(t)

	input := "this shouldn't%be\runchanged\n"
	output := "this shouldn't%25be%0Dunchanged%0A"
	Expect(encode(input)).To(Equal(output))
}

func TestUtil_EncodeDataEscapes(t *testing.T) {
	RegisterTestingT(t)

	input := "[ + 1 ]"
	output := "[+%2B+1+]"
	Expect(encodeWithPlus(input)).To(Equal(output))
}

func TestUtil_ParseCaps(t *testing.T) {
	RegisterTestingT(t)

	caps := parseCaps("gc=1+ki=1+fc=1+pd=1+mcl3=2560+aac=1+sm=0+si=0+dec=1+bt=0+kdf=0")
	Expect(caps).To(HaveKeyWithValue("fc", "1"))
	Expect(caps).To(HaveKeyWithValue("mcl3", "2560"))
	Expect(caps).To(HaveKeyWithValue("kdf", "0"))

	caps = parseCaps("")
	Expect(caps).To(HaveLen(0))

	caps = parseCaps("gc=1=3=4=")
	Expect(caps).To(HaveKeyWithValue("gc", "1"))

	caps = parseCaps("gc=")
	Expect(caps).To(HaveKeyWithValue("gc", ""))

	caps = parseCaps("gc+pd=5")
	Expect(caps).To(HaveLen(1))
	Expect(caps).To(HaveKeyWithValue("pd", "5"))
}
