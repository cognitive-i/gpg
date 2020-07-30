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
