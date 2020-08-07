package agent

import (
	"bytes"
	"golang.org/x/crypto/openpgp/s2k"
)

type KdfCollection struct {
	Pw1      *Kdf
	Pw1Reset *Kdf
	Pw3      *Kdf
}

type Kdf struct {
	HashPassword func(password string) []byte
}

func NewKdf(algorithm, hashAlgorithm, salt []byte, iterationCount byte) *Kdf {
	if (len(algorithm) != 1) || (len(hashAlgorithm) != 1) || (len(salt) == 0) {
		return nil
	}

	var buffer []byte = nil
	buffer = append(buffer, algorithm...)
	buffer = append(buffer, hashAlgorithm...)
	buffer = append(buffer, salt...)
	buffer = append(buffer, iterationCount)

	if hash, ok := s2k.HashIdToHash(hashAlgorithm[0]); ok {
		digestLength := hash.Size()

		if pwHasher, err := s2k.Parse(bytes.NewBuffer(buffer)); err == nil {
			return &Kdf{
				HashPassword: func(password string) []byte {
					result := make([]byte, digestLength, digestLength)
					pwHasher(result, []byte(password))
					return result
				},
			}
		}
	}
	return nil
}

func NewKdfCollection(tags map[byte][]byte) KdfCollection {
	var result KdfCollection
	if iteration, ok := tags[0x83]; ok && len(iteration) == 4 {
		iterationCount := encodeCountFromByte(iteration)

		algorithm := tags[0x81]
		hash := tags[0x82]

		saltPw1 := tags[0x84]
		saltResetPw1 := tags[0x85]
		saltPw3 := tags[0x86]

		result.Pw1 = NewKdf(algorithm, hash, saltPw1, iterationCount)
		result.Pw1Reset = NewKdf(algorithm, hash, saltResetPw1, iterationCount)
		result.Pw3 = NewKdf(algorithm, hash, saltPw3, iterationCount)
	}

	return result
}

func encodeCountFromByte(iterationCount []byte) uint8 {
	iteration := 0
	for _, b := range iterationCount {
		iteration = (iteration << 8) | int(b)
	}

	return encodeCount(iteration)
}

// borrowed from golang.org/x/crypto/openpgp/s2k/s2k.go
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

// borrowed from golang.org/x/crypto/openpgp/s2k/s2k.go
// decodeCount returns the s2k mode 3 iterative "count" corresponding to
// the encoded octet c.
func decodeCount(c uint8) int {
	return (16 + int(c&15)) << (uint32(c>>4) + 6)
}
