package agent

import (
	"bytes"
	"strconv"
	"strings"
)

var (
	decoderPlus = strings.NewReplacer("+", " ")
	encoderPlus = strings.NewReplacer(" ", "+", "+", "%2B")
	encoder     = strings.NewReplacer("%", "%25", "\r", "%0D", "\n", "%0A")
)

func decode(source string) string {
	result := bytes.NewBuffer(nil)
	length := len(source)

	for i := 0; i < length; {
		b := source[i]
		if b == '%' && (2 <= (length - i)) {
			v, _ := strconv.ParseUint(source[i+1:i+3], 16, 8)
			b = byte(v)
			i += 2
		}

		result.WriteByte(b)

		i++
	}

	return result.String()
}

func encode(source string) string {
	return encoder.Replace(source)
}

func decodeWithPlus(source string) string {
	return decode(decoderPlus.Replace(source))
}

func encodeWithPlus(source string) string {
	return encoderPlus.Replace(encode(source))
}

func parseCaps(extCaps string) map[string]string {
	result := map[string]string{}
	for _, capTuple := range strings.Split(extCaps, "+") {
		if pair := strings.Split(capTuple, "="); len(pair) >= 2 {
			result[pair[0]] = pair[1]
		}
	}

	return result
}

func parseTags(data string, skipBytes int) map[byte][]byte {
	s := bytes.NewBufferString(data[skipBytes:])
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
