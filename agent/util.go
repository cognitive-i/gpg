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
