package agent

import (
	"fmt"
	"regexp"
	"strconv"
	"strings"
	"time"
)

// CardKey describes the information gpg-agent exposes about a card key
type CardKey struct {
	Key

	Created time.Time
}

// CardSex describes the sex specified on the card.
type CardSex int

// These constants define the possible CardSex values.
const (
	CardSexUnspecified CardSex = 0
	CardSexMale                = 1
	CardSexFemale              = 2
)

// Card describes the information gpg-agent exposes about a card
type Card struct {
	Reader  string
	Serial  string
	AppType string
	ExtCap  string

	LoginData       string
	DisplayName     string
	DisplayLanguage string
	DisplaySex      CardSex
	PubkeyURL       string

	SignatureCounter   int
	SignaturePINCached bool
	MaxPINLength       [cardMaxKeyNumber]int
	PINRetryCounter    [cardMaxKeyNumber]int

	Subkeys [cardMaxKeyNumber]*CardKey

	conn *Conn
}

// The IDs of the different subkeys
const (
	SignatureKey = iota
	EncryptionKey
	AuthenticationKey
	cardMaxKeyNumber
)

var errIllegalFormat = "illegal format for %s line"

var cardOpenGPGIndex = regexp.MustCompile("^OPENPGP.([0-9]+)$")

// CurrentCard returns the currently connected smartcard, including its subkeys
func (conn *Conn) CurrentCard() (*Card, error) {
	var card Card
	card.conn = conn

	respFunc := func(respType, data string) error {
		if respType != "S" {
			return nil
		}

		return cardScan(&card, data)
	}

	conn.mu.Lock()
	defer conn.mu.Unlock()

	err := conn.Raw(respFunc, "LEARN --sendinfo --ssh-fpr")
	if err != nil {
		return nil, err
	}

	for _, key := range card.Subkeys {
		if key == nil {
			continue
		}
		key.Key, err = card.conn.key(key.Keygrip)
		if err != nil {
			return nil, err
		}
	}

	return &card, nil
}

// SignatureKey returns the card signature key (or nil if it's missing)
func (card *Card) SignatureKey() *CardKey {
	return card.Subkeys[SignatureKey]
}

// EncryptionKey returns the card encryption key (or nil if it's missing)
func (card *Card) EncryptionKey() *CardKey {
	return card.Subkeys[EncryptionKey]
}

// AuthenticationKey returns the card authentication key (or nil if it's missing)
func (card *Card) AuthenticationKey() *CardKey {
	return card.Subkeys[AuthenticationKey]
}

func cardEnsureKey(card *Card, n int) (*CardKey, error) {
	if n > cardMaxKeyNumber {
		return nil, fmt.Errorf("card only supports a maximum of %d subkeys (%d were given)", cardMaxKeyNumber, n)
	}
	index := n - 1
	if card.Subkeys[index] != nil {
		return card.Subkeys[index], nil
	}
	key := &CardKey{}
	card.Subkeys[index] = key
	return key, nil
}

func cardScan(card *Card, line string) error {
	parts := strings.Fields(strings.TrimSpace(line))
	switch parts[0] {
	case "SIG-COUNTER":
		if len(parts) != 2 {
			return fmt.Errorf(errIllegalFormat, parts[0])
		}
		v, err := strconv.ParseInt(parts[1], 10, 32)
		if err != nil {
			return err
		}
		card.SignatureCounter = int(v)
	case "CHV-STATUS":
		if len(parts) != 2 {
			return fmt.Errorf(errIllegalFormat, parts[0])
		}
		pieces := strings.Split(parts[1], "+")
		if len(pieces) != 8 {
			return fmt.Errorf(errIllegalFormat, parts[0])
		}
		card.SignaturePINCached = pieces[1] == "1"
		for i := 0; i < cardMaxKeyNumber; i++ {
			v, err := strconv.ParseInt(pieces[2+i], 10, 32)
			if err != nil {
				return err
			}
			card.MaxPINLength[i] = int(v)
		}
		for i := 0; i < cardMaxKeyNumber; i++ {
			v, err := strconv.ParseInt(pieces[5+i], 10, 32)
			if err != nil {
				return err
			}
			card.PINRetryCounter[i] = int(v)
		}
	case "KEY-TIME":
		if len(parts) != 3 {
			return fmt.Errorf(errIllegalFormat, parts[0])
		}
		idx, err := strconv.ParseInt(parts[1], 10, 32)
		if err != nil {
			return err
		}
		ts, err := strconv.ParseInt(parts[2], 10, 64)
		if err != nil {
			return err
		}
		key, err := cardEnsureKey(card, int(idx))
		if err != nil {
			return err
		}
		key.Created = time.Unix(ts, 0)
	case "KEY-FPR":
		if len(parts) != 3 {
			return fmt.Errorf(errIllegalFormat, parts[0])
		}
		idx, err := strconv.ParseInt(parts[1], 10, 32)
		if err != nil {
			return err
		}
		key, err := cardEnsureKey(card, int(idx))
		if err != nil {
			return err
		}
		key.Fingerprint = parts[2]
	case "LOGIN-DATA":
		if len(parts) != 2 {
			return fmt.Errorf(errIllegalFormat, parts[0])
		}
		card.LoginData = parts[1]
	case "DISP-LANG":
		if len(parts) != 2 {
			return fmt.Errorf(errIllegalFormat, parts[0])
		}
		card.DisplayLanguage = parts[1]
	case "DISP-SEX":
		if len(parts) != 2 {
			return fmt.Errorf(errIllegalFormat, parts[0])
		}
		card.DisplaySex = CardSexUnspecified
		switch parts[1] {
		case "1":
			card.DisplaySex = CardSexMale
		case "2":
			card.DisplaySex = CardSexFemale
		}
	case "DISP-NAME":
		if len(parts) != 2 {
			return fmt.Errorf(errIllegalFormat, parts[0])
		}
		card.DisplayName = strings.Replace(strings.Replace(parts[1], ">>", " ", -1), ">", " ", -1)
	case "PUBKEY-URL":
		if len(parts) != 2 {
			return fmt.Errorf(errIllegalFormat, parts[0])
		}
		card.PubkeyURL = parts[1]
	case "EXTCAP":
		if len(parts) != 2 {
			return fmt.Errorf(errIllegalFormat, parts[0])
		}
		card.ExtCap = parts[1]
	case "APPTYPE":
		if len(parts) != 2 {
			return fmt.Errorf(errIllegalFormat, parts[0])
		}
		card.AppType = parts[1]
	case "SERIALNO":
		if len(parts) != 2 {
			return fmt.Errorf(errIllegalFormat, parts[0])
		}
		card.Serial = parts[1]
	case "READER":
		if len(parts) < 2 {
			return fmt.Errorf(errIllegalFormat, parts[0])
		}
		card.Reader = strings.Join(parts[1:], " ")
	case "KEYPAIRINFO":
		if len(parts) != 3 {
			return fmt.Errorf(errIllegalFormat, parts[0])
		}
		matches := cardOpenGPGIndex.FindStringSubmatch(parts[2])
		if matches == nil || len(matches) != 2 {
			return fmt.Errorf(errIllegalFormat, parts[0])
		}
		idx, err := strconv.ParseInt(matches[1], 10, 32)
		if err != nil {
			return err
		}
		key, err := cardEnsureKey(card, int(idx))
		if err != nil {
			return err
		}
		key.Keygrip = parts[1]
	case "PROGRESS":
	default:
		return fmt.Errorf("unknown property %s in %s", parts[0], line)
	}

	return nil
}
