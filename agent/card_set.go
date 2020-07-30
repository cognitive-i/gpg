package agent

import (
	"fmt"
	"strconv"
	"strings"
	"time"
)

func doInquire(conn *Conn) ResponseFunc {
	return func(respType, data string) error {
		if respType == "INQUIRE" {
			return conn.Raw(nil, "END")
		}
		return fmt.Errorf("unexpected: %v %v", respType, data)
	}
}

// SetDisplayName sets the display name on the given smart card
func (card *Card) SetDisplayName(name string) error {
	card.conn.mu.Lock()
	defer card.conn.mu.Unlock()

	return card.conn.Raw(doInquire(card.conn), "scd SETATTR DISP-NAME %v", name)
}

// SetDisplaySex sets the display sex on the given smart card
func (card *Card) SetDisplaySex(sex CardSex) error {
	card.conn.mu.Lock()
	defer card.conn.mu.Unlock()

	return card.conn.Raw(doInquire(card.conn), "scd SETATTR DISP-SEX %v", sex)
}

// SetDisplayLanguage sets the display language on the given smart card
func (card *Card) SetDisplayLanguage(lang string) error {
	card.conn.mu.Lock()
	defer card.conn.mu.Unlock()

	return card.conn.Raw(doInquire(card.conn), "scd SETATTR DISP-LANG %v", lang)
}

// SetLoginData sets the login data on the given smart card
func (card *Card) SetLoginData(loginData string) error {
	card.conn.mu.Lock()
	defer card.conn.mu.Unlock()

	return card.conn.Raw(doInquire(card.conn), "scd SETATTR LOGIN-DATA %v", loginData)
}

// FactoryReset will ensure the key is completely wiped out,
// see https://support.yubico.com/support/solutions/articles/15000006421-resetting-the-openpgp-applet-on-your-yubikey for more information
func (card *Card) FactoryReset() error {
	card.conn.mu.Lock()
	defer card.conn.mu.Unlock()

	err := card.conn.Raw(nil, "scd RESET")
	if err != nil {
		return err
	}
	err = card.conn.Raw(nil, "scd SERIALNO")
	if err != nil {
		return err
	}
	// Retry every PIN 4 times to ensure they are blocked
	for _, command := range []string{"00200081084040404040404040", "00200083084040404040404040"} {
		for i := 0; i < 4; i++ {
			err = card.conn.Raw(func(respType, data string) error {
				if respType == "D" && len(data) == 2 {
					if int(data[1]) != 0xC0+i {
						return fmt.Errorf("unexpected answer: %#x", int(data[1]))
					}
					return nil
				}
				return fmt.Errorf("unexpected: %v %v", respType, data)
			}, "scd APDU %s", command)
		}
	}
	err = card.conn.Raw(nil, "scd APDU 00e60000")
	if err != nil {
		return err
	}
	return card.conn.Raw(nil, "scd APDU 00440000")
}

// ResetPassword will unblock the requested password
func (card *Card) ResetPassword(admin bool) error {
	card.conn.mu.Lock()
	defer card.conn.mu.Unlock()

	id := 1
	if admin {
		id = 3
	}
	return card.conn.Raw(doInquire(card.conn), "scd PASSWD --reset %d", id)
}

// SetPIN will provide a prompt to set the requested password
func (card *Card) SetPIN(admin bool) error {
	card.conn.mu.Lock()
	defer card.conn.mu.Unlock()

	id := 1
	if admin {
		id = 3
	}
	return card.conn.Raw(doInquire(card.conn), "scd PASSWD %d", id)
}

// CheckPIN will check the requested password (potentially cached, might need unplugging for subsequent calls)
func (card *Card) CheckPIN(admin bool) error {
	card.conn.mu.Lock()
	defer card.conn.mu.Unlock()

	suffix := ""
	if admin {
		suffix = "[CHV3]"
	}
	return card.conn.Raw(doInquire(card.conn), "scd CHECKPIN %s%s", card.Serial, suffix)
}

// AddKey will generate a new key on the card
func (card *Card) AddKey(subKey int) error {
	if subKey >= cardMaxKeyNumber {
		return fmt.Errorf("invalid key ID %d", subKey)
	}
	card.conn.mu.Lock()
	defer card.conn.mu.Unlock()

	key := &CardKey{
		Key: Key{
			conn: card.conn,
		},
	}
	card.Subkeys[subKey] = key

	inquireFunc := doInquire(card.conn)
	err := card.conn.Raw(func(respType, data string) error {
		if respType == "INQUIRE" {
			return inquireFunc(respType, data)
		}
		if respType == "S" {
			parts := strings.Fields(strings.TrimSpace(data))
			switch parts[0] {
			case "KEY-DATA":
			case "KEY-CREATED-AT":
				ts, err := strconv.ParseInt(parts[1], 10, 64)
				if err != nil {
					return err
				}
				key.Created = time.Unix(ts, 0)
			case "KEY-FPR":
				key.Fingerprint = parts[1]
			default:
				return cardScan(card, data)
			}
			return nil
		}
		return fmt.Errorf("unexpected: %v %v", respType, data)
	}, "scd GENKEY %d", subKey+1)
	if err != nil {
		return err
	}
	err = card.conn.Raw(nil, "RESET")
	if err != nil {
		return err
	}

	err = card.conn.Raw(func(respType, data string) error {
		if respType != "S" {
			return nil
		}

		return cardScan(card, data)
	}, "LEARN --sendinfo --ssh-fpr")
	if err != nil {
		return err
	}

	key.Key, err = card.conn.key(key.Keygrip)
	return err
}
