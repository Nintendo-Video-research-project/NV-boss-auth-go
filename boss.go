package NV_boss_auth_go

import (
	"bytes"
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"crypto/sha256"
	"encoding/binary"
	"errors"
	"log"
	"os"
	"path/filepath"
)

// store key if cached
var _keycache []byte = nil

// constants
const (
	OUTER_SIZE          = 0x28
	CONTENT_HEADER_SIZE = 0x132
	PAYLOAD_HEADER_SIZE = 0x13C
	HEADER_SIZE         = OUTER_SIZE + CONTENT_HEADER_SIZE + PAYLOAD_HEADER_SIZE
	DATATYPE_NV         = 0x00010001 // Value seen in retail NV containers
)

func nv_boss_key() []byte {
	/* 16-byte BOSS content AES key */
	if _keycache == nil {
		var env = os.Getenv("NV_BOSS_KEY")
		if env == "" {
			var boss_keypath string

			// set to server executable path
			exePath, err := os.Executable()
			if err != nil {
				exePath = "."
			}
			boss_keypath = filepath.Join(filepath.Dir(exePath), "boss.key")

			// check if there is a valid 16-bit key inside the key file
			if info, err := os.Stat(boss_keypath); err == nil && !info.IsDir() {
				content, err := os.ReadFile(boss_keypath)
				if err != nil {
					log.Printf("Failed to read boss key from %s: %s\n", boss_keypath, err)
				} else {
					_keycache = content
				}
			}
		} else {
			_keycache = []byte(env)
		}
	}
	// spit out cached key
	return _keycache
}
func nv_boss_buildCTR(iv12 []byte, data []byte) ([]byte, error) {
	// Initializes AES Cipher Key
	key := nv_boss_key()

	// build block cipher
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}
	// Allocates a slice of 16 bytes with zeros
	counterBlock := make([]byte, 16)
	copy(counterBlock[:12], iv12)

	// Set the 4-bytes we need
	counterBlock[12] = 0x00
	counterBlock[13] = 0x00
	counterBlock[14] = 0x00
	counterBlock[15] = 0x01

	// Pass counter block into cipher builder
	stream := cipher.NewCTR(block, counterBlock)
	dst := make([]byte, len(data))
	// Apply XOR operation
	stream.XORKeyStream(dst, data)

	return dst, nil
}
func nv_boss_Encrypt(payload []byte, titleID uint64, nsDataID uint32, version uint32, timestamp uint64, datatype uint32, ctrEncrypt func(iv, data []byte) []byte) []byte {

	// The content header
	ch := make([]byte, 0x12)
	ch[0] = 0x80
	binary.BigEndian.PutUint16(ch[0x10:], 1)

	// SHA256
	h := sha256.New()
	h.Write(ch)
	h.Write([]byte{0x00, 0x00})
	contentHash := h.Sum(nil)

	contentHeader := make([]byte, 0, len(ch)+len(contentHash)+0x100)
	contentHeader = append(contentHeader, ch...)
	contentHeader = append(contentHeader, contentHash...)
	contentHeader = append(contentHeader, make([]byte, 0x100)...) // 256 zero bytes

	// Payload Header
	pch := make([]byte, 28)
	binary.BigEndian.PutUint64(pch[0:8], titleID)
	binary.BigEndian.PutUint32(pch[8:12], 0)
	binary.BigEndian.PutUint32(pch[12:16], DATATYPE_NV)
	binary.BigEndian.PutUint32(pch[16:20], uint32(len(payload)))
	binary.BigEndian.PutUint32(pch[20:24], nsDataID)
	binary.BigEndian.PutUint32(pch[24:28], version)

	// PCH Hash
	h2 := sha256.New()
	h2.Write(pch)
	h2.Write([]byte{0x00, 0x00})
	h2.Write(payload)
	pchHash := h2.Sum(nil)

	payloadHeader := make([]byte, 0, len(pch)+len(pchHash)+0x100)
	payloadHeader = append(payloadHeader, pch...)
	payloadHeader = append(payloadHeader, pchHash...)
	payloadHeader = append(payloadHeader, make([]byte, 0x100)...) // 256 zero bytes

	iv := make([]byte, 12)
	rand.Read(iv)

	body := make([]byte, 0, len(contentHeader)+len(payloadHeader)+len(payload))
	body = append(body, contentHeader...)
	body = append(body, payloadHeader...)
	body = append(body, payload...)

	// Outer header
	outer := make([]byte, OUTER_SIZE)
	copy(outer[0:4], []byte("boss"))
	binary.BigEndian.PutUint32(outer[4:8], 0x10001)
	binary.BigEndian.PutUint32(outer[8:12], uint32(OUTER_SIZE+len(body)))
	binary.BigEndian.PutUint64(outer[12:20], timestamp)
	binary.BigEndian.PutUint16(outer[20:22], 1)
	binary.BigEndian.PutUint16(outer[22:24], 0)
	binary.BigEndian.PutUint16(outer[24:26], 2)
	binary.BigEndian.PutUint16(outer[26:28], 2)
	copy(outer[28:40], iv)

	encryptedBody := ctrEncrypt(iv, body)

	result := make([]byte, 0, len(outer)+len(encryptedBody))
	result = append(result, outer...)
	result = append(result, encryptedBody...)

	return result
}
func nv_boss_Decrypt(data []byte) ([]byte, error) {
	if len(data) < OUTER_SIZE {
		return nil, errors.New("data is too short to be BOSS container")
	}

	if !bytes.Equal(data[:4], []byte("boss")) {
		return nil, errors.New("data is not BOSS container")
	}

	iv := data[28:40]
	encryptedBody := data[OUTER_SIZE:]

	return nv_boss_buildCTR(iv, encryptedBody)
}
func nv_boss_extract_payload(data []byte) ([]byte, error) {
	decrypted, err := nv_boss_Decrypt(data)
	if err != nil {
		return nil, err
	}
	headerOffset := CONTENT_HEADER_SIZE + PAYLOAD_HEADER_SIZE

	if len(decrypted) < headerOffset {
		return nil, errors.New("data is too short")
	}

	return decrypted[headerOffset:], nil
}