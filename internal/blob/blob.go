package blob

import (
	"bytes"
	"encoding/binary"
	"errors"
)

// 16kb should be enough
const blobSize = 16 * 1024
const maxMagic = 32
const magicString = "PARAMETERS"

var blob = [blobSize]byte{
	// magic length
	0x0a, // 10 = len("PARAMETERS")
	// magic string "PARAMETERS"
	'P', 'A', 'R', 'A', 'M', 'E', 'T', 'E', 'R', 'S',
	// version
	0x01,
}

func Load() []byte {
	if blob[0] == 0 {
		return nil
	}

	magicLen := int(blob[0])
	hdr := 1 + magicLen + 1 + 2
	if hdr > blobSize {
		return nil
	}

	payloadLen := int(binary.LittleEndian.Uint16(blob[1+magicLen+1:]))
	if payloadLen <= 0 || hdr+payloadLen > blobSize {
		return nil
	}
	return blob[hdr : hdr+payloadLen]
}

func Patch(data []byte, payload string) ([]byte, error) {
	magicBytes := []byte(magicString)
	if len(magicBytes) == 0 || len(magicBytes) > maxMagic {
		return nil, errors.New("invalid magic length")
	}

	// Search for magicLen + magicBytes
	pattern := append([]byte{uint8(len(magicString))}, magicBytes...)

	offset := bytes.Index(data, pattern)
	if offset < 0 {
		return nil, errors.New("blob not found")
	}

	if offset+blobSize > len(data) {
		return nil, errors.New("invalid blob boundary")
	}

	payloadBytes := []byte(payload)
	headerSize := 1 + len(magicBytes) + 1 + 2

	if headerSize+len(payloadBytes) > blobSize {
		return nil, errors.New("payload too large")
	}

	// Zero payload region only (after header)
	for i := offset + headerSize; i < offset+headerSize+len(payloadBytes); i++ {
		data[i] = 0
	}

	// Write payload length
	binary.LittleEndian.PutUint16(
		data[offset+1+len(magicBytes)+1:],
		uint16(len(payloadBytes)),
	)

	// Write payload
	copy(
		data[offset+headerSize:],
		payloadBytes,
	)
	return data, nil
}
