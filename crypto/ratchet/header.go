package ratchet

import (
	"encoding/binary"
	"errors"
)

// Header is sent alongside each ratchet-encrypted message. DHPub is
// always present. MLKEMPub is present when the sender is initiating a
// periodic PQ injection (PRD §5: "fresh ML-KEM encapsulation injected
// every 50 messages or 24h"); MLKEMCiphertext is present when the
// sender is responding to a PQ injection the peer initiated earlier.
type Header struct {
	DHPub           []byte
	PN              uint32
	N               uint32
	MLKEMPub        []byte
	MLKEMCiphertext []byte
}

// Marshal serializes the header into a simple length-prefixed binary
// format. This is a demo wire format, not a versioned protocol —
// production would carry a version tag and use a schema-checked
// serializer (protobuf or similar).
func (h *Header) Marshal() []byte {
	size := 4 + len(h.DHPub) + 4 + 4 + 4 + len(h.MLKEMPub) + 4 + len(h.MLKEMCiphertext)
	buf := make([]byte, 0, size)
	buf = appendBytes(buf, h.DHPub)
	buf = binary.BigEndian.AppendUint32(buf, h.PN)
	buf = binary.BigEndian.AppendUint32(buf, h.N)
	buf = appendBytes(buf, h.MLKEMPub)
	buf = appendBytes(buf, h.MLKEMCiphertext)
	return buf
}

func appendBytes(buf, data []byte) []byte {
	buf = binary.BigEndian.AppendUint32(buf, uint32(len(data)))
	return append(buf, data...)
}

// UnmarshalHeader parses a header previously produced by Marshal.
func UnmarshalHeader(buf []byte) (*Header, error) {
	h := &Header{}
	var err error
	if h.DHPub, buf, err = readBytes(buf); err != nil {
		return nil, err
	}
	if h.PN, buf, err = readUint32(buf); err != nil {
		return nil, err
	}
	if h.N, buf, err = readUint32(buf); err != nil {
		return nil, err
	}
	if h.MLKEMPub, buf, err = readBytes(buf); err != nil {
		return nil, err
	}
	if h.MLKEMCiphertext, buf, err = readBytes(buf); err != nil {
		return nil, err
	}
	if len(buf) != 0 {
		return nil, errors.New("ratchet: trailing bytes after header")
	}
	if len(h.MLKEMPub) == 0 {
		h.MLKEMPub = nil
	}
	if len(h.MLKEMCiphertext) == 0 {
		h.MLKEMCiphertext = nil
	}
	return h, nil
}

func readUint32(buf []byte) (uint32, []byte, error) {
	if len(buf) < 4 {
		return 0, nil, errors.New("ratchet: truncated header")
	}
	return binary.BigEndian.Uint32(buf), buf[4:], nil
}

func readBytes(buf []byte) ([]byte, []byte, error) {
	n, buf, err := readUint32(buf)
	if err != nil {
		return nil, nil, err
	}
	if uint64(len(buf)) < uint64(n) {
		return nil, nil, errors.New("ratchet: truncated header field")
	}
	return buf[:n], buf[n:], nil
}
