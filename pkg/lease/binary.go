// Package lease - binary encoding for MSTR/1 protocol.
package lease

import (
	"encoding/binary"
	"encoding/json"
)

// EncodeBinary encodes the lease into a length-prefixed JSON payload
// for the MSTR/1 protocol. Format: [4-byte big-endian length][JSON bytes].
func (l *Lease) EncodeBinary() ([]byte, error) {
	data, err := json.Marshal(l)
	if err != nil {
		return nil, err
	}
	buf := make([]byte, 4+len(data))
	binary.BigEndian.PutUint32(buf[:4], uint32(len(data)))
	copy(buf[4:], data)
	return buf, nil
}

// DecodeBinaryLease decodes a length-prefixed JSON lease from binary.
func DecodeBinaryLease(data []byte) (*Lease, error) {
	if len(data) < 4 {
		return nil, ErrTooShort
	}
	length := binary.BigEndian.Uint32(data[:4])
	if int(length) > len(data)-4 {
		return nil, ErrTooShort
	}
	var l Lease
	if err := json.Unmarshal(data[4:4+length], &l); err != nil {
		return nil, err
	}
	return &l, nil
}

type binaryError string

func (e binaryError) Error() string { return string(e) }

// ErrTooShort is returned when binary data is too short to decode.
const ErrTooShort = binaryError("binary data too short")
