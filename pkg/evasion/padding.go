package evasion

import (
	"crypto/rand"
	"encoding/hex"
	"io"
	mrand "math/rand"
)

type PacketPadder struct {
	minPadding int
	maxPadding int
}

func NewPacketPadder(minPadding, maxPadding int) *PacketPadder {
	return &PacketPadder{
		minPadding: minPadding,
		maxPadding: maxPadding,
	}
}

func (pp *PacketPadder) GeneratePadding() []byte {
	if pp.minPadding >= pp.maxPadding {
		return nil
	}
	size := pp.minPadding + mrand.Intn(pp.maxPadding-pp.minPadding)
	if size <= 0 {
		return nil
	}
	buf := make([]byte, size)
	_, _ = io.ReadFull(rand.Reader, buf)
	return buf
}

func (pp *PacketPadder) GeneratePaddingHex() string {
	padding := pp.GeneratePadding()
	if padding == nil {
		return ""
	}
	return hex.EncodeToString(padding)
}

func (pp *PacketPadder) PadPayload(payload []byte) []byte {
	padding := pp.GeneratePadding()
	if padding == nil {
		return payload
	}
	result := make([]byte, len(payload)+len(padding))
	copy(result, payload)
	copy(result[len(payload):], padding)
	return result
}
