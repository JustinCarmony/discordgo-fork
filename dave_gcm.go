package discordgo

// Truncated AES-GCM implementation for DAVE protocol.
//
// Go's standard library requires GCM tag sizes of 12-16 bytes,
// but DAVE uses 8-byte truncated tags. This implements the full
// AES-GCM algorithm with configurable tag truncation.

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/subtle"
	"encoding/binary"
	"errors"
)

// truncatedGCM implements cipher.AEAD with a configurable (possibly < 12) tag size.
type truncatedGCM struct {
	block   cipher.Block
	tagSize int
	h       [16]byte // H = AES(K, 0^128) for GHASH
}

func newTruncatedGCM(key []byte, tagSize int) (cipher.AEAD, error) {
	if tagSize < 1 || tagSize > 16 {
		return nil, errors.New("dave_gcm: invalid tag size")
	}
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}
	g := &truncatedGCM{block: block, tagSize: tagSize}
	// Precompute H = AES(K, 0^128)
	block.Encrypt(g.h[:], make([]byte, 16))
	return g, nil
}

func (g *truncatedGCM) NonceSize() int { return 12 }
func (g *truncatedGCM) Overhead() int  { return g.tagSize }

// Seal encrypts and authenticates plaintext with truncated tag.
func (g *truncatedGCM) Seal(dst, nonce, plaintext, additionalData []byte) []byte {
	if len(nonce) != 12 {
		panic("dave_gcm: incorrect nonce length")
	}

	// J0 = nonce || 0x00000001
	var j0 [16]byte
	copy(j0[:12], nonce)
	j0[15] = 1

	// Encrypt plaintext with CTR starting at inc32(J0)
	ctr := j0
	gcmInc32(&ctr)
	ct := make([]byte, len(plaintext))
	gcmCounterCrypt(g.block, &ctr, ct, plaintext)

	// Compute tag = GHASH(H, AAD, CT) XOR AES(K, J0)
	tag := g.computeTag(additionalData, ct, &j0)

	// Append ciphertext + truncated tag
	ret, out := sliceForAppend(dst, len(ct)+g.tagSize)
	copy(out, ct)
	copy(out[len(ct):], tag[:g.tagSize])
	return ret
}

// Open decrypts and verifies ciphertext with truncated tag.
func (g *truncatedGCM) Open(dst, nonce, ciphertext, additionalData []byte) ([]byte, error) {
	if len(nonce) != 12 {
		return nil, errors.New("dave_gcm: incorrect nonce length")
	}
	if len(ciphertext) < g.tagSize {
		return nil, errors.New("dave_gcm: ciphertext too short")
	}

	ct := ciphertext[:len(ciphertext)-g.tagSize]
	receivedTag := ciphertext[len(ciphertext)-g.tagSize:]

	// J0 = nonce || 0x00000001
	var j0 [16]byte
	copy(j0[:12], nonce)
	j0[15] = 1

	// Compute expected tag
	expectedTag := g.computeTag(additionalData, ct, &j0)

	// Constant-time comparison of truncated tag
	if subtle.ConstantTimeCompare(expectedTag[:g.tagSize], receivedTag) != 1 {
		return nil, errors.New("dave_gcm: message authentication failed")
	}

	// Decrypt with CTR starting at inc32(J0)
	ctr := j0
	gcmInc32(&ctr)
	ret, out := sliceForAppend(dst, len(ct))
	gcmCounterCrypt(g.block, &ctr, out, ct)
	return ret, nil
}

// computeTag computes the full 16-byte GCM authentication tag.
func (g *truncatedGCM) computeTag(aad, ct []byte, j0 *[16]byte) [16]byte {
	// GHASH(H, AAD, CT)
	var s [16]byte
	ghashBlocks(&g.h, &s, aad)
	ghashBlocks(&g.h, &s, ct)

	// Final GHASH block: len(AAD) || len(CT) in bits, both as 64-bit big-endian
	var lenBlock [16]byte
	binary.BigEndian.PutUint64(lenBlock[:8], uint64(len(aad))*8)
	binary.BigEndian.PutUint64(lenBlock[8:], uint64(len(ct))*8)
	ghashMul(&g.h, &s, &lenBlock)

	// Tag = S XOR AES(K, J0)
	var encJ0 [16]byte
	g.block.Encrypt(encJ0[:], j0[:])
	for i := range s {
		s[i] ^= encJ0[i]
	}
	return s
}

// gcmCounterCrypt performs AES-CTR encryption/decryption with GCM's counter format.
// The counter increments the last 32 bits (big-endian).
func gcmCounterCrypt(block cipher.Block, ctr *[16]byte, dst, src []byte) {
	var keystream [16]byte
	for len(src) > 0 {
		block.Encrypt(keystream[:], ctr[:])
		gcmInc32(ctr)

		n := len(src)
		if n > 16 {
			n = 16
		}
		for i := 0; i < n; i++ {
			dst[i] = src[i] ^ keystream[i]
		}
		src = src[n:]
		dst = dst[n:]
	}
}

// gcmInc32 increments the last 4 bytes of the counter (big-endian).
func gcmInc32(ctr *[16]byte) {
	c := binary.BigEndian.Uint32(ctr[12:])
	c++
	binary.BigEndian.PutUint32(ctr[12:], c)
}

// ghashBlocks processes data through GHASH, padding to 16-byte blocks.
func ghashBlocks(h, s *[16]byte, data []byte) {
	var block [16]byte
	for len(data) > 0 {
		n := len(data)
		if n > 16 {
			n = 16
		}
		// Zero-pad if necessary (block is zero-initialized each iteration)
		block = [16]byte{}
		copy(block[:], data[:n])
		ghashMul(h, s, &block)
		data = data[n:]
	}
}

// ghashMul computes s = (s XOR x) * h in GF(2^128).
func ghashMul(h, s, x *[16]byte) {
	// XOR x into s
	for i := range s {
		s[i] ^= x[i]
	}
	// Multiply s by h in GF(2^128) with polynomial x^128 + x^7 + x^2 + x + 1
	gfMul(h, s)
}

// gfMul multiplies s by h in GF(2^128), storing the result in s.
// Uses the reducing polynomial x^128 + x^7 + x^2 + x + 1 (0xE1 << 120).
func gfMul(h, s *[16]byte) {
	var z [16]byte // accumulator, starts at 0
	var v [16]byte // working copy of h
	copy(v[:], h[:])

	// Process each bit of s (MSB first)
	for i := 0; i < 128; i++ {
		// If bit i of s is set, XOR v into z
		byteIdx := i / 8
		bitIdx := uint(7 - (i % 8))
		if s[byteIdx]&(1<<bitIdx) != 0 {
			for j := range z {
				z[j] ^= v[j]
			}
		}

		// Shift v right by 1, with conditional XOR of reduction polynomial
		lsb := v[15] & 1
		for j := 15; j > 0; j-- {
			v[j] = (v[j] >> 1) | (v[j-1] << 7)
		}
		v[0] >>= 1
		if lsb != 0 {
			v[0] ^= 0xE1 // Reduction polynomial: x^128 + x^7 + x^2 + x + 1
		}
	}
	copy(s[:], z[:])
}

// sliceForAppend is a helper that grows dst to accommodate n extra bytes.
func sliceForAppend(in []byte, n int) (head, tail []byte) {
	if total := len(in) + n; cap(in) >= total {
		head = in[:total]
	} else {
		head = make([]byte, total)
		copy(head, in)
	}
	tail = head[len(in):]
	return
}
