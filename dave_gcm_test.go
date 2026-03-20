package discordgo

import (
	"bytes"
	"crypto/aes"
	"crypto/cipher"
	"testing"
)

func TestTruncatedGCM_RoundTrip(t *testing.T) {
	key := make([]byte, 16)
	for i := range key {
		key[i] = byte(i)
	}
	nonce := make([]byte, 12)
	nonce[0] = 0x42

	gcm, err := newTruncatedGCM(key, 8)
	if err != nil {
		t.Fatal(err)
	}

	plaintext := []byte("hello world, this is a DAVE test frame")
	sealed := gcm.Seal(nil, nonce, plaintext, nil)
	if len(sealed) != len(plaintext)+8 {
		t.Fatalf("sealed length = %d, want %d", len(sealed), len(plaintext)+8)
	}

	opened, err := gcm.Open(nil, nonce, sealed, nil)
	if err != nil {
		t.Fatalf("Open failed: %v", err)
	}
	if !bytes.Equal(opened, plaintext) {
		t.Fatalf("opened = %q, want %q", opened, plaintext)
	}
}

// TestTruncatedGCM_CompatibleWithStandardGCM verifies that our truncated GCM
// produces ciphertext compatible with Go's standard GCM (just with truncated tag).
func TestTruncatedGCM_CompatibleWithStandardGCM(t *testing.T) {
	key := make([]byte, 16)
	for i := range key {
		key[i] = byte(i + 10)
	}
	nonce := make([]byte, 12)
	nonce[3] = 0x99

	// Encrypt with standard GCM (16-byte tag)
	block, _ := aes.NewCipher(key)
	stdGCM, _ := cipher.NewGCM(block)
	plaintext := []byte("test data for compatibility check")
	stdSealed := stdGCM.Seal(nil, nonce, plaintext, nil)

	// The ciphertext (before tag) should be identical
	stdCiphertext := stdSealed[:len(plaintext)]
	stdFullTag := stdSealed[len(plaintext):]

	// Create truncated version: ciphertext + first 8 bytes of tag
	truncatedSealed := make([]byte, len(stdCiphertext)+8)
	copy(truncatedSealed, stdCiphertext)
	copy(truncatedSealed[len(stdCiphertext):], stdFullTag[:8])

	// Our truncated GCM should decrypt this
	tGCM, _ := newTruncatedGCM(key, 8)
	opened, err := tGCM.Open(nil, nonce, truncatedSealed, nil)
	if err != nil {
		t.Fatalf("truncated GCM failed to decrypt standard GCM ciphertext: %v", err)
	}
	if !bytes.Equal(opened, plaintext) {
		t.Fatalf("decrypted = %q, want %q", opened, plaintext)
	}
}

func TestTruncatedGCM_AuthFailure(t *testing.T) {
	key := make([]byte, 16)
	nonce := make([]byte, 12)

	gcm, _ := newTruncatedGCM(key, 8)
	sealed := gcm.Seal(nil, nonce, []byte("secret"), nil)

	// Flip a bit in the ciphertext
	sealed[0] ^= 0x01
	_, err := gcm.Open(nil, nonce, sealed, nil)
	if err == nil {
		t.Fatal("expected authentication failure, got nil error")
	}
}
