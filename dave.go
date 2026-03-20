package discordgo

import (
	"crypto/cipher"
	"encoding/binary"
	"fmt"
	"strconv"
	"sync"

	"github.com/bwmarrin/discordgo/mls"
)

// receiverState tracks per-user decryption state for received DAVE frames.
type receiverState struct {
	baseSecret        []byte
	currentGeneration uint32
	cipher            cipher.AEAD
}

type DAVESession struct {
	mu                  sync.Mutex
	protocolVersion     int
	epoch               uint64
	pendingTransitionID uint16
	pendingVersion      int

	exporterSecret    []byte
	senderKey         []byte
	senderNonce       uint32
	frameCipher       cipher.AEAD
	userID            string
	active            bool
	ratchetBaseSecret []byte
	currentGeneration uint32
	hasPendingKey     bool

	// receivers caches per-user decryption state keyed by user ID.
	receivers map[string]*receiverState

	kpBundle *mls.KeyPackageBundle
}

func NewDAVESession(userID string) *DAVESession {
	return &DAVESession{
		userID: userID,
	}
}

func (d *DAVESession) GenerateKeyPackage() ([]byte, error) {
	d.mu.Lock()
	defer d.mu.Unlock()
	return d.generateKeyPackageLocked()
}

func (d *DAVESession) ResetForReWelcome() ([]byte, error) {
	d.mu.Lock()
	defer d.mu.Unlock()

	d.exporterSecret = nil
	d.hasPendingKey = false

	return d.generateKeyPackageLocked()
}

func (d *DAVESession) generateKeyPackageLocked() ([]byte, error) {
	userIDNum, err := strconv.ParseUint(d.userID, 10, 64)
	if err != nil {
		return nil, fmt.Errorf("parsing user ID for credential: %w", err)
	}
	identity := make([]byte, 8)
	binary.BigEndian.PutUint64(identity, userIDNum)

	bundle, err := mls.GenerateKeyPackage(identity)
	if err != nil {
		return nil, fmt.Errorf("generating key package: %w", err)
	}
	d.kpBundle = bundle
	return bundle.Serialized, nil
}

func (d *DAVESession) HandleExternalSenderPackage(data []byte) error {
	d.mu.Lock()
	defer d.mu.Unlock()
	return nil
}

func (d *DAVESession) HandleWelcome(data []byte) error {
	d.mu.Lock()
	defer d.mu.Unlock()

	if d.kpBundle == nil {
		return fmt.Errorf("no key package generated")
	}

	result, err := mls.ProcessWelcome(data, d.kpBundle)
	if err != nil {
		return fmt.Errorf("processing welcome: %w", err)
	}

	d.exporterSecret = result.ExporterSecret
	d.epoch = result.Epoch
	d.hasPendingKey = true
	d.receivers = nil // Reset receiver keys on new epoch.
	return nil
}

func (d *DAVESession) HandleCommit(data []byte) error {
	d.mu.Lock()
	defer d.mu.Unlock()
	return nil
}

func (d *DAVESession) HandlePrepareTransition(transitionID uint16, protocolVersion int) {
	d.mu.Lock()
	defer d.mu.Unlock()
	d.pendingTransitionID = transitionID
	d.pendingVersion = protocolVersion
}

func (d *DAVESession) HandleExecuteTransition(transitionID uint16) error {
	d.mu.Lock()
	defer d.mu.Unlock()

	if transitionID != d.pendingTransitionID {
		if d.senderKey != nil {
			d.active = true
		}
		return nil
	}

	if d.pendingVersion > 0 {
		derivedNewKey := false
		if d.hasPendingKey && d.exporterSecret != nil {
			if err := d.deriveSenderKeyLocked(); err != nil {
				return err
			}
			d.hasPendingKey = false
			derivedNewKey = true
		}
		if d.senderKey == nil {
			return nil
		}

		if !derivedNewKey && !d.hasPendingKey {
			d.active = false
			d.senderKey = nil
			d.frameCipher = nil
			d.ratchetBaseSecret = nil
			d.currentGeneration = 0
			return nil
		}

		d.active = true
	} else {
		d.active = false
		d.senderKey = nil
		d.frameCipher = nil
		d.hasPendingKey = false
	}
	return nil
}

func (d *DAVESession) HandlePrepareEpoch(epoch uint64, protocolVersion int) ([]byte, error) {
	d.mu.Lock()
	defer d.mu.Unlock()

	d.epoch = epoch
	d.active = false
	d.senderKey = nil
	d.frameCipher = nil
	d.exporterSecret = nil
	d.receivers = nil

	return d.generateKeyPackageLocked()
}

func (d *DAVESession) DeriveSenderKey() error {
	d.mu.Lock()
	defer d.mu.Unlock()
	return d.deriveSenderKeyLocked()
}

func (d *DAVESession) deriveSenderKeyLocked() error {
	if d.exporterSecret == nil {
		return fmt.Errorf("no exporter secret")
	}

	userIDNum, err := strconv.ParseUint(d.userID, 10, 64)
	if err != nil {
		return fmt.Errorf("parsing user ID: %w", err)
	}
	context := make([]byte, 8)
	binary.LittleEndian.PutUint64(context, userIDNum)

	baseSecret, err := mls.Export(d.exporterSecret, daveExportLabel, context, daveKeySize)
	if err != nil {
		return fmt.Errorf("exporting base secret: %w", err)
	}

	d.ratchetBaseSecret = baseSecret
	d.currentGeneration = 0
	d.senderNonce = 0

	key, err := hashRatchetGetKey(baseSecret, 0)
	if err != nil {
		return fmt.Errorf("deriving ratchet key: %w", err)
	}
	d.senderKey = key

	frameCipher, err := newDAVECipher(key)
	if err != nil {
		return fmt.Errorf("creating frame cipher: %w", err)
	}
	d.frameCipher = frameCipher
	return nil
}

func (d *DAVESession) EncryptFrame(opusData []byte) ([]byte, error) {
	d.mu.Lock()
	defer d.mu.Unlock()

	if d.frameCipher == nil {
		return nil, fmt.Errorf("no frame cipher")
	}

	d.senderNonce++

	generation := d.senderNonce >> 24
	if generation != d.currentGeneration {
		d.currentGeneration = generation
		key, err := hashRatchetGetKey(d.ratchetBaseSecret, generation)
		if err != nil {
			return nil, fmt.Errorf("ratcheting key for generation %d: %w", generation, err)
		}
		d.senderKey = key
		frameCipher, err := newDAVECipher(key)
		if err != nil {
			return nil, fmt.Errorf("creating cipher for generation %d: %w", generation, err)
		}
		d.frameCipher = frameCipher
	}

	encrypted := encryptSecureFrame(d.frameCipher, d.senderNonce, opusData)
	return encrypted, nil
}

// DecryptFrame decrypts a DAVE-encrypted frame from another participant.
// senderUserID is the user who sent this frame (looked up from SSRC mapping).
func (d *DAVESession) DecryptFrame(senderUserID string, data []byte) (plaintext []byte, retErr error) {
	d.mu.Lock()
	defer d.mu.Unlock()

	// Recover from panics so a malformed frame never crashes the gateway.
	defer func() {
		if r := recover(); r != nil {
			plaintext = nil
			retErr = fmt.Errorf("DAVE decrypt panic: %v", r)
		}
	}()

	if d.exporterSecret == nil {
		return nil, fmt.Errorf("no exporter secret")
	}

	// Parse the secure frame to extract ciphertext, tag, and nonce.
	return d.decryptSecureFrameLocked(senderUserID, data)
}

// decryptSecureFrameLocked parses and decrypts a DAVE secure frame. Must hold d.mu.
func (d *DAVESession) decryptSecureFrameLocked(senderUserID string, data []byte) ([]byte, error) {
	// Secure frame format:
	// [ciphertext...] [8-byte truncated tag] [ULEB128 nonce] [supplemental_size] [0xFA 0xFA]
	if len(data) < 4 {
		return nil, fmt.Errorf("frame too short: %d bytes", len(data))
	}

	// Verify magic bytes at the end.
	if data[len(data)-1] != 0xFA || data[len(data)-2] != 0xFA {
		// Not a DAVE-encrypted frame — return as-is.
		return data, nil
	}

	supplementalSize := int(data[len(data)-3])
	if supplementalSize < 4 || supplementalSize > len(data) {
		return nil, fmt.Errorf("invalid supplemental size: %d", supplementalSize)
	}

	// The supplemental section starts at len(data) - 2 - 1 - (supplementalSize - 3)
	// supplementalSize includes: tagSize(8) + nonceBytes + supplementalSizeByte(1) + magic(2)
	nonceLen := supplementalSize - daveTagSize - 1 - 2
	if nonceLen < 1 || nonceLen > 5 {
		return nil, fmt.Errorf("invalid nonce length: %d", nonceLen)
	}

	// Parse layout:
	// [ciphertext] [8-byte tag] [nonce bytes] [supplemental_size] [0xFA] [0xFA]
	magicEnd := len(data)
	suppSizeIdx := magicEnd - 3
	nonceStart := suppSizeIdx - nonceLen
	tagStart := nonceStart - daveTagSize
	ciphertextEnd := tagStart

	if ciphertextEnd < 0 {
		return nil, fmt.Errorf("frame too short for ciphertext")
	}

	ciphertext := data[:ciphertextEnd]
	truncatedTag := data[tagStart:nonceStart]
	nonceBytes := data[nonceStart:suppSizeIdx]

	// Decode ULEB128 nonce.
	nonce := decodeULEB128(nonceBytes)
	generation := nonce >> 24

	// Get or create receiver state for this sender.
	rs, err := d.getReceiverStateLocked(senderUserID, generation)
	if err != nil {
		return nil, fmt.Errorf("deriving receiver key for %s: %w", senderUserID, err)
	}

	// Build full nonce for AES-GCM.
	fullNonce := buildNonce(nonce)

	// Reconstruct sealed message: ciphertext + truncated tag (8 bytes).
	// The cipher uses NewGCMWithTagSize(8) so it expects 8-byte tags.
	sealed := make([]byte, len(ciphertext)+daveTagSize)
	copy(sealed, ciphertext)
	copy(sealed[len(ciphertext):], truncatedTag)

	plaintext, err := rs.cipher.Open(nil, fullNonce, sealed, nil)
	if err != nil {
		return nil, fmt.Errorf("DAVE decrypt failed (gen=%d, nonce=%d): %w", generation, nonce, err)
	}

	return plaintext, nil
}

// getReceiverStateLocked gets or creates the receiver key state for a sender.
// Handles generation-based key ratcheting. Must hold d.mu.
func (d *DAVESession) getReceiverStateLocked(senderUserID string, generation uint32) (*receiverState, error) {
	if d.receivers == nil {
		d.receivers = make(map[string]*receiverState)
	}

	rs, ok := d.receivers[senderUserID]
	if ok && rs.currentGeneration == generation && rs.cipher != nil {
		return rs, nil
	}

	// Need to derive or ratchet the key.
	if rs == nil {
		// First time seeing this sender — derive their base secret.
		userIDNum, err := strconv.ParseUint(senderUserID, 10, 64)
		if err != nil {
			return nil, fmt.Errorf("parsing sender user ID: %w", err)
		}
		ctx := make([]byte, 8)
		binary.LittleEndian.PutUint64(ctx, userIDNum)

		baseSecret, err := mls.Export(d.exporterSecret, daveExportLabel, ctx, daveKeySize)
		if err != nil {
			return nil, fmt.Errorf("exporting receiver base secret: %w", err)
		}

		rs = &receiverState{baseSecret: baseSecret}
	}

	// Derive key for the requested generation.
	key, err := hashRatchetGetKey(rs.baseSecret, generation)
	if err != nil {
		return nil, fmt.Errorf("ratcheting receiver key to gen %d: %w", generation, err)
	}

	frameCipher, err := newDAVECipherTruncated(key)
	if err != nil {
		return nil, fmt.Errorf("creating receiver cipher: %w", err)
	}

	rs.currentGeneration = generation
	rs.cipher = frameCipher
	// Store in map only after cipher is successfully created. // DC-057
	d.receivers[senderUserID] = rs
	return rs, nil
}

// ResetReceivers clears all receiver key state (e.g. on epoch change).
func (d *DAVESession) ResetReceivers() {
	d.mu.Lock()
	defer d.mu.Unlock()
	d.receivers = nil
}

func (d *DAVESession) IsActive() bool {
	d.mu.Lock()
	defer d.mu.Unlock()
	return d.active
}

func (d *DAVESession) CanEncrypt() bool {
	d.mu.Lock()
	defer d.mu.Unlock()
	return d.frameCipher != nil
}

// CanDecrypt returns true if the session has an exporter secret and can
// derive receiver keys for decryption. This is available after Welcome,
// even before execute_transition sets active=true.
func (d *DAVESession) CanDecrypt() bool {
	d.mu.Lock()
	defer d.mu.Unlock()
	return d.exporterSecret != nil
}

func (d *DAVESession) Reset() {
	d.mu.Lock()
	defer d.mu.Unlock()

	d.exporterSecret = nil
	d.senderKey = nil
	d.senderNonce = 0
	d.frameCipher = nil
	d.active = false
	d.kpBundle = nil
	d.pendingTransitionID = 0
	d.pendingVersion = 0
	d.ratchetBaseSecret = nil
	d.currentGeneration = 0
	d.hasPendingKey = false
	d.receivers = nil
}
