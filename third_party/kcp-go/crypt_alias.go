package kcp

import "github.com/xtaci/kcp-go/crypt"

// The cipher suite lives in package crypt so it can be linked without the rest
// of kcp -- kcptun's udptun binaries want BlockCrypt and nothing else, and
// importing kcp would drag in reedsolomon and the whole KCP state machine.
// See PATCH_NOTES.md. These aliases keep kcp's own API unchanged.

// BlockCrypt defines encryption/decryption methods for a given byte slice.
type BlockCrypt = crypt.BlockCrypt

// Entropy defines a entropy source
type Entropy = crypt.Entropy

var (
	NewAESBlockCrypt       = crypt.NewAESBlockCrypt
	NewTEABlockCrypt       = crypt.NewTEABlockCrypt
	NewSimpleXORBlockCrypt = crypt.NewSimpleXORBlockCrypt
	NewNoneBlockCrypt      = crypt.NewNoneBlockCrypt
	NewBlowfishBlockCrypt  = crypt.NewBlowfishBlockCrypt
	NewTwofishBlockCrypt   = crypt.NewTwofishBlockCrypt
	NewCast5BlockCrypt     = crypt.NewCast5BlockCrypt
	NewTripleDESBlockCrypt = crypt.NewTripleDESBlockCrypt
	NewXTEABlockCrypt      = crypt.NewXTEABlockCrypt
	NewSalsa20BlockCrypt   = crypt.NewSalsa20BlockCrypt
	NewSM4BlockCrypt       = crypt.NewSM4BlockCrypt
)
