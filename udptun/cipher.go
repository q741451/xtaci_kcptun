package udptun

import (
	"crypto/sha1"
	"fmt"

	"github.com/xtaci/kcp-go/crypt"
	"golang.org/x/crypto/pbkdf2"
)

// SALT matches kcptun's, so -key and -crypt mean here exactly what they mean
// there.
const SALT = "kcp-go"

// NewBlockCrypt derives a key from pass and returns the named cipher. Names and
// key sizes follow kcptun's -crypt; an unknown name is an error rather than a
// silent fallback, since a mismatched cipher just looks like a dead tunnel.
func NewBlockCrypt(name, pass string) (crypt.BlockCrypt, error) {
	key := pbkdf2.Key([]byte(pass), []byte(SALT), 4096, 32, sha1.New)
	switch name {
	case "sm4":
		return crypt.NewSM4BlockCrypt(key[:16])
	case "tea":
		return crypt.NewTEABlockCrypt(key[:16])
	case "xor":
		return crypt.NewSimpleXORBlockCrypt(key)
	case "none":
		return crypt.NewNoneBlockCrypt(key)
	case "aes-128":
		return crypt.NewAESBlockCrypt(key[:16])
	case "aes-192":
		return crypt.NewAESBlockCrypt(key[:24])
	case "blowfish":
		return crypt.NewBlowfishBlockCrypt(key)
	case "twofish":
		return crypt.NewTwofishBlockCrypt(key)
	case "cast5":
		return crypt.NewCast5BlockCrypt(key[:16])
	case "3des":
		return crypt.NewTripleDESBlockCrypt(key[:24])
	case "xtea":
		return crypt.NewXTEABlockCrypt(key[:16])
	case "salsa20":
		return crypt.NewSalsa20BlockCrypt(key)
	case "aes":
		return crypt.NewAESBlockCrypt(key)
	}
	return nil, fmt.Errorf("udptun: unknown -crypt %q", name)
}

// CryptList is the accepted -crypt values, for help text.
const CryptList = "aes, aes-128, aes-192, salsa20, blowfish, twofish, cast5, 3des, tea, xtea, xor, sm4, none"
