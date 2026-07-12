//go:build unix

package main

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/hex"
	"encoding/pem"
	"errors"
	"flag"
	"fmt"
	"io"
	"log"
	"math/big"
	"net"
	"os"
	"path/filepath"
	"strings"
	"time"
)

// ---------------------------------------------------------------------------
// #10 at-rest encryption for received files (chunked AES-256-GCM)
//
// File format: magic "TSE1" | 16-byte salt | repeated [4-byte BE chunk len |
// ciphertext+tag]. Each chunk is sealed with a nonce of random8 || counter,
// where random8 is derived once from the key+salt; the trailing counter
// guarantees per-chunk uniqueness. Key = scrypt-free SHA-256(passphrase|salt)
// — simple and dependency-free; for a generated key it's already 256-bit.

const encMagic = "TSE1"
const encChunk = 1 << 20 // 1 MiB plaintext chunks

func resolveEncKey(c *config) ([]byte, error) {
	if c.encKeyHex != "" {
		k, err := hex.DecodeString(c.encKeyHex)
		if err != nil || len(k) != 32 {
			return nil, errors.New("bad inherited encryption key")
		}
		return k, nil
	}
	if c.Password != "" { // derive from the share password
		sum := sha256.Sum256([]byte("tshare-enc:" + c.Password))
		return sum[:], nil
	}
	// generate and show once — the user needs it to decrypt later
	k := make([]byte, 32)
	if _, err := rand.Read(k); err != nil {
		return nil, err
	}
	c.encKeyHex = hex.EncodeToString(k)
	fmt.Fprintf(os.Stderr, "  🔐 inbox encryption key (save this — needed to decrypt):\n     %s\n", c.encKeyHex)
	return k, nil
}

func encWriter(dst io.Writer, key []byte) (io.WriteCloser, error) {
	salt := make([]byte, 16)
	if _, err := rand.Read(salt); err != nil {
		return nil, err
	}
	gcm, base, err := encGCM(key, salt)
	if err != nil {
		return nil, err
	}
	if _, err := io.WriteString(dst, encMagic); err != nil {
		return nil, err
	}
	if _, err := dst.Write(salt); err != nil {
		return nil, err
	}
	return &chunkEncWriter{dst: dst, gcm: gcm, base: base}, nil
}

func encGCM(key, salt []byte) (cipher.AEAD, []byte, error) {
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, nil, err
	}
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, nil, err
	}
	// derive an 8-byte nonce prefix from key+salt; counter fills the rest
	h := sha256.Sum256(append(append([]byte("nonce"), key...), salt...))
	base := make([]byte, gcm.NonceSize())
	copy(base, h[:8])
	return gcm, base, nil
}

type chunkEncWriter struct {
	dst     io.Writer
	gcm     cipher.AEAD
	base    []byte
	counter uint64
	buf     []byte
}

func (w *chunkEncWriter) Write(p []byte) (int, error) {
	w.buf = append(w.buf, p...)
	for len(w.buf) >= encChunk {
		if err := w.seal(w.buf[:encChunk]); err != nil {
			return 0, err
		}
		w.buf = w.buf[encChunk:]
	}
	return len(p), nil
}

func (w *chunkEncWriter) seal(plain []byte) error {
	nonce := make([]byte, len(w.base))
	copy(nonce, w.base)
	for i := 0; i < 8; i++ {
		nonce[len(nonce)-1-i] = byte(w.counter >> (8 * i))
	}
	w.counter++
	ct := w.gcm.Seal(nil, nonce, plain, nil)
	var lenb [4]byte
	lenb[0], lenb[1], lenb[2], lenb[3] = byte(len(ct)>>24), byte(len(ct)>>16), byte(len(ct)>>8), byte(len(ct))
	if _, err := w.dst.Write(lenb[:]); err != nil {
		return err
	}
	_, err := w.dst.Write(ct)
	return err
}

func (w *chunkEncWriter) Close() error {
	if len(w.buf) > 0 {
		return w.seal(w.buf)
	}
	return nil
}

func decryptFile(in io.Reader, out io.Writer, key []byte) error {
	magic := make([]byte, 4)
	if _, err := io.ReadFull(in, magic); err != nil || string(magic) != encMagic {
		return errors.New("not a tshare-encrypted file")
	}
	salt := make([]byte, 16)
	if _, err := io.ReadFull(in, salt); err != nil {
		return err
	}
	gcm, base, err := encGCM(key, salt)
	if err != nil {
		return err
	}
	var counter uint64
	var lenb [4]byte
	for {
		_, err := io.ReadFull(in, lenb[:])
		if err == io.EOF {
			return nil
		}
		if err != nil {
			return err
		}
		clen := int(lenb[0])<<24 | int(lenb[1])<<16 | int(lenb[2])<<8 | int(lenb[3])
		ct := make([]byte, clen)
		if _, err := io.ReadFull(in, ct); err != nil {
			return err
		}
		nonce := make([]byte, len(base))
		copy(nonce, base)
		for i := 0; i < 8; i++ {
			nonce[len(nonce)-1-i] = byte(counter >> (8 * i))
		}
		counter++
		plain, err := gcm.Open(nil, nonce, ct, nil)
		if err != nil {
			return errors.New("decryption failed (wrong key or corrupt file)")
		}
		if _, err := out.Write(plain); err != nil {
			return err
		}
	}
}

func cmdDecrypt(args []string) {
	fs := flag.NewFlagSet("decrypt", flag.ExitOnError)
	pw := fs.String("p", "", "passphrase")
	fs.StringVar(pw, "password", "", "")
	keyHex := fs.String("key", "", "raw 64-hex-char key")
	outDir := fs.String("o", ".", "output directory")
	fs.Parse(args)
	if fs.NArg() == 0 {
		fmt.Println("usage: tshare decrypt [-p pass | -key HEX] [-o dir] <file.enc>...")
		return
	}
	var key []byte
	switch {
	case *keyHex != "":
		k, err := hex.DecodeString(*keyHex)
		if err != nil || len(k) != 32 {
			log.Fatal("tshare: -key must be 64 hex chars (32 bytes)")
		}
		key = k
	case *pw != "":
		sum := sha256.Sum256([]byte("tshare-enc:" + *pw))
		key = sum[:]
	default:
		log.Fatal("tshare: need -p <passphrase> or -key <hex>")
	}
	for _, in := range fs.Args() {
		f, err := os.Open(in)
		if err != nil {
			log.Printf("  ✗ %s: %v", in, err)
			continue
		}
		outName := strings.TrimSuffix(filepath.Base(in), ".enc")
		outPath := filepath.Join(*outDir, outName)
		of, err := os.Create(outPath)
		if err != nil {
			f.Close()
			log.Printf("  ✗ %s: %v", in, err)
			continue
		}
		err = decryptFile(f, of, key)
		f.Close()
		of.Close()
		if err != nil {
			os.Remove(outPath)
			log.Printf("  ✗ %s: %v", in, err)
			continue
		}
		fmt.Printf("  ✓ %s → %s\n", in, outPath)
	}
}

// ---------------------------------------------------------------------------
// #64 self-signed TLS for LAN-only HTTPS

func selfSignedTLS(hosts []string) (*tls.Config, error) {
	priv, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return nil, err
	}
	serial, _ := rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 128))
	tmpl := x509.Certificate{
		SerialNumber:          serial,
		Subject:               pkix.Name{CommonName: "tshare-local"},
		NotBefore:             time.Now().Add(-time.Hour),
		NotAfter:              time.Now().Add(365 * 24 * time.Hour),
		KeyUsage:              x509.KeyUsageDigitalSignature | x509.KeyUsageKeyEncipherment,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		BasicConstraintsValid: true,
	}
	for _, h := range hosts {
		if ip := net.ParseIP(h); ip != nil {
			tmpl.IPAddresses = append(tmpl.IPAddresses, ip)
		} else {
			tmpl.DNSNames = append(tmpl.DNSNames, h)
		}
	}
	der, err := x509.CreateCertificate(rand.Reader, &tmpl, &tmpl, &priv.PublicKey, priv)
	if err != nil {
		return nil, err
	}
	keyDER, err := x509.MarshalECPrivateKey(priv)
	if err != nil {
		return nil, err
	}
	certPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})
	keyPEM := pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: keyDER})
	cert, err := tls.X509KeyPair(certPEM, keyPEM)
	if err != nil {
		return nil, err
	}
	return &tls.Config{Certificates: []tls.Certificate{cert}}, nil
}
