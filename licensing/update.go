package main

// Signed auto-update manifests.
//
// The update system mirrors the licensing one's trust model, but with a
// SEPARATE key. The update-signing private key lives only on the release
// machine (your PC) and is never on the server. So even someone who fully
// owns netvis.cc cannot push code to users: they can host files, but a
// manifest they alter fails its signature, and a build they swap in fails its
// SHA-256. The flip side is that the server alone can't fix a bad release
// either - every update has to be signed here and uploaded.
//
// The signature covers the EXACT bytes of update.json. The client fetches
// those bytes, verifies them against the update public key compiled into it,
// then trusts the version/url/sha256 inside. So update.json must be served
// byte-for-byte: any re-encoding invalidates it (see the server side).

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"log"
	"os"
	"path/filepath"
	"strings"
)

// The manifest, exactly as it is signed and served. Field order here is the
// byte order in the file (Go marshals struct fields in declaration order), so
// don't reorder these without re-signing.
type updateManifest struct {
	Version string `json:"version"`
	URL     string `json:"url"`
	SHA256  string `json:"sha256"`
	Notes   string `json:"notes,omitempty"`
}

// signBytes signs the raw bytes with ECDSA P-256, returning raw r||s hex -
// the same shape the client's CNG verify expects. This is what covers
// update.json.
func signBytes(priv *ecdsa.PrivateKey, data []byte) (string, error) {
	digest := sha256.Sum256(data)
	r, s, err := ecdsa.Sign(rand.Reader, priv, digest[:])
	if err != nil {
		return "", err
	}
	out := make([]byte, 64)
	r.FillBytes(out[:32])
	s.FillBytes(out[32:])
	return hex.EncodeToString(out), nil
}

func sha256File(path string) (string, int64, error) {
	f, err := os.Open(path)
	if err != nil {
		return "", 0, err
	}
	defer f.Close()
	h := sha256.New()
	n, err := io.Copy(h, f)
	if err != nil {
		return "", 0, err
	}
	return hex.EncodeToString(h.Sum(nil)), n, nil
}

func copyFile(dst, src string) error {
	in, err := os.Open(src)
	if err != nil {
		return err
	}
	defer in.Close()
	if err := os.MkdirAll(filepath.Dir(dst), 0o755); err != nil {
		return err
	}
	out, err := os.Create(dst)
	if err != nil {
		return err
	}
	defer out.Close()
	_, err = io.Copy(out, in)
	return err
}

// cmdGenUpdateKeys makes a fresh update-signing key, SEPARATE from the
// licensing key. The private half stays on your release machine only; the
// public half is compiled into the client as kUpdatePublicKey.
//
// With -write it saves the private key to update_private_key.txt directly (so
// deploy.bat can set it up without the secret ever passing through a batch
// variable) and prints one machine-readable line the script can parse:
//
//	UPDATE_PUBLIC_KEY=<hex>
func cmdGenUpdateKeys(args []string) {
	fs := flag.NewFlagSet("genupdatekeys", flag.ExitOnError)
	write := fs.Bool("write", false, "write the private key to update_private_key.txt in this folder")
	fs.Parse(args)

	priv, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		log.Fatal(err)
	}
	d := make([]byte, 32)
	priv.D.FillBytes(d)
	pub := make([]byte, 64)
	priv.PublicKey.X.FillBytes(pub[:32])
	priv.PublicKey.Y.FillBytes(pub[32:])
	pubHex := hex.EncodeToString(pub)

	if *write {
		const keyFile = "update_private_key.txt"
		if _, err := os.Stat(keyFile); err == nil {
			log.Fatalf("%s already exists - refusing to overwrite an existing key", keyFile)
		}
		if err := os.WriteFile(keyFile, []byte(hex.EncodeToString(d)+"\n"), 0o600); err != nil {
			log.Fatalf("writing %s: %v", keyFile, err)
		}
		// The single line deploy.bat greps for.
		fmt.Printf("UPDATE_PUBLIC_KEY=%s\n", pubHex)
		fmt.Printf("Wrote private key to %s (keep it secret, never commit it).\n", keyFile)
		return
	}

	fmt.Println("Update-signing key (SEPARATE from the licensing key).")
	fmt.Println()
	fmt.Println("1. Save the private key on THIS machine only - never commit it, never")
	fmt.Println("   put it on the server:")
	fmt.Printf("     echo %s > update_private_key.txt\n\n", hex.EncodeToString(d))
	fmt.Println("2. Put the public key in src/license.cpp as kUpdatePublicKey, then rebuild:")
	fmt.Printf("     const char* const kUpdatePublicKey =\n         \"%s\";\n\n", pubHex)
	fmt.Println("If this key leaks, an attacker who also controls the download path could")
	fmt.Println("push a malicious update. Treat update_private_key.txt like a signing cert.")
}

func loadUpdateKey(keyArg string) *ecdsa.PrivateKey {
	raw := keyArg
	if strings.HasPrefix(keyArg, "@") { // @path reads the key from a file
		b, err := os.ReadFile(keyArg[1:])
		if err != nil {
			log.Fatalf("reading key file %s: %v", keyArg[1:], err)
		}
		raw = string(b)
	}
	// Keep only hex characters. A key file can pick up a UTF-8 BOM, CRLF line
	// endings, or - the usual culprit on Windows - UTF-16 encoding from
	// PowerShell's `echo x > file`. Filtering to hex recovers the key from any
	// of those instead of failing on an invisible byte.
	var b strings.Builder
	for _, c := range raw {
		if (c >= '0' && c <= '9') || (c >= 'a' && c <= 'f') || (c >= 'A' && c <= 'F') {
			b.WriteRune(c)
		}
	}
	hexKey := b.String()
	if len(hexKey) != 64 {
		log.Fatalf("update key: expected 64 hex characters, found %d after cleaning.\n"+
			"Fix: delete update_private_key.txt and run `deploy.bat` again to regenerate it,\n"+
			"or make sure that file is one line of plain ASCII hex.", len(hexKey))
	}
	priv, err := parseSigningKey(hexKey) // reused from sign.go: validates a P-256 scalar
	if err != nil {
		log.Fatalf("update key: %v", err)
	}
	return priv
}

// cmdSignUpdate builds and signs a release manifest. Run it on your release
// machine after building the installer:
//
//	licensing signupdate -version 1.1.0 \
//	    -file ..\installer\output\netvis-setup.exe \
//	    -key @update_private_key.txt
//
// It writes update.json, update.json.sig and a versioned copy of the exe into
// updates/windows/. Upload those three files to the server's matching folder.
func cmdSignUpdate(args []string) {
	fs := flag.NewFlagSet("signupdate", flag.ExitOnError)
	version := fs.String("version", "", "release version, e.g. 1.1.0 (required)")
	file := fs.String("file", "", "the built installer/exe to publish (required)")
	keyArg := fs.String("key", "", "update private key: hex, or @path-to-file (required)")
	baseURL := fs.String("baseurl", "https://netvis.cc/updates/windows", "public URL folder the files are served from")
	outDir := fs.String("out", "updates/windows", "where to write the manifest + versioned exe")
	notes := fs.String("notes", "", "optional short release notes shown to users")
	platform := fs.String("platform", "windows", "windows or macos (names the file: .exe or .dmg)")
	fs.Parse(args)

	if *version == "" || *file == "" || *keyArg == "" {
		fs.Usage()
		log.Fatal("signupdate needs -version, -file and -key")
	}
	priv := loadUpdateKey(*keyArg)

	sum, size, err := sha256File(*file)
	if err != nil {
		log.Fatalf("hashing %s: %v", *file, err)
	}

	ext := ".exe"
	if *platform == "macos" {
		ext = ".dmg"
	}
	artifact := fmt.Sprintf("netvis-%s-%s%s", *platform, *version, ext)
	base := strings.TrimRight(*baseURL, "/")

	m := updateManifest{
		Version: *version,
		URL:     base + "/" + artifact,
		SHA256:  sum,
		Notes:   *notes,
	}
	// Marshal WITHOUT indentation and sign these exact bytes. The client
	// verifies the same bytes it downloads, so the server must not re-encode.
	manifestBytes, err := json.Marshal(m)
	if err != nil {
		log.Fatal(err)
	}
	sig, err := signBytes(priv, manifestBytes)
	if err != nil {
		log.Fatal(err)
	}

	if err := os.MkdirAll(*outDir, 0o755); err != nil {
		log.Fatal(err)
	}
	mustWrite := func(name string, data []byte) {
		p := filepath.Join(*outDir, name)
		if err := os.WriteFile(p, data, 0o644); err != nil {
			log.Fatalf("writing %s: %v", p, err)
		}
	}
	mustWrite("update.json", manifestBytes)
	mustWrite("update.json.sig", []byte(sig))
	if err := copyFile(filepath.Join(*outDir, artifact), *file); err != nil {
		log.Fatalf("copying artifact: %v", err)
	}

	fmt.Printf("Wrote %s/ :\n", *outDir)
	fmt.Printf("  update.json      %d bytes  (sha256 %s)\n", len(manifestBytes), func() string {
		h := sha256.Sum256(manifestBytes)
		return hex.EncodeToString(h[:])
	}())
	fmt.Printf("  update.json.sig  %d bytes\n", len(sig))
	fmt.Printf("  %s  %d bytes\n\n", artifact, size)
	fmt.Printf("Upload all three to the server so they are reachable at:\n  %s/\n", base)
	fmt.Println("Then clients pick it up within ~10s of launch, or via Settings -> Check now.")
}
