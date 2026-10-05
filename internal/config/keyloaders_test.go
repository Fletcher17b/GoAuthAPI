package config

import (
	"crypto/ed25519"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/pem"
	"os"
	"path/filepath"
	"testing"
)

// ---------- test helpers ----------
func genRSAKeyPair(t *testing.T) *rsa.PrivateKey {
	t.Helper()
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("failed to generate RSA key for test fixture: %v", err)
	}
	return key
}

func writePKCS8PrivatePEM(t *testing.T, dir, filename string, key *rsa.PrivateKey) string {
	t.Helper()
	der, err := x509.MarshalPKCS8PrivateKey(key)
	if err != nil {
		t.Fatalf("failed to marshal PKCS8 private key: %v", err)
	}
	block := &pem.Block{Type: "PRIVATE KEY", Bytes: der}
	path := filepath.Join(dir, filename)
	if err := os.WriteFile(path, pem.EncodeToMemory(block), 0o600); err != nil {
		t.Fatalf("failed to write private key file: %v", err)
	}
	return path
}

func writePKCS1PrivatePEM(t *testing.T, dir, filename string, key *rsa.PrivateKey) string {
	t.Helper()
	der := x509.MarshalPKCS1PrivateKey(key)
	block := &pem.Block{Type: "RSA PRIVATE KEY", Bytes: der}
	path := filepath.Join(dir, filename)
	if err := os.WriteFile(path, pem.EncodeToMemory(block), 0o600); err != nil {
		t.Fatalf("failed to write private key file: %v", err)
	}
	return path
}
func writePKIXPublicPEM(t *testing.T, dir, filename string, pub *rsa.PublicKey) string {
	t.Helper()
	der, err := x509.MarshalPKIXPublicKey(pub)
	if err != nil {
		t.Fatalf("failed to marshal PKIX public key: %v", err)
	}
	block := &pem.Block{Type: "PUBLIC KEY", Bytes: der}
	path := filepath.Join(dir, filename)
	if err := os.WriteFile(path, pem.EncodeToMemory(block), 0o600); err != nil {
		t.Fatalf("failed to write public key file: %v", err)
	}
	return path
}

// ---------- LoadPrivateKey ----------
func TestLoadPrivateKey(t *testing.T) {
	dir := t.TempDir()
	rsaKey := genRSAKeyPair(t)

	t.Run("valid PKCS8 RSA private key", func(t *testing.T) {
		path := writePKCS8PrivatePEM(t, dir, "valid_private.pem", rsaKey)

		got, err := LoadPrivateKey(path)
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if got == nil {
			t.Fatal("expected non-nil key")
		}
		if !got.Equal(rsaKey) {
			t.Fatal("loaded key does not match the original key")
		}
	})

	t.Run("file does not exist", func(t *testing.T) {
		_, err := LoadPrivateKey(filepath.Join(dir, "does_not_exist.pem"))
		if err == nil {
			t.Fatal("expected error for missing file, got nil")
		}
	})

	t.Run("malformed PEM content", func(t *testing.T) {
		path := filepath.Join(dir, "malformed.pem")
		if err := os.WriteFile(path, []byte("this is not a PEM file"), 0o600); err != nil {
			t.Fatalf("failed to write fixture: %v", err)
		}

		_, err := LoadPrivateKey(path)
		if err == nil {
			t.Fatal("expected error for malformed PEM, got nil")
		}
	})

	t.Run("empty file", func(t *testing.T) {
		path := filepath.Join(dir, "empty.pem")
		if err := os.WriteFile(path, []byte(""), 0o600); err != nil {
			t.Fatalf("failed to write fixture: %v", err)
		}

		_, err := LoadPrivateKey(path)
		if err == nil {
			t.Fatal("expected error for empty file, got nil")
		}
	})

	t.Run("PKCS1-encoded key rejected (only PKCS8 supported)", func(t *testing.T) {
		path := writePKCS1PrivatePEM(t, dir, "pkcs1_private.pem", rsaKey)

		_, err := LoadPrivateKey(path)
		if err == nil {
			t.Fatal("expected error for PKCS1 key, since LoadPrivateKey only parses PKCS8")
		}
	})

	t.Run("valid PKCS8 but non-RSA key type rejected", func(t *testing.T) {
		_, edPriv, err := ed25519.GenerateKey(rand.Reader)
		if err != nil {
			t.Fatalf("failed to generate ed25519 key: %v", err)
		}
		der, err := x509.MarshalPKCS8PrivateKey(edPriv)
		if err != nil {
			t.Fatalf("failed to marshal ed25519 key: %v", err)
		}
		path := filepath.Join(dir, "ed25519_private.pem")
		block := &pem.Block{Type: "PRIVATE KEY", Bytes: der}
		if err := os.WriteFile(path, pem.EncodeToMemory(block), 0o600); err != nil {
			t.Fatalf("failed to write fixture: %v", err)
		}

		_, err = LoadPrivateKey(path)
		if err == nil {
			t.Fatal("expected error for non-RSA PKCS8 key, got nil")
		}
	})

	t.Run("directory path instead of file", func(t *testing.T) {
		_, err := LoadPrivateKey(dir)
		if err == nil {
			t.Fatal("expected error when path is a directory, got nil")
		}
	})
}

// ---------- LoadPublicKey ----------
func TestLoadPublicKey(t *testing.T) {
	dir := t.TempDir()
	rsaKey := genRSAKeyPair(t)

	t.Run("valid PKIX RSA public key", func(t *testing.T) {
		path := writePKIXPublicPEM(t, dir, "valid_public.pem", &rsaKey.PublicKey)

		got, err := LoadPublicKey(path)
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if got == nil {
			t.Fatal("expected non-nil key")
		}
		if !got.Equal(&rsaKey.PublicKey) {
			t.Fatal("loaded public key does not match the original key")
		}
	})

	t.Run("file does not exist", func(t *testing.T) {
		_, err := LoadPublicKey(filepath.Join(dir, "does_not_exist.pem"))
		if err == nil {
			t.Fatal("expected error for missing file, got nil")
		}
	})

	t.Run("malformed PEM content", func(t *testing.T) {
		path := filepath.Join(dir, "malformed_pub.pem")
		if err := os.WriteFile(path, []byte("not a pem file"), 0o600); err != nil {
			t.Fatalf("failed to write fixture: %v", err)
		}

		_, err := LoadPublicKey(path)
		if err == nil {
			t.Fatal("expected error for malformed PEM, got nil")
		}
	})

	t.Run("private key file passed instead of public key", func(t *testing.T) {
		path := writePKCS8PrivatePEM(t, dir, "priv_as_pub.pem", rsaKey)

		_, err := LoadPublicKey(path)
		if err == nil {
			t.Fatal("expected error when a PKCS8 private key block is parsed as a PKIX public key")
		}
	})

	t.Run("valid PKIX but non-RSA public key rejected", func(t *testing.T) {
		edPub, _, err := ed25519.GenerateKey(rand.Reader)
		if err != nil {
			t.Fatalf("failed to generate ed25519 key: %v", err)
		}
		der, err := x509.MarshalPKIXPublicKey(edPub)
		if err != nil {
			t.Fatalf("failed to marshal ed25519 public key: %v", err)
		}
		path := filepath.Join(dir, "ed25519_public.pem")
		block := &pem.Block{Type: "PUBLIC KEY", Bytes: der}
		if err := os.WriteFile(path, pem.EncodeToMemory(block), 0o600); err != nil {
			t.Fatalf("failed to write fixture: %v", err)
		}

		_, err = LoadPublicKey(path)
		if err == nil {
			t.Fatal("expected error for non-RSA PKIX key, got nil")
		}
	})
}

// ---------- getFilePath ----------
func TestGetFilePath(t *testing.T) {
	t.Run("env var set takes precedence", func(t *testing.T) {
		t.Setenv("TEST_KEY_PATH", "/custom/path/key.pem")

		got := getFilePath("TEST_KEY_PATH", "irrelevant_secret", "creds/default.pem")
		if got != "/custom/path/key.pem" {
			t.Fatalf("got %q, want %q", got, "/custom/path/key.pem")
		}
	})

	t.Run("falls back to default when env unset and secret file absent", func(t *testing.T) {
		t.Setenv("TEST_KEY_PATH", "")

		got := getFilePath("TEST_KEY_PATH", "some_secret_that_should_not_exist_12345", "creds/default.pem")
		if got != "creds/default.pem" {
			t.Fatalf("got %q, want default %q", got, "creds/default.pem")
		}
	})

	// NOTE: the "secret file exists at /run/secrets/<name>" branch is not covered
	// here because it requires write access to /run/secrets, which is normally
	// only available inside a container with a mounted secrets volume (e.g. Docker
	// Swarm/Kubernetes secrets). If /run/secrets is writable in the CI environment,
	// this can be extended to create a real file there and assert getFilePath
	// returns "/run/secrets/<name>".
}

// ---------- LoadKeys ----------
func TestLoadKeys(t *testing.T) {
	t.Run("valid key pair loads successfully via env-configured paths", func(t *testing.T) {
		dir := t.TempDir()
		rsaKey := genRSAKeyPair(t)

		privPath := writePKCS8PrivatePEM(t, dir, "private.pem", rsaKey)
		pubPath := writePKIXPublicPEM(t, dir, "public.pem", &rsaKey.PublicKey)

		t.Setenv("AUTH_PRIVATE_KEY_PATH", privPath)
		t.Setenv("AUTH_PUBLIC_KEY_PATH", pubPath)

		priv, pub, err := LoadKeys()
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if priv == nil || pub == nil {
			t.Fatal("expected non-nil private and public keys")
		}
		if !priv.Equal(rsaKey) {
			t.Error("loaded private key does not match fixture")
		}
		if !pub.Equal(&rsaKey.PublicKey) {
			t.Error("loaded public key does not match fixture")
		}
	})

	t.Run("missing private key file returns error", func(t *testing.T) {
		dir := t.TempDir()
		rsaKey := genRSAKeyPair(t)
		pubPath := writePKIXPublicPEM(t, dir, "public.pem", &rsaKey.PublicKey)

		t.Setenv("AUTH_PRIVATE_KEY_PATH", filepath.Join(dir, "missing_private.pem"))
		t.Setenv("AUTH_PUBLIC_KEY_PATH", pubPath)

		priv, pub, err := LoadKeys()
		if err == nil {
			t.Fatal("expected error when private key file is missing")
		}
		if priv != nil || pub != nil {
			t.Fatal("expected nil keys on error")
		}
	})

	t.Run("missing public key file returns error", func(t *testing.T) {
		dir := t.TempDir()
		rsaKey := genRSAKeyPair(t)
		privPath := writePKCS8PrivatePEM(t, dir, "private.pem", rsaKey)

		t.Setenv("AUTH_PRIVATE_KEY_PATH", privPath)
		t.Setenv("AUTH_PUBLIC_KEY_PATH", filepath.Join(dir, "missing_public.pem"))

		priv, pub, err := LoadKeys()
		if err == nil {
			t.Fatal("expected error when public key file is missing")
		}
		if priv != nil || pub != nil {
			t.Fatal("expected nil keys on error")
		}
	})

	t.Run("falls back to default creds path when env unset", func(t *testing.T) {
		// With no env vars set and no /run/secrets/* entries, LoadKeys should
		// attempt to read from "creds/private.pem" and "creds/public.pem"
		// relative to the working directory, and fail since they don't exist
		// in the test environment.
		t.Setenv("AUTH_PRIVATE_KEY_PATH", "")
		t.Setenv("AUTH_PUBLIC_KEY_PATH", "")

		_, _, err := LoadKeys()
		if err == nil {
			t.Skip("creds/private.pem and/or creds/public.pem unexpectedly exist in the working directory; skipping negative-path assertion")
		}
	})
}

// ---------- LoadTokenSecret ----------
func TestLoadTokenSecret(t *testing.T) {
	t.Run("returns configured secret", func(t *testing.T) {
		t.Setenv("TOKEN_SECRET", "super-secret-value")

		got, err := LoadTokenSecret()
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if got != "super-secret-value" {
			t.Fatalf("got %q, want %q", got, "super-secret-value")
		}
	})
}
