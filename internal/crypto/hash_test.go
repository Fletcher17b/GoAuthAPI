package crypto

import (
	"strings"
	"testing"

	"golang.org/x/crypto/bcrypt"
)

func TestHashPassword(t *testing.T) {
	password := "my-secure-password"

	hash, err := HashPassword(password)
	if err != nil {
		t.Fatalf("HashPassword() returned unexpected error: %v", err)
	}

	if hash == "" {
		t.Fatal("HashPassword() returned an empty hash")
	}

	if hash == password {
		t.Fatal("HashPassword() returned the plaintext password")
	}

	if err := bcrypt.CompareHashAndPassword([]byte(hash), []byte(password)); err != nil {
		t.Fatalf("generated hash does not match password: %v", err)
	}

	cost, err := bcrypt.Cost([]byte(hash))
	if err != nil {
		t.Fatalf("bcrypt.Cost() returned unexpected error: %v", err)
	}

	if cost != 12 {
		t.Errorf("bcrypt cost = %d, want 12", cost)
	}
}

func TestHashPassword_GeneratesDifferentHashes(t *testing.T) {
	password := "my-secure-password"

	hash1, err := HashPassword(password)
	if err != nil {
		t.Fatalf("HashPassword() returned unexpected error: %v", err)
	}

	hash2, err := HashPassword(password)
	if err != nil {
		t.Fatalf("HashPassword() returned unexpected error: %v", err)
	}

	if hash1 == hash2 {
		t.Error("HashPassword() generated identical hashes for the same password")
	}
}

func TestHashPassword_EmptyPassword(t *testing.T) {
	hash, err := HashPassword("")
	if err != nil {
		t.Fatalf("HashPassword() returned unexpected error: %v", err)
	}

	if hash == "" {
		t.Fatal("HashPassword() returned an empty hash")
	}

	if err := bcrypt.CompareHashAndPassword([]byte(hash), []byte("")); err != nil {
		t.Fatalf("generated hash does not match empty password: %v", err)
	}
}

func TestComparePassword(t *testing.T) {
	password := "my-secure-password"

	hash, err := HashPassword(password)
	if err != nil {
		t.Fatalf("HashPassword() returned unexpected error: %v", err)
	}

	tests := []struct {
		name     string
		hash     string
		password string
		wantErr  bool
	}{
		{
			name:     "correct password",
			hash:     hash,
			password: password,
			wantErr:  false,
		},
		{
			name:     "incorrect password",
			hash:     hash,
			password: "wrong-password",
			wantErr:  true,
		},
		{
			name:     "empty password",
			hash:     hash,
			password: "",
			wantErr:  true,
		},
		{
			name:     "invalid hash",
			hash:     "not-a-valid-bcrypt-hash",
			password: password,
			wantErr:  true,
		},
		{
			name:     "empty hash",
			hash:     "",
			password: password,
			wantErr:  true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := ComparePassword(tt.hash, tt.password)

			if (err != nil) != tt.wantErr {
				t.Errorf(
					"ComparePassword() error = %v, wantErr = %v",
					err,
					tt.wantErr,
				)
			}
		})
	}
}

func TestHashToken(t *testing.T) {
	tests := []struct {
		name   string
		token  string
		secret string
		want   string
	}{
		{
			name:   "known values",
			token:  "my-token",
			secret: "my-secret",
			want:   "84ddc211c015c2a3f591b4f78e5e885b612673c06555b1034090f5f29db3e1de",
		},
		{
			name:   "empty token",
			token:  "",
			secret: "my-secret",
		},
		{
			name:   "empty secret",
			token:  "my-token",
			secret: "",
		},
		{
			name:   "both empty",
			token:  "",
			secret: "",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := HashToken(tt.token, tt.secret)

			if got == "" {
				t.Fatal("HashToken() returned an empty string")
			}

			// HMAC-SHA256 produces 32 bytes, which hex-encodes to 64 chars.
			if len(got) != 64 {
				t.Errorf("HashToken() returned length %d, want 64", len(got))
			}

			if tt.want != "" && got != tt.want {
				t.Errorf("HashToken() = %q, want %q", got, tt.want)
			}
		})
	}
}

func TestHashToken_Deterministic(t *testing.T) {
	token := "my-token"
	secret := "my-secret"

	hash1 := HashToken(token, secret)
	hash2 := HashToken(token, secret)

	if hash1 != hash2 {
		t.Errorf(
			"HashToken() produced different hashes for the same input: %q != %q",
			hash1,
			hash2,
		)
	}
}

func TestHashToken_ChangesWithToken(t *testing.T) {
	secret := "my-secret"

	hash1 := HashToken("token-1", secret)
	hash2 := HashToken("token-2", secret)

	if hash1 == hash2 {
		t.Error("HashToken() produced the same hash for different tokens")
	}
}

func TestHashToken_ChangesWithSecret(t *testing.T) {
	token := "my-token"

	hash1 := HashToken(token, "secret-1")
	hash2 := HashToken(token, "secret-2")

	if hash1 == hash2 {
		t.Error("HashToken() produced the same hash for different secrets")
	}
}

func TestHashToken_IsHexEncoded(t *testing.T) {
	hash := HashToken("my-token", "my-secret")

	if strings.Trim(hash, "0123456789abcdef") != "" {
		t.Errorf("HashToken() returned non-hex characters: %q", hash)
	}
}
