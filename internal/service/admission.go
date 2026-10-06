package service

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"errors"
	"fmt"
	"strings"
	"time"
	"uuid"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/Duongondro/duongondro-api/internal/db"
)

// crockford is Crockford's base32 alphabet, as in invite ids and recovery codes.
const crockford = "0123456789ABCDEFGHJKMNPQRSTVWXYZ"

// AdmissionCodeLength is 16 characters, 80 bits: guessing one is out of reach without
// any limit beyond the sign-in routes' per-address one.
const AdmissionCodeLength = 16

// DefaultAdmissionLifetime is how long `duongondro-api admit` codes last by default.
const DefaultAdmissionLifetime = 30 * 24 * time.Hour

// NormalizeCode reads a typed code as the iOS RecoveryCode.normalise does: upper case,
// spaces, line breaks and hyphens dropped, O read as 0 and I and L as 1.
func NormalizeCode(typed string) string {
	var b strings.Builder
	for _, c := range strings.ToUpper(typed) {
		switch c {
		case '-', ' ', '\t', '\r', '\n':
		case 'O':
			b.WriteByte('0')
		case 'I', 'L':
			b.WriteByte('1')
		default:
			b.WriteRune(c)
		}
	}
	return b.String()
}

// FormatCode groups a code in fours with spaces, as it is printed and mailed.
func FormatCode(code string) string {
	var b strings.Builder
	for i, c := range code {
		if i > 0 && i%4 == 0 {
			b.WriteByte(' ')
		}
		b.WriteRune(c)
	}
	return b.String()
}

// randomCode draws n Crockford base32 characters; 32 divides 256, so taking five bits
// of each random byte is uniform.
func randomCode(n int) (string, error) {
	raw := make([]byte, n)
	if _, err := rand.Read(raw); err != nil {
		return "", err
	}
	for i, b := range raw {
		raw[i] = crockford[b&31]
	}
	return string(raw), nil
}

func hashCode(normalized string) []byte {
	sum := sha256.Sum256([]byte(normalized))
	return sum[:]
}

// Admissions issues admission codes: the bootstrap gate, for members nobody can invite
// (the first ones, while nobody has an account). Each admits one account, as a root
// of the invite tree.
type Admissions struct {
	q *db.Queries
}

func NewAdmissions(pool *pgxpool.Pool) *Admissions { return &Admissions{q: db.New(pool)} }

// Issue stores n fresh codes valid for lifetime and returns them, normalized; the
// server keeps only their SHA-256.
func (a *Admissions) Issue(ctx context.Context, n int, lifetime time.Duration) ([]string, error) {
	if n < 1 || n > 1000 {
		return nil, fmt.Errorf("issue between 1 and 1000 codes, not %d", n)
	}
	if lifetime <= 0 {
		return nil, fmt.Errorf("the lifetime must be positive")
	}
	expires := time.Now().Add(lifetime)
	codes := make([]string, n)
	for i := range codes {
		code, err := randomCode(AdmissionCodeLength)
		if err != nil {
			return nil, err
		}
		if err := a.q.CreateAdmissionCode(ctx, db.CreateAdmissionCodeParams{CodeHash: hashCode(code), ExpiresAt: expires}); err != nil {
			return nil, err
		}
		codes[i] = code
	}
	return codes, nil
}

// SignUpProof is what a sign-up presents: an invitation or an admission code, exactly
// one of them.
type SignUpProof struct {
	Invite        *InviteProof
	AdmissionCode string
}

// gate is a checked SignUpProof, stored with a ceremony or link until the account is
// made.
type gate struct {
	inviteID    *string
	admissionID *uuid.UUID
}

// checkProof is the sign-up gate: a live invite with its auth, or a live, unused
// admission code. A wrong, spent or expired one answers ErrNotFound, like an unknown
// invite.
func (s *SignIn) checkProof(ctx context.Context, p SignUpProof) (gate, error) {
	switch {
	case p.Invite != nil && p.AdmissionCode != "":
		return gate{}, invalid("present an invitation or an admission code, not both")
	case p.Invite != nil:
		inv, err := s.social.CheckInvite(ctx, p.Invite.ID, p.Invite.Auth)
		if err != nil {
			return gate{}, err
		}
		return gate{inviteID: &inv.ID}, nil
	case p.AdmissionCode != "":
		code := NormalizeCode(p.AdmissionCode)
		if len(code) != AdmissionCodeLength || strings.Trim(code, crockford) != "" {
			return gate{}, invalid("an admission code is %d characters of Crockford base32", AdmissionCodeLength)
		}
		row, err := s.q.GetLiveAdmissionCode(ctx, hashCode(code))
		if errors.Is(err, pgx.ErrNoRows) {
			return gate{}, ErrNotFound
		} else if err != nil {
			return gate{}, err
		}
		return gate{admissionID: &row.ID}, nil
	}
	return gate{}, invalid("an invitation or an admission code is needed to create an account")
}

// spendAdmission locks the code and checks it is still unused and live, inside the
// caller's transaction, so two sign-ups racing on one code make one account.
func spendAdmission(ctx context.Context, q *db.Queries, id uuid.UUID) error {
	code, err := q.LockAdmissionCode(ctx, id)
	if errors.Is(err, pgx.ErrNoRows) {
		return ErrNotFound
	} else if err != nil {
		return err
	}
	if code.UsedAt != nil || !code.ExpiresAt.After(time.Now()) {
		return ErrNotFound
	}
	return nil
}
