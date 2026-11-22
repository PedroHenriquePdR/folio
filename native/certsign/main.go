package main

import (
	"bufio"
	"bytes"
	"context"
	"crypto/ecdsa"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/asn1"
	"encoding/hex"
	"encoding/json"
	"errors"
	"io"
	"os"
	"sort"
	"strings"
	"time"

	"github.com/sukujgrg/go-certstore"
)

const (
	headerLimit  = 16 << 10
	contentLimit = 301 << 20 // Folio's 300 MiB limit plus the PDF signature revision.
	cmsLimit     = 32 << 10
	outputLimit  = 1 << 20
)

type request struct {
	Action   string `json:"action"`
	ID       string `json:"id"`
	Password string `json:"password"`
}

type certificateView struct {
	ID         string `json:"id"`
	Holder     string `json:"holder"`
	Issuer     string `json:"issuer"`
	ValidUntil string `json:"validUntil"`
	StampName  string `json:"stampName"`
	TaxID      *taxID `json:"taxId,omitempty"`
}

type response struct {
	Certificates *[]certificateView `json:"certificates,omitempty"`
	CMS          []byte             `json:"cms,omitempty"`
	Error        string             `json:"error,omitempty"`
}

func main() { serve(os.Stdin, os.Stdout, openSystemStore) }

func serve(in io.Reader, out io.Writer, open func(context.Context, string) (certstore.Store, error)) {
	result := handle(in, open)
	data, err := json.Marshal(result)
	if err != nil || len(data)+1 > outputLimit {
		data = []byte(`{"error":"sign_failed"}`)
	}
	_, _ = out.Write(append(data, '\n'))
}

func handle(in io.Reader, open func(context.Context, string) (certstore.Store, error)) response {
	reader := bufio.NewReaderSize(in, headerLimit)
	line, err := reader.ReadSlice('\n')
	if err != nil {
		return response{Error: "invalid_request"}
	}
	var req request
	decoder := json.NewDecoder(bytes.NewReader(line))
	decoder.DisallowUnknownFields()
	if decoder.Decode(&req) != nil || decoder.Decode(&struct{}{}) != io.EOF ||
		len(req.Password) > 1024 || strings.ContainsRune(req.Password, 0) {
		return response{Error: "invalid_request"}
	}
	// The reader reuses line's backing array as the covered PDF bytes arrive.
	clear(line)
	var digest []byte
	switch req.Action {
	case "list":
		if _, err := reader.Peek(1); req.ID != "" || err != io.EOF {
			return response{Error: "invalid_request"}
		}
	case "sign":
		id, err := hex.DecodeString(req.ID)
		if err != nil || len(id) != sha256.Size || req.ID != hex.EncodeToString(id) {
			return response{Error: "invalid_request"}
		}
		header, err := reader.Peek(5)
		if err != nil || !bytes.Equal(header, []byte("%PDF-")) {
			return response{Error: "invalid_request"}
		}
		hash := sha256.New()
		n, err := io.Copy(hash, io.LimitReader(reader, contentLimit+1))
		if err != nil || n > contentLimit {
			return response{Error: "invalid_request"}
		}
		digest = hash.Sum(nil)
	default:
		return response{Error: "invalid_request"}
	}

	ctx := context.Background()
	store, err := open(ctx, req.Password)
	if err != nil {
		return storeFailure(err, "no_store")
	}
	defer store.Close()
	identities, err := store.Identities(ctx)
	if err != nil {
		return storeFailure(err, "no_store")
	}
	// Signers and identities own distinct OS handles. Close them before the store.
	defer func() {
		for _, id := range identities {
			if id != nil {
				id.Close()
			}
		}
	}()
	certificates := []certificateView{}
	seen := make(map[string]bool)
	for _, id := range identities {
		if id == nil {
			continue
		}
		cert, err := id.Certificate(ctx)
		if err != nil || !eligible(cert, time.Now()) {
			continue
		}
		sum := sha256.Sum256(cert.Raw)
		fingerprint := hex.EncodeToString(sum[:])
		if req.Action == "sign" {
			if req.ID != fingerprint {
				continue
			}
			return signIdentity(ctx, id, cert, digest)
		}
		if !seen[fingerprint] {
			seen[fingerprint] = true
			certificates = append(certificates, certificateView{
				ID: fingerprint, Holder: displayName(cert.Subject), Issuer: displayName(cert.Issuer),
				ValidUntil: cert.NotAfter.UTC().Format(time.RFC3339),
				StampName:  stampName(cert.Subject.CommonName), TaxID: holderTaxID(cert),
			})
		}
	}
	if req.Action == "sign" {
		return response{Error: "certificate_unavailable"}
	}
	sort.Slice(certificates, func(i, j int) bool {
		if certificates[i].Holder == certificates[j].Holder {
			return certificates[i].ID < certificates[j].ID
		}
		return certificates[i].Holder < certificates[j].Holder
	})
	return response{Certificates: &certificates}
}

func displayName(name pkix.Name) string {
	if name.CommonName != "" {
		return name.CommonName
	}
	return name.String()
}

func eligible(cert *x509.Certificate, now time.Time) bool {
	if cert == nil || cert.IsCA || now.Before(cert.NotBefore) || now.After(cert.NotAfter) ||
		cert.KeyUsage&(x509.KeyUsageDigitalSignature|x509.KeyUsageContentCommitment) == 0 || !documentUsage(cert) || !personalProfile(cert) {
		return false
	}
	switch pub := cert.PublicKey.(type) {
	case *rsa.PublicKey:
		if pub.N.BitLen() < 2048 {
			return false
		}
	case *ecdsa.PublicKey:
		if pub.Curve.Params().BitSize < 256 {
			return false
		}
	default:
		return false
	}
	// DOC-ICP-04 identifies an A1 signing profile under this arc. A policy OID
	// in a leaf certificate is a selection criterion, not evidence of trust.
	const a1 = "2.16.76.1.2.1"
	for _, policy := range cert.Policies {
		id := policy.String()
		if id == a1 || strings.HasPrefix(id, a1+".") {
			return true
		}
	}
	return false
}

func documentUsage(cert *x509.Certificate) bool {
	if len(cert.ExtKeyUsage) == 0 && len(cert.UnknownExtKeyUsage) == 0 {
		return true
	}
	var clientAuth, serverAuth bool
	for _, purpose := range cert.ExtKeyUsage {
		// DOC-ICP-04 permits clientAuth or emailProtection on personal A1 leaves,
		// with digitalSignature alone. Older TLS server leaves may also carry clientAuth.
		switch purpose {
		case x509.ExtKeyUsageAny, x509.ExtKeyUsageEmailProtection:
			return true
		case x509.ExtKeyUsageClientAuth:
			clientAuth = true
		case x509.ExtKeyUsageServerAuth:
			serverAuth = true
		}
	}
	for _, purpose := range cert.UnknownExtKeyUsage {
		if purpose.Equal(asn1.ObjectIdentifier{1, 3, 6, 1, 5, 5, 7, 3, 36}) ||
			purpose.Equal(asn1.ObjectIdentifier{1, 3, 6, 1, 4, 1, 311, 10, 3, 12}) {
			return true
		}
	}
	return clientAuth && !serverAuth
}

func personalProfile(cert *x509.Certificate) bool {
	// DOC-ICP-04 places this otherName on equipment/application certificates,
	// which may share the A1 policy and clientAuth EKU with personal signers.
	return allOtherNames(cert, func(kind asn1.ObjectIdentifier, _ []byte) bool {
		return !kind.Equal(asn1.ObjectIdentifier{2, 16, 76, 1, 3, 8})
	})
}

func signIdentity(ctx context.Context, id certstore.Identity, cert *x509.Certificate, digest []byte) response {
	chain, err := id.CertificateChain(ctx)
	if err != nil {
		return storeFailure(err, "sign_failed")
	}
	signer, err := id.Signer(ctx)
	if err != nil {
		return storeFailure(err, "sign_failed")
	}
	defer certstore.CloseSigner(signer)
	if !eligible(cert, time.Now()) {
		return response{Error: "certificate_unavailable"}
	}
	der, err := detachedCMS(cert, chain, signer, digest)
	if err != nil || len(der) > cmsLimit {
		return storeFailure(err, "sign_failed")
	}
	return response{CMS: der}
}

func storeFailure(err error, fallback string) response {
	if errors.Is(err, certstore.ErrIncorrectCredential) || errors.Is(err, certstore.ErrCredentialRequired) {
		return response{Error: "password_required"}
	}
	return response{Error: fallback}
}
