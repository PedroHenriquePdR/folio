package main

import (
	"bytes"
	"context"
	"crypto"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/asn1"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"math/big"
	"strings"
	"testing"
	"time"

	"github.com/smallstep/pkcs7"
	"github.com/sukujgrg/go-certstore"
)

type testIdentity struct {
	cert  *x509.Certificate
	key   crypto.Signer
	chain []*x509.Certificate
}

func (i testIdentity) Certificate(context.Context) (*x509.Certificate, error) { return i.cert, nil }
func (i testIdentity) CertificateChain(context.Context) ([]*x509.Certificate, error) {
	return i.chain, nil
}
func (i testIdentity) Signer(context.Context) (crypto.Signer, error) { return i.key, nil }
func (i testIdentity) Close()                                        {}

type testStore []certstore.Identity

func (s testStore) Identities(context.Context) ([]certstore.Identity, error) { return s, nil }
func (s testStore) Close()                                                   {}
func (s testStore) open(context.Context, string) (certstore.Store, error)    { return s, nil }

type testReply struct {
	Certificates []struct{ ID, Holder, Issuer, ValidUntil string }
	CMS          []byte
	Error        string
}

func invoke(t *testing.T, input io.Reader, open func(context.Context, string) (certstore.Store, error)) testReply {
	t.Helper()
	var output bytes.Buffer
	serve(input, &output, open)
	var obj map[string]json.RawMessage
	if err := json.Unmarshal(output.Bytes(), &obj); err != nil || len(obj) != 1 {
		t.Fatalf("expected a single JSON object with one result; got %q", output.String())
	}
	var reply testReply
	if err := json.Unmarshal(output.Bytes(), &reply); err != nil {
		t.Fatal(err)
	}
	return reply
}

func ecKey(t *testing.T) crypto.Signer {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	return key
}

func testOID(t *testing.T, s string) x509.OID {
	t.Helper()
	oid, err := x509.ParseOID(s)
	if err != nil {
		t.Fatal(err)
	}
	return oid
}

func fixture(t *testing.T, name string, parent *testIdentity, key crypto.Signer, configure func(*x509.Certificate)) testIdentity {
	t.Helper()
	serial, err := rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 120))
	if err != nil {
		t.Fatal(err)
	}
	now := time.Now()
	tmpl := &x509.Certificate{
		SerialNumber: serial, Subject: pkix.Name{CommonName: name},
		NotBefore: now.Add(-time.Hour), NotAfter: now.Add(time.Hour),
		BasicConstraintsValid: true, KeyUsage: x509.KeyUsageDigitalSignature | x509.KeyUsageContentCommitment,
		Policies: []x509.OID{testOID(t, "2.16.76.1.2.1.99")},
	}
	if configure != nil {
		configure(tmpl)
	}
	issuer, signingKey := tmpl, key
	if parent != nil {
		issuer, signingKey = parent.cert, parent.key
	}
	raw, err := x509.CreateCertificate(rand.Reader, tmpl, issuer, key.Public(), signingKey)
	if err != nil {
		t.Fatal(err)
	}
	cert, err := x509.ParseCertificate(raw)
	if err != nil {
		t.Fatal(err)
	}
	id := testIdentity{cert: cert, key: key, chain: []*x509.Certificate{cert}}
	if parent != nil {
		id.chain = append(id.chain, parent.chain...)
	}
	return id
}

func asCA(c *x509.Certificate) { c.IsCA = true; c.KeyUsage = x509.KeyUsageCertSign }

func testID(c *x509.Certificate) string { return fmt.Sprintf("%x", sha256.Sum256(c.Raw)) }

func signInput(id string, body []byte) io.Reader {
	return io.MultiReader(strings.NewReader(fmt.Sprintf("{\"action\":\"sign\",\"id\":%q}\n", id)), bytes.NewReader(body))
}

func TestProfileDetachedCMS(t *testing.T) {
	root := fixture(t, "Synthetic Root", nil, ecKey(t), asCA)
	inter := fixture(t, "Synthetic Issuer", &root, ecKey(t), asCA)
	first := fixture(t, "Other identity", &inter, ecKey(t), nil)
	rsaKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	for _, tc := range []struct {
		name, algorithm string
		key             crypto.Signer
	}{
		{"ECDSA", "1.2.840.10045.4.3.2", ecKey(t)}, {"RSA", "1.2.840.113549.1.1.11", rsaKey},
	} {
		t.Run(tc.name, func(t *testing.T) {
			chosen := fixture(t, "Selected", &inter, tc.key, nil)
			content := []byte("%PDF-1.7\nbytes covered before and after the signature hole\n%%EOF\n")
			got := invoke(t, signInput(testID(chosen.cert), content), testStore{first, chosen}.open)
			if got.Error != "" || len(got.CMS) == 0 {
				t.Fatalf("expected CMS, got error %q", got.Error)
			}
			message, err := pkcs7.Parse(got.CMS)
			if err != nil {
				t.Fatal(err)
			}
			if len(message.Content) != 0 || len(message.Signers) != 1 || !chosen.cert.Equal(message.GetOnlySigner()) {
				t.Fatal("expected detached content with the explicitly selected signer")
			}
			if len(message.Certificates) != 2 {
				t.Fatalf("expected leaf and intermediate, got %d certificates", len(message.Certificates))
			}
			message.Content = content
			if err := message.Verify(); err != nil {
				t.Fatalf("detached signature: %v", err)
			}
			message.Content = []byte("%PDF-1.7\nchanged")
			if err := message.Verify(); err == nil {
				t.Fatal("signature accepted modified bytes")
			}
			signer := message.Signers[0]
			if signer.DigestAlgorithm.Algorithm.String() != "2.16.840.1.101.3.4.2.1" || signer.DigestEncryptionAlgorithm.Algorithm.String() != tc.algorithm {
				t.Fatal("wrong digest or signature algorithm")
			}
			if len(signer.AuthenticatedAttributes) != 4 || len(signer.UnauthenticatedAttributes) != 0 {
				t.Fatal("unexpected signed or unsigned attributes")
			}
			var ct asn1.ObjectIdentifier
			if err := message.UnmarshalSignedAttribute(pkcs7.OIDAttributeContentType, &ct); err != nil || !ct.Equal(pkcs7.OIDData) {
				t.Fatal("incorrect content-type")
			}
			var ess struct {
				Certs []struct {
					Hash         []byte
					IssuerSerial struct {
						Names  []asn1.RawValue
						Serial *big.Int
					}
				}
			}
			if err := message.UnmarshalSignedAttribute(asn1.ObjectIdentifier{1, 2, 840, 113549, 1, 9, 16, 2, 47}, &ess); err != nil {
				t.Fatal(err)
			}
			leafHash := sha256.Sum256(chosen.cert.Raw)
			if len(ess.Certs) != 1 || !bytes.Equal(ess.Certs[0].Hash, leafHash[:]) {
				t.Fatal("ESS reference does not identify selected certificate")
			}
			is := ess.Certs[0].IssuerSerial
			if is.Serial.Cmp(chosen.cert.SerialNumber) != 0 || len(is.Names) != 1 || is.Names[0].Tag != 4 || !bytes.Equal(is.Names[0].Bytes, chosen.cert.RawIssuer) {
				t.Fatal("wrong ESS issuer or serial")
			}
			var policy struct {
				ID     asn1.ObjectIdentifier
				Digest struct {
					Algorithm pkix.AlgorithmIdentifier
					Hash      []byte
				}
				Qualifiers []asn1.RawValue `asn1:"optional"`
			}
			if err := message.UnmarshalSignedAttribute(asn1.ObjectIdentifier{1, 2, 840, 113549, 1, 9, 16, 2, 15}, &policy); err != nil {
				t.Fatal(err)
			}
			if policy.ID.String() != "2.16.76.1.7.1.11.1.3" || policy.Digest.Algorithm.Algorithm.String() != "2.16.840.1.101.3.4.2.1" || hex.EncodeToString(policy.Digest.Hash) != "23e4be4b9b362172e4ebb0e72b86a133ece5aad843d8651c6e38a0ba3f08fc60" {
				t.Fatal("incorrect signature policy or policy hash")
			}
		})
	}
}

func TestListAndSignCheckSuitabilityAndCurrentSelection(t *testing.T) {
	valid := fixture(t, "Usable", nil, ecKey(t), nil)
	other := fixture(t, "Usable", nil, ecKey(t), nil)
	invalid := []testIdentity{
		fixture(t, "CA", nil, ecKey(t), asCA),
		fixture(t, "Expired", nil, ecKey(t), func(c *x509.Certificate) { c.NotAfter = time.Now().Add(-time.Minute) }),
		fixture(t, "Premature", nil, ecKey(t), func(c *x509.Certificate) { c.NotBefore = time.Now().Add(time.Minute) }),
		fixture(t, "Encryption only", nil, ecKey(t), func(c *x509.Certificate) { c.KeyUsage = x509.KeyUsageKeyEncipherment }),
		fixture(t, "Other policy", nil, ecKey(t), func(c *x509.Certificate) { c.Policies = []x509.OID{testOID(t, "2.16.76.1.2.10.99")} }),
		fixture(t, "Unspecified policy", nil, ecKey(t), func(c *x509.Certificate) { c.Policies = nil }),
	}
	store := testStore{valid, other, valid}
	for _, id := range invalid {
		store = append(store, id)
	}
	list := invoke(t, strings.NewReader("{\"action\":\"list\"}\n"), store.open)
	if len(list.Certificates) != 2 || list.Certificates[0].ID == list.Certificates[1].ID {
		t.Fatalf("unexpected list: %+v", list)
	}
	for _, c := range list.Certificates {
		if c.Holder != "Usable" || c.Issuer != "Usable" || (c.ID != testID(valid.cert) && c.ID != testID(other.cert)) {
			t.Fatalf("unexpected identity: %+v", c)
		}
		if _, err := time.Parse(time.RFC3339, c.ValidUntil); err != nil {
			t.Fatal(err)
		}
	}
	for _, id := range append(invalid, fixture(t, "Removed", nil, ecKey(t), nil)) {
		if got := invoke(t, signInput(testID(id.cert), []byte("%PDF-1.7\n")), store.open); got.Error != "certificate_unavailable" {
			t.Fatalf("%s: %+v", id.cert.Subject.CommonName, got)
		}
	}
}

func TestA1CertificatePurposeAndKeySize(t *testing.T) {
	smallRSA, err := rsa.GenerateKey(rand.Reader, 1024)
	if err != nil {
		t.Fatal(err)
	}
	_, edKey, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	key := ecKey(t)
	accepted := []testIdentity{
		fixture(t, "General A1", nil, key, func(c *x509.Certificate) { c.Policies = []x509.OID{testOID(t, "2.16.76.1.2.1")} }),
		fixture(t, "Multipurpose A1", nil, key, func(c *x509.Certificate) {
			c.ExtKeyUsage = []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth, x509.ExtKeyUsageEmailProtection}
		}),
		fixture(t, "RFB personal clientAuth", nil, key, func(c *x509.Certificate) {
			c.KeyUsage = x509.KeyUsageDigitalSignature
			c.ExtKeyUsage = []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth}
			addOtherName(t, c, 1)
		}),
		fixture(t, "RFB personal emailProtection", nil, key, func(c *x509.Certificate) {
			c.KeyUsage = x509.KeyUsageDigitalSignature
			c.ExtKeyUsage = []x509.ExtKeyUsage{x509.ExtKeyUsageEmailProtection}
		}),
		fixture(t, "Document EKU", nil, key, func(c *x509.Certificate) {
			c.UnknownExtKeyUsage = []asn1.ObjectIdentifier{{1, 3, 6, 1, 5, 5, 7, 3, 36}}
		}),
	}
	rejected := []testIdentity{
		fixture(t, "A3", nil, key, func(c *x509.Certificate) { c.Policies = []x509.OID{testOID(t, "2.16.76.1.2.3.99")} }),
		fixture(t, "Small key", nil, smallRSA, nil), fixture(t, "Not supported by the store adapter", nil, edKey, nil),
		fixture(t, "TLS only", nil, key, func(c *x509.Certificate) {
			c.ExtKeyUsage = []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth, x509.ExtKeyUsageServerAuth}
		}),
		fixture(t, "Code only", nil, key, func(c *x509.Certificate) { c.ExtKeyUsage = []x509.ExtKeyUsage{x509.ExtKeyUsageCodeSigning} }),
		fixture(t, "Timestamp only", nil, key, func(c *x509.Certificate) { c.ExtKeyUsage = []x509.ExtKeyUsage{x509.ExtKeyUsageTimeStamping} }),
		fixture(t, "OCSP only", nil, key, func(c *x509.Certificate) { c.ExtKeyUsage = []x509.ExtKeyUsage{x509.ExtKeyUsageOCSPSigning} }),
		fixture(t, "A1 application", nil, key, func(c *x509.Certificate) {
			c.ExtKeyUsage = []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth}
			addOtherName(t, c, 8)
		}),
	}
	for _, id := range accepted {
		r := invoke(t, signInput(testID(id.cert), []byte("%PDF-1.7")), testStore{id}.open)
		if len(r.CMS) == 0 {
			t.Errorf("%s: %s", id.cert.Subject.CommonName, r.Error)
		}
	}
	for _, id := range rejected {
		r := invoke(t, signInput(testID(id.cert), []byte("%PDF-1.7")), testStore{id}.open)
		if r.Error != "certificate_unavailable" {
			t.Errorf("%s: expected certificate_unavailable", id.cert.Subject.CommonName)
		}
	}
}

func addOtherName(t *testing.T, cert *x509.Certificate, arc int) {
	t.Helper()
	kind, err := asn1.Marshal(asn1.ObjectIdentifier{2, 16, 76, 1, 3, arc})
	if err != nil {
		t.Fatal(err)
	}
	encoded, err := asn1.Marshal([]asn1.RawValue{{Class: 2, Tag: 0, IsCompound: true,
		Bytes: append(kind, 0xa0, 0x04, 0x0c, 0x02, 'I', 'D')}})
	if err != nil {
		t.Fatal(err)
	}
	cert.ExtraExtensions = append(cert.ExtraExtensions, pkix.Extension{Id: asn1.ObjectIdentifier{2, 5, 29, 17}, Value: encoded})
}

func TestInvalidRequestNeverOpensStore(t *testing.T) {
	bad := func(context.Context, string) (certstore.Store, error) {
		t.Fatal("invalid input opened store")
		return nil, nil
	}
	id := strings.Repeat("a", 64)
	for _, input := range []io.Reader{
		strings.NewReader("{}\n"), strings.NewReader("{\"action\":\"unsupported\"}\n"), strings.NewReader("{\"action\":\"list\"}"), strings.NewReader("{\"action\":\"list\"}\nextra"),
		strings.NewReader("{\"action\":\"list\",\"password\":\"" + strings.Repeat("a", 20000) + "\"}\n"),
		strings.NewReader("{\"action\":\"list\",\"module\":\"elsewhere\"}\n"), signInput(strings.ToUpper(id), []byte("%PDF-1.7")), signInput("", []byte("%PDF-1.7")), signInput(id, []byte("not a PDF")),
		io.MultiReader(signInput(id, []byte("%PDF-")), io.LimitReader(zeroes{}, 301<<20)),
	} {
		if got := invoke(t, input, bad); got.Error != "invalid_request" {
			t.Fatalf("unexpected error %q", got.Error)
		}
	}
}

type zeroes struct{}

func (zeroes) Read(b []byte) (int, error) { clear(b); return len(b), nil }

func TestBadKeyBindingAndStoreErrorsDoNotDiscloseDetails(t *testing.T) {
	oversized := fixture(t, "Certificate larger than the PDF signature reservation", nil, ecKey(t), func(c *x509.Certificate) {
		c.ExtraExtensions = []pkix.Extension{{Id: asn1.ObjectIdentifier{1, 3, 6, 1, 4, 1, 42, 1}, Value: make([]byte, 32<<10)}}
	})
	if got := invoke(t, signInput(testID(oversized.cert), []byte("%PDF-1.7")), testStore{oversized}.open); got.Error != "sign_failed" {
		t.Fatalf("oversized CMS: expected sign_failed")
	}
	id := fixture(t, "Synthetic", nil, ecKey(t), nil)
	id.key = ecKey(t)
	if got := invoke(t, signInput(testID(id.cert), []byte("%PDF-1.7")), testStore{id}.open); got.Error != "sign_failed" {
		t.Fatalf("wrong key: %+v", got)
	}
	for _, v := range []struct {
		err  error
		code string
	}{
		{fmt.Errorf("sensitive detail: %w", certstore.ErrIncorrectCredential), "password_required"},
		{fmt.Errorf("sensitive detail: %w", certstore.ErrCredentialRequired), "password_required"},
		{errors.New("sensitive store name"), "no_store"},
	} {
		open := func(context.Context, string) (certstore.Store, error) { return nil, v.err }
		if got := invoke(t, strings.NewReader("{\"action\":\"list\"}\n"), open); got.Error != v.code {
			t.Fatalf("wrong status %q", got.Error)
		}
	}
}
