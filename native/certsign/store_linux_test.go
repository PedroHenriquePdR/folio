package main

import (
	"bytes"
	"crypto/sha256"
	"crypto/x509"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"

	"github.com/smallstep/pkcs7"
)

func TestNativeNSSProcess(t *testing.T) {
	if root := os.Getenv("FOLIO_NSS_TEST_CHILD"); root != "" {
		if !filepath.IsAbs(root) || os.Getenv("HOME") != filepath.Join(root, "synthetic-home") || os.Getenv("XDG_DATA_HOME") != filepath.Join(root, "synthetic-data") {
			t.Fatal("fixture subprocess requires its own home and data directory")
		}
		main()
		os.Exit(0)
	}
	for _, tool := range []string{"certutil", "pk12util", "openssl"} {
		if _, err := exec.LookPath(tool); err != nil {
			t.Skipf("NSS fixture requires %s", tool)
		}
	}
	fixtures := t.ArtifactDir()
	home := filepath.Join(fixtures, "synthetic-home")
	xdg := filepath.Join(fixtures, "synthetic-data")
	modern := filepath.Join(xdg, "pki", "nssdb")
	legacy := filepath.Join(home, ".pki", "nssdb")
	if err := os.MkdirAll(home, 0700); err != nil {
		t.Fatal(err)
	}

	call := func(input io.Reader) testReply {
		t.Helper()
		cmd := exec.Command(os.Args[0], "-test.run=^TestNativeNSSProcess$")
		cmd.Env = append(os.Environ(), "HOME="+home, "XDG_DATA_HOME="+xdg, "FOLIO_NSS_TEST_CHILD="+fixtures)
		cmd.Stdin = input
		var stdout, stderr bytes.Buffer
		cmd.Stdout, cmd.Stderr = &stdout, &stderr
		if err := cmd.Run(); err != nil || stderr.Len() != 0 {
			t.Fatalf("helper exit %v, stderr size %d", err, stderr.Len())
		}
		var r testReply
		if err := json.Unmarshal(stdout.Bytes(), &r); err != nil {
			t.Fatal(err)
		}
		return r
	}
	list := func(password string) testReply {
		return call(strings.NewReader(fmt.Sprintf("{\"action\":\"list\",\"password\":%q}\n", password)))
	}
	if got := list(""); got.Error != "no_store" {
		t.Fatalf("absent store: %+v", got)
	}
	if _, err := os.Stat(modern); !os.IsNotExist(err) {
		t.Fatal("listing created NSS files")
	}

	command := func(args ...string) {
		t.Helper()
		cmd := exec.Command(args[0], args[1:]...)
		cmd.Env = append(os.Environ(), "HOME="+home, "XDG_DATA_HOME="+xdg)
		if b, err := cmd.CombinedOutput(); err != nil {
			t.Fatalf("%s fixture %v: %s", args[0], err, b)
		}
	}
	protect := func(path, password string) {
		t.Helper()
		if err := os.WriteFile(path, []byte(password+"\n"), 0600); err != nil {
			t.Fatal(err)
		}
	}
	importP12 := func(folder, password string, identity testIdentity) {
		t.Helper()
		privateDER, err := x509.MarshalPKCS8PrivateKey(identity.key) // generated test key only
		if err != nil {
			t.Fatal(err)
		}
		keyPath, certPath := filepath.Join(folder, "fixture-key.pem"), filepath.Join(folder, "fixture-cert.pem")
		if err := os.WriteFile(keyPath, pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: privateDER}), 0600); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(certPath, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: identity.cert.Raw}), 0600); err != nil {
			t.Fatal(err)
		}
		p12 := filepath.Join(folder, "fixture.p12")
		p12Password := filepath.Join(folder, "fixture-p12-password")
		protect(p12Password, "synthetic transport")
		command("openssl", "pkcs12", "-export", "-in", certPath, "-inkey", keyPath, "-name", identity.cert.Subject.CommonName, "-out", p12, "-passout", "file:"+p12Password)
		command("pk12util", "-i", p12, "-d", "sql:"+folder, "-k", password, "-w", p12Password)
	}
	create := func(dir, password, name string) testIdentity {
		t.Helper()
		if err := os.MkdirAll(dir, 0700); err != nil {
			t.Fatal(err)
		}
		pwfile := filepath.Join(dir, "fixture-db-password")
		protect(pwfile, password)
		if password == "" {
			command("certutil", "-N", "-d", "sql:"+dir, "--empty-password")
		} else {
			command("certutil", "-N", "-d", "sql:"+dir, "-f", pwfile)
		}
		identity := fixture(t, name, nil, ecKey(t), nil)
		importP12(dir, pwfile, identity)
		return identity
	}
	fingerprint := func(path string) [32]byte {
		t.Helper()
		b, err := os.ReadFile(path)
		if err != nil {
			t.Fatal(err)
		}
		return sha256.Sum256(b)
	}
	const password = "synthetic database"
	modernID := create(modern, password, "Synthetic modern")
	certPath, keyPath := filepath.Join(modern, "cert9.db"), filepath.Join(modern, "key4.db")
	beforeCert, beforeKey := fingerprint(certPath), fingerprint(keyPath)
	for _, wrong := range []string{"", "incorrect"} {
		if r := list(wrong); r.Error != "password_required" {
			t.Fatalf("locked store: %+v", r)
		}
	}
	if r := list(password); len(r.Certificates) != 1 || r.Certificates[0].ID != testID(modernID.cert) {
		t.Fatalf("modern store: %+v", r)
	}
	content := []byte("%PDF-1.7\nsynthetic NSS byte range\n")
	signed := call(io.MultiReader(strings.NewReader(fmt.Sprintf("{\"action\":\"sign\",\"id\":%q,\"password\":%q}\n", testID(modernID.cert), password)), bytes.NewReader(content)))
	if signed.Error != "" {
		t.Fatalf("sign with NSS: %s", signed.Error)
	}
	cms, err := pkcs7.Parse(signed.CMS)
	if err != nil {
		t.Fatal(err)
	}
	cms.Content = content
	if err := cms.Verify(); err != nil || !modernID.cert.Equal(cms.GetOnlySigner()) {
		t.Fatalf("NSS signature: %v", err)
	}
	if fingerprint(certPath) != beforeCert || fingerprint(keyPath) != beforeKey {
		t.Fatal("signing modified the NSS store")
	}

	legacyID := create(legacy, "", "Synthetic legacy")
	r := list("")
	if len(r.Certificates) != 1 || r.Certificates[0].ID != testID(legacyID.cert) {
		t.Fatalf("legacy precedence or empty password: %+v", r)
	}
	if r := call(signInput(testID(modernID.cert), content)); r.Error != "certificate_unavailable" {
		t.Fatalf("unselected store used: %+v", r)
	}
}
