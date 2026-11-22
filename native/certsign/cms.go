package main

import (
	"bytes"
	"crypto"
	"crypto/rand"
	"crypto/sha256"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/asn1"
	"encoding/hex"
	"errors"
	"math/big"

	"github.com/github/smimesign/ietf-cms/oid"
	"github.com/github/smimesign/ietf-cms/protocol"
)

var (
	signingCertificateV2 = asn1.ObjectIdentifier{1, 2, 840, 113549, 1, 9, 16, 2, 47}
	signaturePolicyID    = asn1.ObjectIdentifier{1, 2, 840, 113549, 1, 9, 16, 2, 15}
	basicPolicyID        = asn1.ObjectIdentifier{2, 16, 76, 1, 7, 1, 11, 1, 3}
)

// The policy's own signPolicyHash field, published by ITI in PA_PAdES_AD_RB_v1_3.der.
const policyHashHex = "23e4be4b9b362172e4ebb0e72b86a133ece5aad843d8651c6e38a0ba3f08fc60"

type issuerSerial struct {
	Issuer []asn1.RawValue
	Serial *big.Int
}
type essCertIDV2 struct {
	// RFC 5035 defines SHA-256 as DEFAULT, which DER omits.
	CertHash     []byte
	IssuerSerial issuerSerial
}
type signingCertificate struct{ Certs []essCertIDV2 }
type policyDigest struct {
	Algorithm pkix.AlgorithmIdentifier
	Hash      []byte
}
type policyQualifier struct {
	ID  asn1.ObjectIdentifier
	URI string `asn1:"ia5"`
}
type signaturePolicy struct {
	ID         asn1.ObjectIdentifier
	Digest     policyDigest
	Qualifiers []policyQualifier
}

func signedAttributes(cert *x509.Certificate, digest []byte) (protocol.Attributes, []byte, error) {
	leafHash := sha256.Sum256(cert.Raw)
	ess := signingCertificate{Certs: []essCertIDV2{{
		CertHash: leafHash[:], IssuerSerial: issuerSerial{
			Issuer: []asn1.RawValue{{Class: asn1.ClassContextSpecific, Tag: 4, IsCompound: true, Bytes: cert.RawIssuer}},
			Serial: cert.SerialNumber,
		},
	}}}
	policyHash, err := hex.DecodeString(policyHashHex)
	if err != nil {
		return nil, nil, err
	}
	policy := signaturePolicy{
		ID: basicPolicyID, Digest: policyDigest{pkix.AlgorithmIdentifier{Algorithm: oid.DigestAlgorithmSHA256}, policyHash},
		Qualifiers: []policyQualifier{{
			ID:  asn1.ObjectIdentifier{1, 2, 840, 113549, 1, 9, 16, 5, 1},
			URI: "https://politicas.icpbrasil.gov.br/PA_PAdES_AD_RB_v1_3.der",
		}},
	}
	var attributes protocol.Attributes
	for _, value := range []struct {
		id    asn1.ObjectIdentifier
		value any
	}{
		{oid.AttributeContentType, oid.ContentTypeData}, {oid.AttributeMessageDigest, digest},
		{signingCertificateV2, ess}, {signaturePolicyID, policy},
	} {
		attr, err := protocol.NewAttribute(value.id, value.value)
		if err != nil {
			return nil, nil, err
		}
		attributes = append(attributes, attr)
	}
	encoded, err := attributes.MarshaledForSigning()
	if err != nil {
		return nil, nil, err
	}
	// CMS stores signedAttrs under an implicit tag. Preserve the DER SET order
	// when writing that field so independent verifiers hash these exact octets.
	var canonical protocol.Attributes
	if _, err := asn1.UnmarshalWithParams(encoded, &canonical, "set"); err != nil {
		return nil, nil, err
	}
	return canonical, encoded, nil
}

func detachedCMS(cert *x509.Certificate, chain []*x509.Certificate, signer crypto.Signer, digest []byte) ([]byte, error) {
	attributes, encoded, err := signedAttributes(cert, digest)
	if err != nil {
		return nil, err
	}
	sid, err := protocol.NewIssuerAndSerialNumber(cert)
	if err != nil {
		return nil, err
	}
	hashID := pkix.AlgorithmIdentifier{Algorithm: oid.DigestAlgorithmSHA256}
	algorithm := x509.ECDSAWithSHA256
	signatureID := pkix.AlgorithmIdentifier{Algorithm: oid.SignatureAlgorithmECDSAWithSHA256}
	if cert.PublicKeyAlgorithm == x509.RSA {
		algorithm = x509.SHA256WithRSA
		signatureID = pkix.AlgorithmIdentifier{Algorithm: oid.SignatureAlgorithmSHA256WithRSA, Parameters: asn1.NullRawValue}
	}
	message, err := protocol.NewSignedData(protocol.EncapsulatedContentInfo{EContentType: oid.ContentTypeData})
	if err != nil {
		return nil, err
	}
	if err := message.AddCertificate(cert); err != nil {
		return nil, err
	}
	current := cert
	for _, issuer := range chain {
		if issuer == nil || issuer.Equal(cert) {
			continue
		}
		if !bytes.Equal(current.RawIssuer, issuer.RawSubject) || current.CheckSignatureFrom(issuer) != nil {
			break
		}
		if bytes.Equal(issuer.RawSubject, issuer.RawIssuer) && issuer.CheckSignatureFrom(issuer) == nil {
			break
		}
		if err := message.AddCertificate(issuer); err != nil {
			return nil, err
		}
		current = issuer
	}
	if signer == nil {
		return nil, errors.New("no signer")
	}
	attributeHash := sha256.Sum256(encoded)
	signature, err := signer.Sign(rand.Reader, attributeHash[:], crypto.SHA256)
	if err != nil {
		return nil, err
	}
	// Some stores locate keys by a provider label. Verify the binding to the
	// exact selected certificate before a signature can leave this process.
	if err := cert.CheckSignature(algorithm, encoded, signature); err != nil {
		return nil, err
	}
	message.DigestAlgorithms = []pkix.AlgorithmIdentifier{hashID}
	message.SignerInfos = []protocol.SignerInfo{{
		Version: 1, SID: sid, DigestAlgorithm: hashID, SignedAttrs: attributes,
		SignatureAlgorithm: signatureID, Signature: signature,
	}}
	return message.ContentInfoDER()
}
