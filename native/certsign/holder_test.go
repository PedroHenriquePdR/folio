package main

import (
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/asn1"
	"encoding/json"
	"maps"
	"strings"
	"testing"
)

func fixtureDER(t *testing.T, value any) []byte {
	t.Helper()
	der, err := asn1.Marshal(value)
	if err != nil {
		t.Fatal(err)
	}
	return der
}

func TestListStampHolder(t *testing.T) {
	otherName := func(arc, tag int, value string) asn1.RawValue {
		oid := fixtureDER(t, asn1.ObjectIdentifier{2, 16, 76, 1, 3, arc})
		text := fixtureDER(t, asn1.RawValue{Tag: tag, Bytes: []byte(value)})
		wrapped := fixtureDER(t, asn1.RawValue{Class: 2, Tag: 0, IsCompound: true, Bytes: text})
		return asn1.RawValue{Class: 2, Tag: 0, IsCompound: true, Bytes: append(oid, wrapped...)}
	}
	person := func(cpf string) asn1.RawValue {
		return otherName(1, asn1.TagOctetString, "01011990"+cpf+strings.Repeat("0", 26)+"SSPSP")
	}
	company := func(cnpj string) asn1.RawValue {
		return otherName(3, asn1.TagPrintableString, cnpj)
	}
	individual := person("12345678909")
	business := company("11222333000181")
	repName := otherName(2, asn1.TagPrintableString, "Representante Ficticio")
	repData := otherName(4, asn1.TagOctetString, "0101199052998224725"+strings.Repeat("0", 26))
	malformed := business
	malformed.Bytes = append(append([]byte{}, business.Bytes...), 0x05, 0x00)
	primitive := business
	primitive.IsCompound = false

	tests := []struct {
		label, cn, name string
		names           []asn1.RawValue
		kind, id        string
	}{
		{"individual", "Ana Silva:12345678909", "Ana Silva", []asn1.RawValue{individual}, "CPF", "123.456.789-09"},
		{"company with representative", "Oficina 42:11222333000181", "Oficina 42", []asn1.RawValue{repName, business, repData}, "CNPJ", "11.222.333/0001-81"},
		{"alphanumeric company", "Editora Exemplo:12ABC34501DE35", "Editora Exemplo", []asn1.RawValue{company("12ABC34501DE35")}, "CNPJ", "12.ABC.345/01DE-35"},
		{"conflicting CPF suffix", "ANA SILVA:52998224725", "ANA SILVA", []asn1.RawValue{individual}, "", ""},
		{"matching CPF suffix with separators", "Ana Silva:123 456.789-09", "Ana Silva", []asn1.RawValue{individual}, "CPF", "123.456.789-09"},
		{"conflicting CNPJ suffix", "Empresa:12.ABC.345/01DE-35", "Empresa", []asn1.RawValue{business}, "", ""},
		{"representative CPF as company suffix", "Empresa:529.982.247-25", "Empresa", []asn1.RawValue{business, repData}, "", ""},
		{"CNPJ suffix on individual", "Ana Silva:11.222.333/0001-81", "Ana Silva", []asn1.RawValue{individual}, "", ""},
		{"ordinary text suffix", "Ana Silva:RG-88888", "Ana Silva", []asn1.RawValue{individual}, "CPF", "123.456.789-09"},
		{"business name ending in digits", "PROCESSADORA10:11222333000181", "PROCESSADORA10", []asn1.RawValue{business}, "CNPJ", "11.222.333/0001-81"},
		{"short business number", "EDIFICIO 1234567:11222333000181", "EDIFICIO 1234567", []asn1.RawValue{business}, "CNPJ", "11.222.333/0001-81"},
		{"colon inside business name", "ABC SERVICOS: RIO:11222333000181", "ABC SERVICOS: RIO", []asn1.RawValue{business}, "CNPJ", "11.222.333/0001-81"},
		{"text after colon", "Editora: Filial Centro", "Editora: Filial Centro", nil, "", ""},
		{"numbered branch after colon", "Editora: Filial 42", "Editora: Filial 42", []asn1.RawValue{business}, "CNPJ", "11.222.333/0001-81"},
		{"private label after colon", "Ana Silva:RG N/D", "Ana Silva", nil, "", ""},
		{"spaced CPF inside company name", "ANA SILVA 529 982 247 25:11222333000181", "ANA SILVA", []asn1.RawValue{business, repData}, "CNPJ", "11.222.333/0001-81"},
		{"mixed separators in name", "OFICINA 529.982.247 25", "OFICINA", []asn1.RawValue{business}, "CNPJ", "11.222.333/0001-81"},
		{"number in name before CPF", "OFICINA 42 529 982 247 25", "OFICINA 42", []asn1.RawValue{business}, "CNPJ", "11.222.333/0001-81"},
		{"unusual digit grouping", "Oficina 52998 22472 5", "Oficina", []asn1.RawValue{business}, "CNPJ", "11.222.333/0001-81"},
		{"unusual grouping in conflicting suffix", "Ana Silva:CPF 52998 22472 5", "Ana Silva", []asn1.RawValue{individual}, "", ""},
		{"alphanumeric CNPJ inside name", "EDITORA 12.ABC.345 01DE-35", "EDITORA", nil, "", ""},
		{"formatted alphanumeric ID with bad check digits in name", "EDITORA 12.ABC.345/01DE-36", "EDITORA", nil, "", ""},
		{"no SAN", "Ana Silva:12345678909", "Ana Silva", nil, "", ""},
		{"absent name", "", "Titular do certificado", nil, "", ""},
		{"only a document for name", "12.ABC.345/01DE-35", "Titular do certificado", nil, "", ""},
		{"document without colon", "Ana Silva 529.982.247-25", "Ana Silva", nil, "", ""},
		{"arbitrary CN suffix", "Ana Silva:RG-88888", "Ana Silva", nil, "", ""},
		{"representative only", "Empresa:52998224725", "Empresa", []asn1.RawValue{repName, repData}, "", ""},
		{"wrong profile marker", "Empresa", "Empresa", []asn1.RawValue{individual, repData}, "", ""},
		{"two kinds", "Empresa", "Empresa", []asn1.RawValue{individual, business}, "", ""},
		{"two CPF values", "Ana Silva", "Ana Silva", []asn1.RawValue{individual, person("52998224725")}, "", ""},
		{"two CNPJ values", "Empresa", "Empresa", []asn1.RawValue{business, company("12ABC34501DE35")}, "", ""},
		{"malformed second holder field", "Empresa", "Empresa", []asn1.RawValue{business, person("00000000000")}, "", ""},
		{"unrelated OID", "Ana Silva", "Ana Silva", []asn1.RawValue{otherName(61, asn1.TagPrintableString, "11222333000181")}, "", ""},
		{"bad CPF check digits", "Ana Silva", "Ana Silva", []asn1.RawValue{person("12345678919")}, "", ""},
		{"repeated CPF", "Ana Silva", "Ana Silva", []asn1.RawValue{person("11111111111")}, "", ""},
		{"CPF in a truncated record", "Ana Silva", "Ana Silva", []asn1.RawValue{otherName(1, asn1.TagOctetString, "12345678909")}, "", ""},
		{"CPF after a malformed date", "Ana Silva", "Ana Silva", []asn1.RawValue{otherName(1, asn1.TagOctetString, "3102199012345678909"+strings.Repeat("0", 26))}, "", ""},
		{"CNPJ with suffix", "Empresa", "Empresa", []asn1.RawValue{company("112223330001810")}, "", ""},
		{"bad CNPJ check digits", "Empresa", "Empresa", []asn1.RawValue{company("11222333000180")}, "", ""},
		{"bad alphanumeric CNPJ", "Empresa", "Empresa", []asn1.RawValue{company("12ABC34501DE25")}, "", ""},
		{"placeholder CNPJ", "Empresa", "Empresa", []asn1.RawValue{company("00000000000000")}, "", ""},
		{"unknown ASN.1 type", "Empresa", "Empresa", []asn1.RawValue{otherName(3, asn1.TagInteger, "11222333000181")}, "", ""},
		{"extra DER value", "Empresa", "Empresa", []asn1.RawValue{malformed}, "", ""},
		{"primitive otherName", "Empresa", "Empresa", []asn1.RawValue{primitive}, "", ""},
	}
	key := ecKey(t)
	issuer := fixture(t, "AC de exemplo", nil, key, asCA)
	for _, tc := range tests {
		t.Run(tc.label, func(t *testing.T) {
			chosen := fixture(t, tc.cn, &issuer, key, func(c *x509.Certificate) {
				c.Subject.SerialNumber = "52998224725"
				c.Subject.Organization = []string{"ICP-Brasil"}
				if len(tc.names) > 0 {
					c.ExtraExtensions = []pkix.Extension{{Id: asn1.ObjectIdentifier{2, 5, 29, 17}, Value: fixtureDER(t, tc.names)}}
				}
			})
			reply := invoke(t, strings.NewReader("{\"action\":\"list\"}\n"), testStore{chosen}.open)
			if len(reply.Certificates) != 1 {
				t.Fatalf("expected the eligible certificate to remain listed: %+v", reply)
			}
			got := reply.Certificates[0]
			legacyHolder := tc.cn
			if legacyHolder == "" {
				legacyHolder = chosen.cert.Subject.String()
			}
			if got.ID != testID(chosen.cert) || got.Holder != legacyHolder || got.Issuer != "AC de exemplo" {
				t.Fatalf("identity changed: %+v", got)
			}
			if got.StampName != tc.name {
				t.Errorf("stampName = %q; want %q", got.StampName, tc.name)
			}
			if tc.id == "" {
				if len(got.TaxID) != 0 {
					t.Errorf("unexpected taxId field %s", got.TaxID)
				}
			} else {
				var id map[string]string
				if err := json.Unmarshal(got.TaxID, &id); err != nil || !maps.Equal(id, map[string]string{"type": tc.kind, "value": tc.id}) {
					t.Errorf("taxId = %s; want %s %s", got.TaxID, tc.kind, tc.id)
				}
			}
		})
	}
}
