package main

import (
	"crypto/x509"
	"encoding/asn1"
	"regexp"
	"strings"
	"time"
	"unicode"
)

type taxID struct {
	Type  string `json:"type"`
	Value string `json:"value"`
}

const (
	numberSeparator = `[.\s\p{Zs}/-]*`
	cpfGroups       = `[0-9]{3}` + numberSeparator + `[0-9]{3}` + numberSeparator + `[0-9]{3}` + numberSeparator + `[0-9]{2}`
	cnpjGroups      = `[A-Za-z0-9]{2}` + numberSeparator + `[A-Za-z0-9]{3}` + numberSeparator + `[A-Za-z0-9]{3}` + numberSeparator + `[A-Za-z0-9]{4}` + numberSeparator + `[0-9]{2}`
)

var (
	numbersInName = regexp.MustCompile(`[0-9]{11,}|` + cpfGroups)
	groupedDigits = regexp.MustCompile(`[0-9]+(?:[.\s\p{Zs}/-]+[0-9]+)*`)
	cnpjInName    = regexp.MustCompile(`\b` + cnpjGroups + `\b`)
	documentOnly  = regexp.MustCompile(`^(?:` + cpfGroups + `|` + cnpjGroups + `)$`)
	documentLabel = regexp.MustCompile(`(?i)^(?:CPF|CNPJ)\b[\s\p{Zs}:-]*`)
	privateLabel  = regexp.MustCompile(`(?i)^(?:CPF|CNPJ|RG|NIS|PIS|PASEP|ID|DOC(?:UMENTO)?|SERIAL(?:NUMBER)?)\b`)
	separators    = regexp.MustCompile(`[.\s\p{Zs}/-]+`)
	digitsOnly    = regexp.MustCompile(`^[0-9]+$`)
)

func compactNumber(s string) string {
	return strings.ToUpper(separators.ReplaceAllString(s, ""))
}

func splitCommonName(cn string) (string, string) {
	// Issuers can append ":document" to a name that itself contains a colon.
	i := strings.LastIndexByte(cn, ':')
	if i < 0 {
		return cn, ""
	}
	suffix := strings.TrimSpace(cn[i+1:])
	if strings.IndexFunc(suffix, unicode.IsLetter) >= 0 && !privateLabel.MatchString(suffix) {
		if strings.IndexFunc(suffix, unicode.IsDigit) < 0 ||
			(strings.ContainsFunc(suffix, unicode.IsSpace) && !documentOnly.MatchString(suffix)) {
			return cn, ""
		}
	}
	return cn[:i], suffix
}

func stampName(commonName string) string {
	name, _ := splitCommonName(commonName)
	name = cnpjInName.ReplaceAllStringFunc(name, func(candidate string) string {
		raw := compactNumber(candidate)
		// A word followed by two digits can be a company name.
		if digitsOnly.MatchString(raw) || strings.ContainsRune(candidate, '/') || validCNPJ(raw) {
			return " "
		}
		return candidate
	})
	// Remove standard groups first so "Loja 42 529 982 247 25" retains "42".
	name = numbersInName.ReplaceAllString(name, " ")
	name = groupedDigits.ReplaceAllStringFunc(name, func(run string) string {
		if len(compactNumber(run)) >= 11 {
			return " "
		}
		return run
	})
	name = strings.Join(strings.Fields(name), " ")
	if strings.IndexFunc(name, unicode.IsLetter) < 0 {
		return "Titular do certificado"
	}
	return name
}

func allOtherNames(cert *x509.Certificate, accept func(asn1.ObjectIdentifier, []byte) bool) bool {
	for _, extension := range cert.Extensions {
		if !extension.Id.Equal(asn1.ObjectIdentifier{2, 5, 29, 17}) {
			continue
		}
		var names []asn1.RawValue
		if rest, err := asn1.Unmarshal(extension.Value, &names); err != nil || len(rest) != 0 {
			return false
		}
		for _, name := range names {
			if name.Class != asn1.ClassContextSpecific || name.Tag != 0 {
				continue
			}
			var oid asn1.ObjectIdentifier
			value, err := asn1.Unmarshal(name.Bytes, &oid)
			if err != nil {
				return false
			}
			if !name.IsCompound {
				// The profile filter only needs the OID. A malformed otherName
				// cannot supply its value for a public mark.
				value = nil
			}
			if !accept(oid, value) {
				return false
			}
		}
	}
	return true
}

func holderTaxID(cert *x509.Certificate) *taxID {
	var id *taxID
	var individual, company bool
	ok := allOtherNames(cert, func(oid asn1.ObjectIdentifier, value []byte) bool {
		if len(oid) != 6 || !oid[:5].Equal(asn1.ObjectIdentifier{2, 16, 76, 1, 3}) {
			return true
		}
		arc := oid[5]
		switch arc {
		case 1, 5, 6:
			individual = true
		case 2, 3, 4, 7:
			company = true
		}
		if individual && company {
			return false
		}
		// The company's representative has separate fields (.2 and .4).
		// Only .1 and .3 describe the holder's own tax identifier.
		if arc != 1 && arc != 3 {
			return true
		}
		if id != nil {
			return false
		}
		id = parseHolderID(arc, value)
		return id != nil
	})
	if !ok || id == nil {
		return nil
	}
	// A document in the conventional CN suffix can contradict the holder
	// field. It may veto disclosure, but it never supplies the identifier.
	_, suffix := splitCommonName(cert.Subject.CommonName)
	suffix = documentLabel.ReplaceAllString(suffix, "")
	raw := compactNumber(suffix)
	if digitsOnly.MatchString(raw) || documentOnly.MatchString(suffix) {
		if raw != compactNumber(id.Value) && (validCPF(raw) || validCNPJ(raw)) {
			return nil
		}
	}
	return id
}

var (
	// DOC-ICP-04 packs birth date, CPF, NIS, RG and optional issuing body in .1.
	cpfRecord  = regexp.MustCompile(`^[0-9]{30}[0-9A-Z]{15}[0-9A-Z ]{0,10}$`)
	cnpjRecord = regexp.MustCompile(`^[0-9A-Z]{12}[0-9]{2}$`)
)

func parseHolderID(arc int, der []byte) *taxID {
	var wrapper, text asn1.RawValue
	if rest, err := asn1.Unmarshal(der, &wrapper); err != nil || len(rest) != 0 ||
		wrapper.Class != asn1.ClassContextSpecific || wrapper.Tag != 0 || !wrapper.IsCompound {
		return nil
	}
	if rest, err := asn1.Unmarshal(wrapper.Bytes, &text); err != nil || len(rest) != 0 ||
		text.Class != asn1.ClassUniversal || text.IsCompound || (text.Tag != asn1.TagPrintableString && text.Tag != asn1.TagOctetString) {
		return nil
	}
	s := string(text.Bytes)
	if arc == 1 {
		if !cpfRecord.MatchString(s) {
			return nil
		}
		if _, err := time.Parse("02012006", s[:8]); err != nil {
			return nil
		}
		cpf := s[8:19]
		if !validCPF(cpf) {
			return nil
		}
		return &taxID{"CPF", cpf[:3] + "." + cpf[3:6] + "." + cpf[6:9] + "-" + cpf[9:]}
	}
	if !validCNPJ(s) {
		return nil
	}
	return &taxID{"CNPJ", s[:2] + "." + s[2:5] + "." + s[5:8] + "/" + s[8:12] + "-" + s[12:]}
}

func validCPF(s string) bool {
	return len(s) == 11 && digitsOnly.MatchString(s) && validCheckDigits(s, []int{11, 10, 9, 8, 7, 6, 5, 4, 3, 2})
}

func validCNPJ(s string) bool {
	return cnpjRecord.MatchString(s) && validCheckDigits(s, []int{6, 5, 4, 3, 2, 9, 8, 7, 6, 5, 4, 3, 2})
}

func validCheckDigits(id string, weights []int) bool {
	if id == strings.Repeat(id[:1], len(id)) {
		return false
	}
	for digit := range 2 {
		sum := 0
		for i, weight := range weights[1-digit:] {
			// Receita Federal assigns the ASCII code minus '0' to CNPJ letters.
			sum += int(id[i]-'0') * weight
		}
		check := 11 - sum%11
		if check >= 10 {
			check = 0
		}
		if int(id[len(id)-2+digit]-'0') != check {
			return false
		}
	}
	return true
}
