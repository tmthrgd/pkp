// Copyright 2017 Tom Thorogood. All rights reserved.
// Use of this source code is governed by a
// Modified BSD License license that can be found in
// the LICENSE file.

package pkp

import (
	"crypto/sha256"
	"crypto/x509"
	"errors"
	"strings"
	"time"
)

type SHA256Pin [sha256.Size]byte

type Pin struct {
	ValidUntil        time.Time
	SHA256Pins        []SHA256Pin
	ReportURI         string
	IncludeSubDomains bool
}

var unixEpoch = time.Unix(0, 0)

func (p *Pin) valid() bool {
	if p == nil {
		return false
	}

	if p.ValidUntil.IsZero() || p.ValidUntil.Equal(unixEpoch) {
		return true
	}

	return time.Now().Before(p.ValidUntil)
}

type KeyPins struct {
	EnforcePins    Storage
	ReportOnlyPins Storage

	//ReportFailure func() error

	MustPin bool
}

func (kp *KeyPins) GetPins(host string) (enforce, report *Pin, err error) {
	hasEnforce, hasReport := kp.EnforcePins != nil, kp.ReportOnlyPins != nil

	if hasEnforce {
		enforce, err = kp.EnforcePins.Get(host)
		if err != nil {
			return
		}
	}

	if hasReport {
		report, err = kp.ReportOnlyPins.Get(host)
		if err != nil {
			return
		}
	}

	if (!hasEnforce || enforce != nil) && (!hasReport || report != nil) {
		return
	}

	labels := strings.Split(host, ".")
	for i := range labels {
		candidate := strings.Join(labels[i:], ".")

		if hasEnforce && enforce == nil {
			enforce, err = kp.EnforcePins.Get(candidate)
			if err != nil {
				return
			}

			if enforce != nil && !enforce.IncludeSubDomains {
				enforce = nil
			}
		}

		if hasReport && report == nil {
			report, err = kp.ReportOnlyPins.Get(candidate)
			if err != nil {
				return
			}

			if report != nil && !report.IncludeSubDomains {
				report = nil
			}
		}

		if (!hasEnforce || enforce != nil) && (!hasReport || report != nil) {
			return
		}
	}

	return
}

func (kp *KeyPins) VerifyPeerCertificate(sni string) func(rawCerts [][]byte, verifiedChains [][]*x509.Certificate) error {
	return func(rawCerts [][]byte, verifiedChains [][]*x509.Certificate) error {
		if len(verifiedChains) == 0 {
			return errors.New("pkp: InsecureSkipVerify not presently supported")
		}

		pe, pr, err := kp.GetPins(sni)
		if err != nil {
			return err
		}

		if pe == nil && kp.MustPin {
			return errors.New("pkp: missing pins for host")
		}

		if pe == nil && pr == nil {
			return nil
		}

		cache := make(map[string]SHA256Pin, len(verifiedChains[0]))

		if pr.valid() && !matches(verifiedChains, pr.SHA256Pins, cache) {
			// TODO: report
		}

		if !pe.valid() || matches(verifiedChains, pe.SHA256Pins, cache) {
			return nil
		}

		// TODO: report
		return errors.New("pkp: invalid certificate chain presented")
	}
}

func matches(chains [][]*x509.Certificate, pins []SHA256Pin, cache map[string]SHA256Pin) bool {
	for _, chain := range chains {
		for _, cert := range chain {
			fpr, ok := cache[string(cert.RawSubjectPublicKeyInfo)]
			if !ok {
				fpr = sha256.Sum256(cert.RawSubjectPublicKeyInfo)
				cache[string(cert.RawSubjectPublicKeyInfo)] = fpr
			}

			for i := range pins {
				if pins[i] == fpr {
					return true
				}
			}
		}
	}

	return false
}
