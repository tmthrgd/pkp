// Copyright 2017 Tom Thorogood. All rights reserved.
// Use of this source code is governed by a
// Modified BSD License license that can be found in
// the LICENSE file.

package pkp

import (
	"errors"
	"net/http"
)

func (kp *KeyPins) ParseHeaders(host string, h http.Header) error {
	if kp.EnforcePins != nil {
		pe, err := ParseHeader(h.Get("Public-Key-Pins"))
		if err != nil {
			return err
		}

		if err = kp.EnforcePins.Set(host, pe); err != nil {
			return err
		}
	}

	if kp.ReportOnlyPins == nil {
		return nil
	}

	pr, err := ParseHeader(h.Get("Public-Key-Pins-Report-Only"))
	if err != nil {
		return err
	}

	return kp.ReportOnlyPins.Set(host, pr)
}

func ParseHeader(v string) (*Pin, error) {
	if v == "" {
		return nil, nil
	}

	return nil, errors.New("pkp: not implemented")
}
