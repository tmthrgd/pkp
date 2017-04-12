// Copyright 2017 Tom Thorogood. All rights reserved.
// Use of this source code is governed by a
// Modified BSD License license that can be found in
// the LICENSE file.

package pkp

import "golang.org/x/sync/syncmap"

type Storage interface {
	Get(host string) (*Pin, error)
	Set(host string, pin *Pin) error
	Remove(host string) error
}

type memStorage struct {
	m syncmap.Map
}

func MemStorage() Storage {
	return new(memStorage)
}

func (s *memStorage) Get(host string) (*Pin, error) {
	v, _ := s.m.Load(host)
	p, _ := v.(*Pin)
	return p, nil
}

func (s *memStorage) Set(host string, pin *Pin) error {
	s.m.Store(host, pin)
	return nil
}

func (s *memStorage) Remove(host string) error {
	s.m.Delete(host)
	return nil
}
