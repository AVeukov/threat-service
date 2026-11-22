package main

import (
	"sync"
	"time"
)

type Store struct {
	mu      sync.RWMutex
	threats map[string]Threat
}

func NewStore() *Store {
	return &Store{threats: make(map[string]Threat)}
}

func (s *Store) Get(md5 string) (Threat, bool) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	threat, ok := s.threats[md5]
	return threat, ok
}

func (s *Store) Create(md5 string, fields ThreatFields) (Threat, bool) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if _, exists := s.threats[md5]; exists {
		return Threat{}, false
	}
	now := time.Now().UTC()
	threat := Threat{
		MD5:          md5,
		ThreatFields: fields,
		CreatedAt:    now,
		UpdatedAt:    now,
	}
	s.threats[md5] = threat
	return threat, true
}

func (s *Store) Update(md5 string, fields ThreatFields) (Threat, bool) {
	s.mu.Lock()
	defer s.mu.Unlock()
	threat, exists := s.threats[md5]
	if !exists {
		return Threat{}, false
	}
	threat.ThreatFields = fields
	threat.UpdatedAt = time.Now().UTC()
	s.threats[md5] = threat
	return threat, true
}
