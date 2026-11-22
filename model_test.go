package main

import (
	"strings"
	"testing"
)

func TestValidateThreatFields(t *testing.T) {
	tests := []struct {
		name   string
		fields ThreatFields
		valid  bool
	}{
		{"minimal", ThreatFields{Name: "Trojan"}, true},
		{"all fields", ThreatFields{Name: "Trojan", Description: "Steals passwords", Severity: "high"}, true},
		{"empty name", ThreatFields{}, false},
		{"blank name", ThreatFields{Name: " \t\n "}, false},
		{"name limit in characters", ThreatFields{Name: strings.Repeat("я", 200)}, true},
		{"long name", ThreatFields{Name: strings.Repeat("я", 201)}, false},
		{"description limit", ThreatFields{Name: "Trojan", Description: strings.Repeat("я", 2000)}, true},
		{"long description", ThreatFields{Name: "Trojan", Description: strings.Repeat("я", 2001)}, false},
		{"invalid severity", ThreatFields{Name: "Trojan", Severity: "dangerous"}, false},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := tt.fields.normalizeAndValidate()
			if tt.valid && err != nil {
				t.Fatalf("unexpected validation error: %v", err)
			}
			if !tt.valid && err == nil {
				t.Fatal("expected a validation error")
			}
		})
	}
	fields := ThreatFields{Name: " Trojan ", Description: " Details \n"}
	if err := fields.normalizeAndValidate(); err != nil {
		t.Fatal(err)
	}
	if fields.Name != "Trojan" || fields.Description != "Details" || fields.Severity != "unknown" {
		t.Fatalf("unexpected normalization: %+v", fields)
	}
}

func TestMD5Validation(t *testing.T) {
	for _, valid := range []string{testMD5, strings.ToUpper(testMD5)} {
		if !md5Pattern.MatchString(valid) {
			t.Errorf("rejected valid MD5 %q", valid)
		}
	}
	for _, invalid := range []string{"", "abc", strings.Repeat("g", 32), testMD5 + "0", " " + testMD5, testMD5 + "\n"} {
		if md5Pattern.MatchString(invalid) {
			t.Errorf("accepted invalid MD5 %q", invalid)
		}
	}
}
