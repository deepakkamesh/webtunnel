package webtunnelserver

import (
	"testing"
)

func TestIP(t *testing.T) {
	ipAllocator, _ := NewIPPam("10.0.0.0/24")

	testCasesAquire := []struct {
		ipAddr           string
		expectErrorCheck bool
		expectedCount    int // If not expecting error
	}{
		{"10.0.0.0", true, 0},    // Should not acquire network IP
		{"10.0.0.255", true, 0},  // Should not acquire broadcast IP
		{"10.0.0.1", false, 3},
		{"10.0.0.1", true, 0},    // Cannot aquire same IP twice
		{"10.0.0.25", false, 4},
		{"192.168.0.1", true, 0}, // IP not in network
		{"10.0.0", true, 0},      // Not a valid IP
		{"10.0.0.300", true, 0},  // Not a valid IP
		{"hello", true, 0},       // Not a valid IP
	}

	for _, tc := range testCasesAquire {
		if tc.expectErrorCheck {
			err := ipAllocator.AcquireSpecificIP(tc.ipAddr, struct{}{})
			if err == nil {
				t.Errorf("Expected error for IP %s, got nil", tc.ipAddr)
			}
		} else {
			err := ipAllocator.AcquireSpecificIP(tc.ipAddr, struct{}{})
			if err != nil {
				t.Errorf("Unexpected error for IP %s: %s", tc.ipAddr, err)
			}
			if ipAllocator.GetAllocatedCount() != tc.expectedCount {
				t.Errorf("Incorrect allocated count after acquiring %s", tc.ipAddr)
			}
		}
	}

	testCasesRelease := []struct {
		ipAddr           string
		expectErrorCheck bool
		expectedCount    int // If not expecting error
	}{
		{"10.0.0.0", true, 0},   // Should not release network IP
		{"10.0.0.255", true, 0}, // Should not release broadcast IP
		{"10.0.0.1", false, 3},
		{"10.0.0.1", true, 0},   // Should not release same IP twice
		{"10.0.0.25", false, 2},
	}

	for _, tc := range testCasesRelease {
		if tc.expectErrorCheck {
			err := ipAllocator.ReleaseIP(tc.ipAddr)
			if err == nil {
				t.Errorf("Expected error for IP %s, got nil", tc.ipAddr)
			}
		} else {
			err := ipAllocator.ReleaseIP(tc.ipAddr)
			if err != nil {
				t.Errorf("Unexpected error for IP %s: %s", tc.ipAddr, err)
			}
			if ipAllocator.GetAllocatedCount() != tc.expectedCount {
				t.Errorf("Incorrect allocated count after acquiring %s", tc.ipAddr)
			}
		}
	}
}

func TestGetMaxUsers(t *testing.T) {
	a := getMaxUsers("192.168.0.0/24")
	if a != 253 {
		t.Errorf("Expected 253, got: %v", a)
	}
	b := getMaxUsers("192.168.0.0/23")
	if b != 509 {
		t.Errorf("Expected 509, got: %v", b)
	}
}
