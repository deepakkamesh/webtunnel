package webtunnelserver

import (
	"testing"
)

func TestIP(t *testing.T) {
	ipam, _ := NewIPPam("10.0.0.0/24")

	err := ipam.AcquireSpecificIP("10.0.0.0", struct{}{})
	if err == nil {
		t.Errorf("Should not acquire broadcast or network IP")
	}

	err = ipam.AcquireSpecificIP("10.0.0.255", struct{}{})
	if err == nil {
		t.Errorf("Should not acquire broadcast or network IP")
	}

	if err := ipam.ReleaseIP("10.0.0.0"); err == nil {
		t.Errorf("Should not release network address")
	}

	if err := ipam.ReleaseIP("10.0.0.255"); err == nil {
		t.Errorf("Should not release bcast address")
	}

	ip, err := ipam.AcquireIP(struct{}{})
	if ip != "10.0.0.1" {
		t.Errorf("Failed to acquire right IP expect: %s got:%s", "10.0.0.1", ip)
	}

	if i := ipam.GetAllocatedCount(); i != 3 {
		t.Errorf("Invalid allocated count expect:3, got:%v", i)
	}

	if err := ipam.ReleaseIP("10.0.0.1"); err != nil {
		t.Errorf("Failed to release IP expect: nil got: %s", err)
	}

	if err := ipam.ReleaseIP("10.0.0.1"); err == nil {
		t.Errorf("Failed to release IP expect: err got: %s", err)
	}

	if i := ipam.GetAllocatedCount(); i != 2 {
		t.Errorf("Invalid allocated count expect:2, got:%v", i)
	}

	err = ipam.AcquireSpecificIP("10.0.0.25", struct{}{})
	if err != nil {
		t.Errorf("Could not acquire specific IP; got %s, expect:nil", err)
	}

	if err := ipam.ReleaseIP("10.0.0.25"); err != nil {
		t.Errorf("Failed to release IP expect: nil got: %s", err)
	}
}
