package main

// Polar as the shop and the key issuer.
//
// Polar sells the licence, collects VAT as merchant of record, generates
// the key, emails it to the customer, and enforces both the 6-month term
// and the one-machine limit. This file is the part that checks a Polar key
// when netvis tries to activate with it.
//
// What deliberately did NOT move to Polar: the per-launch check. netvis
// asks THIS server on every start, and this server answers from its own
// database. Polar is only consulted once, at activation. That keeps the
// common path fast, keeps working if Polar has an outage, and means
// `licensing users` / `revoke` still describe reality.
//
// Keys generated locally with `licensing gen` keep working too - they're
// tried first, so giveaways, testing and manual sales don't need Polar at
// all.

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"time"
)

// Overridable so the tests can point at a stand-in.
var polarAPI = "https://api.polar.sh"

type polarActivation struct {
	ID         string `json:"id"`
	LicenseKey struct {
		ID               string `json:"id"`
		ExpiresAt        string `json:"expires_at"`
		LimitActivations int    `json:"limit_activations"`
		Status           string `json:"status"`
	} `json:"license_key"`
}

// activatePolarKey reserves this machine against the key. Polar enforces
// the activation limit, so if the benefit is set to 1 device, a second
// machine is refused here rather than by us.
//
// The HWID goes in as the label, which is what the customer sees in their
// Polar portal when they want to free up a device.
func (s *server) activatePolarKey(key, hwid string) (*polarActivation, error) {
	if s.cfg.PolarOrganizationID == "" {
		return nil, errors.New("polar is not configured")
	}

	body, _ := json.Marshal(map[string]any{
		"key":             key,
		"organization_id": s.cfg.PolarOrganizationID,
		"label":           hwid,
	})
	req, err := http.NewRequest("POST", polarAPI+"/v1/customer-portal/license-keys/activate",
		bytes.NewReader(body))
	if err != nil {
		return nil, err
	}
	req.Header.Set("Content-Type", "application/json")

	client := &http.Client{Timeout: 20 * time.Second}
	resp, err := client.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	raw, _ := io.ReadAll(io.LimitReader(resp.Body, 1<<20))

	if resp.StatusCode == 404 || resp.StatusCode == 422 {
		return nil, errKeyUnknown
	}
	if resp.StatusCode == 403 {
		// Polar's answer when the activation limit is used up.
		return nil, errKeyInUse
	}
	if resp.StatusCode >= 400 {
		return nil, fmt.Errorf("polar returned http %d: %s", resp.StatusCode, string(raw))
	}

	var act polarActivation
	if err := json.Unmarshal(raw, &act); err != nil {
		return nil, fmt.Errorf("polar sent unreadable json: %w", err)
	}
	if act.LicenseKey.Status != "" && act.LicenseKey.Status != "granted" {
		// revoked / disabled at Polar's end, e.g. after a refund
		return nil, errKeyUnknown
	}
	return &act, nil
}

var (
	errKeyUnknown = errors.New("unknown or already used license key")
	errKeyInUse   = errors.New("this key is already in use on another computer")
)

// polarExpiry converts Polar's expiry into ours. Polar is the authority on
// how long the licence runs, but if the benefit has no expiry configured we
// fall back to our own 6-month term rather than handing out a permanent
// licence by accident.
func polarExpiry(act *polarActivation) string {
	if act.LicenseKey.ExpiresAt != "" {
		if t, err := time.Parse(time.RFC3339, act.LicenseKey.ExpiresAt); err == nil {
			return t.UTC().Format(time.RFC3339)
		}
	}
	return time.Now().UTC().AddDate(0, licenceMonths, 0).Format(time.RFC3339)
}
