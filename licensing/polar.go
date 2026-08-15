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
	"log"
	"net/http"
	"strings"
	"time"
)

// Production unless config says otherwise. Overridable so this can point at
// Polar's sandbox, or at a stand-in during tests.
const polarAPIProduction = "https://api.polar.sh"

func (s *server) polarBase() string {
	if s.cfg.PolarAPIBase != "" {
		return strings.TrimRight(s.cfg.PolarAPIBase, "/")
	}
	return polarAPIProduction
}

var (
	errKeyUnknown = errors.New("unknown or already used license key")
	errKeyInUse   = errors.New("this key is already in use on another computer")
)

type polarActivation struct {
	ID         string `json:"id"`
	LicenseKey struct {
		ID               string `json:"id"`
		ExpiresAt        string `json:"expires_at"`
		LimitActivations int    `json:"limit_activations"`
		Status           string `json:"status"`
	} `json:"license_key"`
}

// polarPost is the one place that talks to Polar. It returns the status and
// body even on failure, because Polar's own message ("activation limit
// reached", "license key does not exist", "organization does not match") is
// the only thing that says what actually went wrong - and guessing from the
// status code alone produces confidently wrong error messages.
func (s *server) polarPost(path string, payload map[string]any) (int, []byte, error) {
	body, _ := json.Marshal(payload)
	req, err := http.NewRequest("POST", s.polarBase()+path, bytes.NewReader(body))
	if err != nil {
		return 0, nil, err
	}
	req.Header.Set("Content-Type", "application/json")

	client := &http.Client{Timeout: 20 * time.Second}
	resp, err := client.Do(req)
	if err != nil {
		return 0, nil, err
	}
	defer resp.Body.Close()
	raw, _ := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
	return resp.StatusCode, raw, nil
}

// polarDetail digs the human-readable reason out of Polar's error body,
// which is either {"detail":"..."} or {"detail":[{"msg":"..."}]}.
func polarDetail(raw []byte) string {
	var asString struct {
		Detail string `json:"detail"`
	}
	if json.Unmarshal(raw, &asString) == nil && asString.Detail != "" {
		return asString.Detail
	}
	var asList struct {
		Detail []struct {
			Msg string `json:"msg"`
		} `json:"detail"`
	}
	if json.Unmarshal(raw, &asList) == nil && len(asList.Detail) > 0 {
		return asList.Detail[0].Msg
	}
	return strings.TrimSpace(string(raw))
}

// activatePolarKey reserves this machine against the key. The HWID goes in
// as the label, which is what the customer sees in their Polar portal when
// they want to free up a device.
func (s *server) activatePolarKey(key, hwid string) (*polarActivation, error) {
	if s.cfg.PolarOrganizationID == "" {
		return nil, errors.New("polar is not configured")
	}

	status, raw, err := s.polarPost("/v1/customer-portal/license-keys/activate", map[string]any{
		"key":             key,
		"organization_id": s.cfg.PolarOrganizationID,
		"label":           hwid,
	})
	if err != nil {
		return nil, err
	}

	if status >= 400 {
		detail := polarDetail(raw)
		// Always log what Polar actually said. Everything below is a guess
		// at classifying it; this line is the fact.
		log.Printf("polar: activate returned %d: %s", status, detail)

		lower := strings.ToLower(detail)
		switch {
		case strings.Contains(lower, "does not support activations"):
			// The benefit has no activation limit configured, so Polar has
			// no device slots to hand out. The key is still perfectly good -
			// fall back to plain validation and let this server be the one
			// that ties it to a single machine.
			log.Print("polar: benefit has no activation limit; falling back to validate")
			return s.validatePolarKey(key)
		case strings.Contains(lower, "limit") && strings.Contains(lower, "activation"):
			return nil, errKeyInUse
		case status == 404, strings.Contains(lower, "does not exist"), strings.Contains(lower, "not found"):
			return nil, errKeyUnknown
		default:
			// Could be a mismatched organization id, activations not enabled
			// on the benefit, a revoked key... Don't pretend to know: pass
			// Polar's own words up so they reach the log and the operator.
			return nil, fmt.Errorf("polar refused the key (http %d): %s", status, detail)
		}
	}

	var act polarActivation
	if err := json.Unmarshal(raw, &act); err != nil {
		return nil, fmt.Errorf("polar sent unreadable json: %w", err)
	}
	if act.LicenseKey.Status != "" && act.LicenseKey.Status != "granted" {
		// revoked / disabled at Polar's end, e.g. after a refund
		log.Printf("polar: key status is %q, refusing", act.LicenseKey.Status)
		return nil, errKeyUnknown
	}
	return &act, nil
}

// validatePolarKey checks a key without reserving a device slot. Used when
// the benefit has no activation limit - the key is real and unexpired, and
// one-machine-per-key is enforced here instead (see handleValidate).
//
// The reply is the licence key object itself rather than an activation, so
// it's reshaped to look like one, with no activation id: there is no slot,
// so there's nothing to give back later.
func (s *server) validatePolarKey(key string) (*polarActivation, error) {
	status, raw, err := s.polarPost("/v1/customer-portal/license-keys/validate", map[string]any{
		"key":             key,
		"organization_id": s.cfg.PolarOrganizationID,
	})
	if err != nil {
		return nil, err
	}
	if status >= 400 {
		detail := polarDetail(raw)
		log.Printf("polar: validate returned %d: %s", status, detail)
		return nil, errKeyUnknown
	}

	var lk struct {
		ID        string `json:"id"`
		Status    string `json:"status"`
		ExpiresAt string `json:"expires_at"`
	}
	if err := json.Unmarshal(raw, &lk); err != nil {
		return nil, fmt.Errorf("polar sent unreadable json: %w", err)
	}
	if lk.Status != "" && lk.Status != "granted" {
		log.Printf("polar: key status is %q, refusing", lk.Status)
		return nil, errKeyUnknown
	}

	act := &polarActivation{}
	act.LicenseKey.ID = lk.ID
	act.LicenseKey.Status = lk.Status
	act.LicenseKey.ExpiresAt = lk.ExpiresAt
	return act, nil
}

// deactivatePolarKey gives the activation slot back, so the same key can be
// used again - on a rebuilt machine, or after support clears an activation.
// Without this, forgetting a machine here would leave the key permanently
// stuck at Polar's activation limit.
func (s *server) deactivatePolarKey(key, activationID string) error {
	if s.cfg.PolarOrganizationID == "" || activationID == "" {
		return nil
	}
	status, raw, err := s.polarPost("/v1/customer-portal/license-keys/deactivate", map[string]any{
		"key":             key,
		"organization_id": s.cfg.PolarOrganizationID,
		"activation_id":   activationID,
	})
	if err != nil {
		return err
	}
	if status >= 400 {
		return fmt.Errorf("http %d: %s", status, polarDetail(raw))
	}
	return nil
}

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

// cmdPolarCheck asks Polar about a key and prints the raw answer. This is
// the tool for "why was my key refused" - it shows Polar's own words rather
// than the tidied-up message the customer sees.
func cmdPolarCheck(s *server, key string) {
	fmt.Printf("server:  %s\n", s.polarBase())
	fmt.Printf("org id:  %s\n", s.cfg.PolarOrganizationID)
	if s.cfg.PolarOrganizationID == "" {
		fmt.Println("\npolar_organization_id is empty - Polar keys cannot work until it's set.")
		return
	}
	fmt.Printf("key:     %s\n\n", key)

	// validate first: it works whether or not activations are enabled on
	// the benefit, so it separates "bad key or wrong org" from "activation
	// problem".
	status, raw, err := s.polarPost("/v1/customer-portal/license-keys/validate", map[string]any{
		"key":             key,
		"organization_id": s.cfg.PolarOrganizationID,
	})
	if err != nil {
		fmt.Printf("validate: could not reach Polar: %v\n", err)
		return
	}
	fmt.Printf("validate -> http %d\n%s\n\n", status, strings.TrimSpace(string(raw)))

	if status >= 400 {
		fmt.Println("The key itself was rejected. Usual causes:")
		fmt.Println("  - polar_organization_id belongs to a different organization")
		fmt.Println("    (sandbox and production have different ids)")
		fmt.Println("  - polar_api_base doesn't match where the key was bought")
		fmt.Println("  - the key was refunded or revoked")
		return
	}

	status, raw, _ = s.polarPost("/v1/customer-portal/license-keys/activate", map[string]any{
		"key":             key,
		"organization_id": s.cfg.PolarOrganizationID,
		"label":           "licensing polarcheck",
	})
	fmt.Printf("activate -> http %d\n%s\n", status, strings.TrimSpace(string(raw)))
	if status >= 400 {
		fmt.Println("\nThe key is valid but couldn't be activated. Usual causes:")
		fmt.Println("  - the benefit has no activation limit set, so activations")
		fmt.Println("    are disabled and this endpoint refuses")
		fmt.Println("  - every activation slot is already used")
	} else {
		fmt.Println("\nWorked - note this used a real activation slot. Free it with:")
		fmt.Println("  licensing forget <hwid>   (or from the Polar dashboard)")
	}
}
