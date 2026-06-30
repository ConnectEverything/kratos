// Copyright © 2023 Ory Corp
// SPDX-License-Identifier: Apache-2.0

package oidc

import (
	"bytes"
	"context"
	"encoding/json"
	"reflect"
	"time"

	"github.com/pkg/errors"
	"github.com/tidwall/gjson"

	"github.com/ory/herodot"
	"github.com/ory/kratos/identity"
	"github.com/ory/x/fetcher"
	"github.com/ory/x/sqlxx"
)

// evaluateClaimsMapperOnLogin re-runs the provider's Jsonnet claims mapper for
// an existing identity on login, exposing both the fresh OIDC claims and the
// current identity to the mapper. It returns the raw evaluated Jsonnet output.
func (s *Strategy) evaluateClaimsMapperOnLogin(ctx context.Context, claims *Claims, provider Provider, currentIdentity *identity.Identity) (string, error) {
	fetch := fetcher.NewFetcher(fetcher.WithClient(s.d.HTTPClient(ctx)), fetcher.WithCache(jsonnetCache, 60*time.Minute))
	jsonnetSnippet, err := fetch.FetchContext(ctx, provider.Config().Mapper)
	if err != nil {
		return "", err
	}

	var jsonClaims bytes.Buffer
	if err := json.NewEncoder(&jsonClaims).Encode(claims); err != nil {
		return "", err
	}

	vm, err := s.d.JsonnetVM(ctx)
	if err != nil {
		return "", err
	}

	vm.ExtCode("claims", jsonClaims.String())

	coalesce := func(b json.RawMessage) json.RawMessage {
		if len(b) == 0 {
			return json.RawMessage("{}")
		}
		return b
	}
	identityCtx, err := json.Marshal(map[string]json.RawMessage{
		"traits":          coalesce(json.RawMessage(currentIdentity.Traits)),
		"metadata_public": coalesce(json.RawMessage(currentIdentity.MetadataPublic)),
		"metadata_admin":  coalesce(json.RawMessage(currentIdentity.MetadataAdmin)),
	})
	if err != nil {
		return "", err
	}
	vm.ExtCode("identity", string(identityCtx))

	evaluated, err := vm.EvaluateAnonymousSnippet(provider.Config().Mapper, jsonnetSnippet.String())
	if err != nil {
		return "", err
	}

	return evaluated, nil
}

// UpdateIdentityFromClaims re-evaluates the provider's claims mapper and merges
// the result into the existing identity's traits and metadata. The mapper output
// takes precedence, but existing traits the mapper does not output are preserved.
// It returns whether the identity actually changed so the caller can avoid an
// unnecessary write.
func (s *Strategy) UpdateIdentityFromClaims(ctx context.Context, claims *Claims, provider Provider, i *identity.Identity) (changed bool, err error) {
	evaluated, err := s.evaluateClaimsMapperOnLogin(ctx, claims, provider, i)
	if err != nil {
		return false, err
	}

	oldTraits := json.RawMessage(i.Traits)
	oldMetadataPublic := json.RawMessage(i.MetadataPublic)
	oldMetadataAdmin := json.RawMessage(i.MetadataAdmin)
	oldVerifiable, _ := json.Marshal(i.VerifiableAddresses)
	oldRecovery, _ := json.Marshal(i.RecoveryAddresses)

	jsonTraits := gjson.Get(evaluated, "identity.traits")
	if !jsonTraits.IsObject() {
		return false, errors.WithStack(herodot.ErrInternalServerError.WithReasonf("OpenID Connect Jsonnet mapper did not return an object for key identity.traits. Please check your Jsonnet code!"))
	}

	// merge(override, base): mapper output wins; existing traits the mapper does
	// not output are preserved.
	mergedTraits, err := merge(json.RawMessage(jsonTraits.Raw), json.RawMessage(i.Traits))
	if err != nil {
		return false, err
	}
	i.Traits = mergedTraits

	// Only update metadata if the mapper explicitly outputs the key, so mappers
	// written for registration only do not wipe existing metadata on login.
	if gjson.Get(evaluated, string(PublicMetadata)).Exists() {
		if err = s.setMetadata(evaluated, i, PublicMetadata); err != nil {
			return false, err
		}
	}
	if gjson.Get(evaluated, string(AdminMetadata)).Exists() {
		if err = s.setMetadata(evaluated, i, AdminMetadata); err != nil {
			return false, err
		}
	}

	// Validate regenerates verifiable/recovery addresses from the schema, losing
	// their verified state. Save the existing ones first so we can restore it.
	oldVerifiableAddresses := make([]identity.VerifiableAddress, len(i.VerifiableAddresses))
	copy(oldVerifiableAddresses, i.VerifiableAddresses)
	oldRecoveryAddresses := make([]identity.RecoveryAddress, len(i.RecoveryAddresses))
	copy(oldRecoveryAddresses, i.RecoveryAddresses)

	if err = s.d.IdentityValidator().Validate(ctx, i); err != nil {
		return false, err
	}

	for n := range i.VerifiableAddresses {
		addr := &i.VerifiableAddresses[n]
		for _, old := range oldVerifiableAddresses {
			if addr.Via == old.Via && addr.Value == old.Value {
				*addr = old
				break
			}
		}
	}
	for n := range i.RecoveryAddresses {
		addr := &i.RecoveryAddresses[n]
		for _, old := range oldRecoveryAddresses {
			if addr.Via == old.Via && addr.Value == old.Value {
				*addr = old
				break
			}
		}
	}

	// Apply verified addresses from the mapper output, mirroring registration so
	// upstream-verified status carries over (e.g. when the user's email changes).
	va, err := s.extractVerifiedAddresses(evaluated)
	if err != nil {
		return false, err
	}
	for n := range i.VerifiableAddresses {
		verifiable := &i.VerifiableAddresses[n]
		for _, verified := range va {
			if verifiable.Via == verified.Via && verifiable.Value == verified.Value {
				if !verifiable.Verified {
					verifiable.Status = identity.VerifiableAddressStatusCompleted
					verifiable.Verified = true
					t := sqlxx.NullTime(time.Now().UTC().Round(time.Second))
					verifiable.VerifiedAt = &t
				}
			}
		}
	}

	newVerifiable, _ := json.Marshal(i.VerifiableAddresses)
	newRecovery, _ := json.Marshal(i.RecoveryAddresses)
	changed = !jsonEqual(oldTraits, json.RawMessage(i.Traits)) ||
		!jsonEqual(oldMetadataPublic, json.RawMessage(i.MetadataPublic)) ||
		!jsonEqual(oldMetadataAdmin, json.RawMessage(i.MetadataAdmin)) ||
		!bytes.Equal(oldVerifiable, newVerifiable) ||
		!bytes.Equal(oldRecovery, newRecovery)

	s.d.Logger().
		WithField("oidc_provider", provider.Config().ID).
		WithField("identity_id", i.ID).
		WithField("identity_changed", changed).
		Debug("Re-evaluated OpenID Connect claims mapper on login.")

	return changed, nil
}

func jsonEqual(a, b json.RawMessage) bool {
	if len(a) == 0 && len(b) == 0 {
		return true
	}
	if len(a) == 0 || len(b) == 0 {
		return false
	}
	var aVal, bVal any
	if err := json.Unmarshal(a, &aVal); err != nil {
		return false
	}
	if err := json.Unmarshal(b, &bVal); err != nil {
		return false
	}
	return reflect.DeepEqual(aVal, bVal)
}
