package types

import (
	"encoding/json"
	"fmt"
	"regexp"

	sdk "github.com/cosmos/cosmos-sdk/types"
	sdkerrors "github.com/cosmos/cosmos-sdk/types/errors"
	paramtypes "github.com/cosmos/cosmos-sdk/x/params/types"
	"github.com/gogo/protobuf/jsonpb"
	"github.com/pkg/errors"
	"gopkg.in/yaml.v2"
)

var (
	ParamStoreKeyUploadAccess           = []byte("uploadAccess")
	ParamStoreKeyInstantiateAccess      = []byte("instantiateAccess")
	ParamStoreKeyBach32IbcPortTranslate = []byte("bach32IbcPort")
)

var AllAccessTypes = []AccessType{
	AccessTypeNobody,
	AccessTypeOnlyAddress,
	AccessTypeAnyOfAddresses,
	AccessTypeEverybody,
}

func (a AccessType) With(addrs ...sdk.AccAddress) AccessConfig {
	switch a {
	case AccessTypeNobody:
		return AllowNobody
	case AccessTypeOnlyAddress:
		if n := len(addrs); n != 1 {
			panic(fmt.Sprintf("expected exactly 1 address but got %d", n))
		}
		if err := sdk.VerifyAddressFormat(addrs[0]); err != nil {
			panic(err)
		}
		return AccessConfig{Permission: AccessTypeOnlyAddress, Address: addrs[0].String()}
	case AccessTypeEverybody:
		return AllowEverybody
	case AccessTypeAnyOfAddresses:
		bech32Addrs := make([]string, len(addrs))
		for i, v := range addrs {
			bech32Addrs[i] = v.String()
		}
		if err := assertValidAddresses(bech32Addrs); err != nil {
			panic(sdkerrors.Wrap(err, "addresses"))
		}
		return AccessConfig{Permission: AccessTypeAnyOfAddresses, Addresses: bech32Addrs}
	}
	panic("unsupported access type")
}

func (a AccessType) String() string {
	switch a {
	case AccessTypeNobody:
		return "Nobody"
	case AccessTypeOnlyAddress:
		return "OnlyAddress"
	case AccessTypeEverybody:
		return "Everybody"
	case AccessTypeAnyOfAddresses:
		return "AnyOfAddresses"
	}
	return "Unspecified"
}

func (a *AccessType) UnmarshalText(text []byte) error {
	for _, v := range AllAccessTypes {
		if v.String() == string(text) {
			*a = v
			return nil
		}
	}
	*a = AccessTypeUnspecified
	return nil
}

func (a AccessType) MarshalText() ([]byte, error) {
	return []byte(a.String()), nil
}

func (a *AccessType) MarshalJSONPB(_ *jsonpb.Marshaler) ([]byte, error) {
	return json.Marshal(a)
}

func (a *AccessType) UnmarshalJSONPB(_ *jsonpb.Unmarshaler, data []byte) error {
	return json.Unmarshal(data, a)
}

func (a AccessConfig) Equals(o AccessConfig) bool {
	return a.Permission == o.Permission && a.Address == o.Address
}

var (
	DefaultUploadAccess = AllowEverybody
	AllowEverybody      = AccessConfig{Permission: AccessTypeEverybody}
	AllowNobody         = AccessConfig{Permission: AccessTypeNobody}
)

// ParamKeyTable returns the parameter key table.
func ParamKeyTable() paramtypes.KeyTable {
	return paramtypes.NewKeyTable().RegisterParamSet(&Params{})
}

// DefaultParams returns default wasm parameters
func DefaultParams() Params {
	return Params{
		CodeUploadAccess:             AllowEverybody,
		InstantiateDefaultPermission: AccessTypeEverybody,
		Bach32IbcPortTranslate:       nil,
	}
}

func (p Params) String() string {
	out, err := yaml.Marshal(p)
	if err != nil {
		panic(err)
	}
	return string(out)
}

// ParamSetPairs returns the parameter set pairs.
func (p *Params) ParamSetPairs() paramtypes.ParamSetPairs {
	return paramtypes.ParamSetPairs{
		paramtypes.NewParamSetPair(ParamStoreKeyUploadAccess, &p.CodeUploadAccess, validateAccessConfig),
		paramtypes.NewParamSetPair(ParamStoreKeyInstantiateAccess, &p.InstantiateDefaultPermission, validateAccessType),
		paramtypes.NewParamSetPair(ParamStoreKeyBach32IbcPortTranslate, &p.Bach32IbcPortTranslate, validateBach32IbcPortTranslate),
	}
}

// ValidateBasic performs basic validation on wasm parameters
func (p Params) ValidateBasic() error {
	if err := validateAccessType(p.InstantiateDefaultPermission); err != nil {
		return errors.Wrap(err, "instantiate default permission")
	}
	if err := validateAccessConfig(p.CodeUploadAccess); err != nil {
		return errors.Wrap(err, "upload access")
	}
	if err := validateBach32IbcPortTranslate(p.Bach32IbcPortTranslate); err != nil {
		return errors.Wrap(err, "translate")
	}
	return nil
}

func validateAccessConfig(i interface{}) error {
	v, ok := i.(AccessConfig)
	if !ok {
		return fmt.Errorf("invalid parameter type: %T", i)
	}
	return v.ValidateBasic()
}

func validateAccessType(i interface{}) error {
	a, ok := i.(AccessType)
	if !ok {
		return fmt.Errorf("invalid parameter type: %T", i)
	}
	if a == AccessTypeUnspecified {
		return sdkerrors.Wrap(ErrEmpty, "type")
	}
	for _, v := range AllAccessTypes {
		if v == a {
			return nil
		}
	}
	return sdkerrors.Wrapf(ErrInvalid, "unknown type: %q", a)
}

// IsValidID defines regular expression to check if the string consist of
// characters in one of the following categories only:
// - Alphanumeric
// - `.`, `_`, `+`, `-`, `#`
// - `[`, `]`, `<`, `>`
var IsValid024 = regexp.MustCompile(`^[a-zA-Z0-9\.\_\+\-\#\[\]\<\>]+$`).MatchString
var IsReverseValid024 = regexp.MustCompile(`^[\.\_\+\-\#\[\]\<\>]+$`).MatchString

// ICS 024 Identifier and Path Validation Implementation
//
// This file defines ValidateFn to validate identifier and path strings
// The spec for ICS 024 can be located here:
// https://github.com/cosmos/ibc/tree/master/spec/core/ics-024-host-requirements

func ics024TargetTrValidator(trg_tr string) error {
	// valid string must contain only 024 special valid characters
	if !IsValid024(trg_tr) {
		return sdkerrors.Wrapf(
			ErrInvalid,
			"string %s must contain only alphanumeric or the following characters: '.', '_', '+', '-', '#', '[', ']', '<', '>'",
			trg_tr,
		)
	}
	return nil
}

func ics024SourceTrValidator(src_tr string) error {
	// valid string must not contain  024 special characters
	if IsReverseValid024(src_tr) {
		return sdkerrors.Wrapf(
			ErrInvalid,
			"string %s must not contain the following characters: '.', '_', '+', '-', '#', '[', ']', '<', '>'",
			src_tr,
		)
	}
	// HRP must contain only US-ASCII characters with values in the range [33-126]
	for _, c := range src_tr {
		if c < 33 || c > 126 {
			return sdkerrors.Wrapf(
				ErrInvalid,
				"string %s must contain the ascii characters between 33 and 126",
				src_tr,
			)
		}
	}

	return nil

}

func validateBach32IbcPortTranslate(i interface{}) error {
	if i == nil {
		return nil
	}
	v, ok := i.([]string)
	if !ok {
		return fmt.Errorf("invalid parameter type: %T", i)
	}
	if len(v) == 0 {
		return nil
	}
	if len(v) != 2 {
		return sdkerrors.Wrapf(ErrLimit, "the lenght of the array must be 2 not %d", len(v))
	}
	if len(v[0]) != len(v[1]) {
		return sdkerrors.Wrap(ErrLimit, "the lenght of the elements must be equal")
	}
	if err := ics024SourceTrValidator(v[0]); err != nil {
		return sdkerrors.Wrapf(err, "string %s contains invalid chars", v[0])
	}
	if err := ics024TargetTrValidator(v[1]); err != nil {
		return sdkerrors.Wrapf(err, "string %s contains invalid chars", v[1])
	}
	return nil
}

// ValidateBasic performs basic validation
func (a AccessConfig) ValidateBasic() error {
	switch a.Permission {
	case AccessTypeUnspecified:
		return sdkerrors.Wrap(ErrEmpty, "type")
	case AccessTypeNobody, AccessTypeEverybody:
		if len(a.Address) != 0 {
			return sdkerrors.Wrap(ErrInvalid, "address not allowed for this type")
		}
		return nil
	case AccessTypeOnlyAddress:
		if len(a.Addresses) != 0 {
			return ErrInvalid.Wrap("addresses field set")
		}
		_, err := sdk.AccAddressFromBech32(a.Address)
		return err
	case AccessTypeAnyOfAddresses:
		if a.Address != "" {
			return ErrInvalid.Wrap("address field set")
		}
		return sdkerrors.Wrap(assertValidAddresses(a.Addresses), "addresses")
	}
	return sdkerrors.Wrapf(ErrInvalid, "unknown type: %q", a.Permission)
}

func assertValidAddresses(addrs []string) error {
	if len(addrs) == 0 {
		return ErrEmpty
	}
	idx := make(map[string]struct{}, len(addrs))
	for _, a := range addrs {
		if _, err := sdk.AccAddressFromBech32(a); err != nil {
			return sdkerrors.Wrapf(err, "address: %s", a)
		}
		if _, exists := idx[a]; exists {
			return ErrDuplicate.Wrapf("address: %s", a)
		}
		idx[a] = struct{}{}
	}
	return nil
}

// Allowed returns if permission includes the actor.
// Actor address must be valid and not nil
func (a AccessConfig) Allowed(actor sdk.AccAddress) bool {
	switch a.Permission {
	case AccessTypeNobody:
		return false
	case AccessTypeEverybody:
		return true
	case AccessTypeOnlyAddress:
		return a.Address == actor.String()
	case AccessTypeAnyOfAddresses:
		for _, v := range a.Addresses {
			if v == actor.String() {
				return true
			}
		}
		return false
	default:
		panic("unknown type")
	}
}
