package keeper

import (
	"strings"

	sdk "github.com/cosmos/cosmos-sdk/types"
	sdkerrors "github.com/cosmos/cosmos-sdk/types/errors"
	capabilitytypes "github.com/cosmos/cosmos-sdk/x/capability/types"
	host "github.com/cosmos/ibc-go/v4/modules/core/24-host"

	"github.com/CosmWasm/wasmd/x/wasm/types"
)

// bindIbcPort will reserve the port.
// returns a string name of the port or error if we cannot bind it.
// this will fail if call twice.
func (k Keeper) bindIbcPort(ctx sdk.Context, portID string) error {
	cap := k.portKeeper.BindPort(ctx, portID)
	return k.ClaimCapability(ctx, cap, host.PortPath(portID))
}

// ensureIbcPort is like registerIbcPort, but it checks if we already hold the port
// before calling register, so this is safe to call multiple times.
// Returns success if we already registered or just registered and error if we cannot
// (lack of permissions or someone else has it)
func (k Keeper) ensureIbcPort(ctx sdk.Context, contractAddr sdk.AccAddress) (string, error) {
	translate := k.getBach32IbcPortTranslate(ctx)
	portID := PortIDForContract(contractAddr, translate)
	if _, ok := k.capabilityKeeper.GetCapability(ctx, host.PortPath(portID)); ok {
		return portID, nil
	}
	return portID, k.bindIbcPort(ctx, portID)
}

const portIDPrefix = "wasm."

func PortIDForContract(addr sdk.AccAddress, translate []string) string {
	translateAddr := addr.String()
	if translate != nil && len(translate) != 0 {
		for i, t := range translate[0] {
			translateAddr = strings.Replace(translateAddr, string(t), string(translate[1][i]), -1)
		}
	}
	return portIDPrefix + translateAddr
}

func ContractFromPortID(portID string, translate []string) (sdk.AccAddress, error) {
	if !strings.HasPrefix(portID, portIDPrefix) {
		return nil, sdkerrors.Wrapf(types.ErrInvalid, "without prefix")
	}
	translateAddr := portID[len(portIDPrefix):]
	if translate != nil && len(translate) != 0 {
		for i, t := range translate[1] {
			translateAddr = strings.Replace(translateAddr, string(t), string(translate[0][i]), -1)
		}
	}
	return sdk.AccAddressFromBech32(translateAddr)
}

// AuthenticateCapability wraps the scopedKeeper's AuthenticateCapability function
func (k Keeper) AuthenticateCapability(ctx sdk.Context, cap *capabilitytypes.Capability, name string) bool {
	return k.capabilityKeeper.AuthenticateCapability(ctx, cap, name)
}

// ClaimCapability allows the transfer module to claim a capability
// that IBC module passes to it
func (k Keeper) ClaimCapability(ctx sdk.Context, cap *capabilitytypes.Capability, name string) error {
	return k.capabilityKeeper.ClaimCapability(ctx, cap, name)
}
