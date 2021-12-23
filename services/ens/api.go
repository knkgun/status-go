package ens

import (
	"context"
	"encoding/binary"
	"encoding/hex"
	"fmt"
	"math/big"

	"github.com/ipfs/go-cid"
	"github.com/multiformats/go-multibase"
	"github.com/multiformats/go-multihash"
	"github.com/pkg/errors"
	"github.com/wealdtech/go-multicodec"

	"github.com/ethereum/go-ethereum/accounts/abi/bind"
	"github.com/ethereum/go-ethereum/common"
	ethTypes "github.com/ethereum/go-ethereum/core/types"
	"github.com/status-im/status-go/account"
	"github.com/status-im/status-go/eth-node/types"
	"github.com/status-im/status-go/params"
	"github.com/status-im/status-go/rpc"
	"github.com/status-im/status-go/transactions"
)

func NewAPI(rpcClient *rpc.Client, accountsManager *account.GethManager, config *params.NodeConfig) *API {
	return &API{
		contractMaker: &contractMaker{
			rpcClient: rpcClient,
		},
		accountsManager: accountsManager,
		config:          config,
	}
}

type uri struct {
	Scheme string
	Host   string
	Path   string
}

type publicKey struct {
	X [32]byte
	Y [32]byte
}

type API struct {
	contractMaker   *contractMaker
	accountsManager *account.GethManager
	config          *params.NodeConfig
}

func (api *API) Resolver(ctx context.Context, chainID uint64, username string) (*common.Address, error) {
	err := validateENSUsername(username)
	if err != nil {
		return nil, err
	}

	registry, err := api.contractMaker.newRegistry(chainID)
	if err != nil {
		return nil, err
	}

	callOpts := &bind.CallOpts{Context: ctx, Pending: false}
	resolver, err := registry.Resolver(callOpts, nameHash(username))
	if err != nil {
		return nil, err
	}

	return &resolver, nil
}

func (api *API) OwnerOf(ctx context.Context, chainID uint64, username string) (*common.Address, error) {
	err := validateENSUsername(username)
	if err != nil {
		return nil, err
	}

	registry, err := api.contractMaker.newRegistry(chainID)
	if err != nil {
		return nil, err
	}

	callOpts := &bind.CallOpts{Context: ctx, Pending: false}
	owner, err := registry.Owner(callOpts, nameHash(username))
	if err != nil {
		return nil, nil
	}

	return &owner, nil
}

func (api *API) ContentHash(ctx context.Context, chainID uint64, username string) ([]byte, error) {
	err := validateENSUsername(username)
	if err != nil {
		return nil, err
	}

	resolverAddress, err := api.Resolver(ctx, chainID, username)
	if err != nil {
		return nil, err
	}

	resolver, err := api.contractMaker.newPublicResolver(chainID, resolverAddress)
	if err != nil {
		return nil, err
	}

	callOpts := &bind.CallOpts{Context: ctx, Pending: false}
	contentHash, err := resolver.Contenthash(callOpts, nameHash(username))
	if err != nil {
		return nil, nil
	}

	return contentHash, nil
}

func (api *API) PublicKeyOf(ctx context.Context, chainID uint64, username string) (*publicKey, error) {
	err := validateENSUsername(username)
	if err != nil {
		return nil, err
	}

	resolverAddress, err := api.Resolver(ctx, chainID, username)
	if err != nil {
		return nil, err
	}

	resolver, err := api.contractMaker.newPublicResolver(chainID, resolverAddress)
	if err != nil {
		return nil, err
	}

	callOpts := &bind.CallOpts{Context: ctx, Pending: false}
	pubKey, err := resolver.Pubkey(callOpts, nameHash(username))
	if err != nil {
		return nil, err
	}

	return &publicKey{pubKey.X, pubKey.Y}, nil
}

func (api *API) AddressOf(ctx context.Context, chainID uint64, username string) (*common.Address, error) {
	err := validateENSUsername(username)
	if err != nil {
		return nil, err
	}

	resolverAddress, err := api.Resolver(ctx, chainID, username)
	if err != nil {
		return nil, err
	}

	resolver, err := api.contractMaker.newPublicResolver(chainID, resolverAddress)
	if err != nil {
		return nil, err
	}

	callOpts := &bind.CallOpts{Context: ctx, Pending: false}
	addr, err := resolver.Addr(callOpts, nameHash(username))
	if err != nil {
		return nil, err
	}

	return &addr, nil
}

func (api *API) ExpireAt(ctx context.Context, chainID uint64, username string) (*big.Int, error) {
	err := validateENSUsername(username)
	if err != nil {
		return nil, err
	}

	registrar, err := api.contractMaker.newUsernameRegistrar(chainID)
	if err != nil {
		return nil, err
	}

	callOpts := &bind.CallOpts{Context: ctx, Pending: false}
	expTime, err := registrar.GetExpirationTime(callOpts, nameHash(username))
	if err != nil {
		return nil, err
	}

	return expTime, nil
}

func (api *API) Price(ctx context.Context, chainID uint64) (*big.Int, error) {
	registrar, err := api.contractMaker.newUsernameRegistrar(chainID)
	if err != nil {
		return nil, err
	}

	callOpts := &bind.CallOpts{Context: ctx, Pending: false}
	price, err := registrar.GetPrice(callOpts)
	if err != nil {
		return nil, err
	}

	return price, nil
}

// TODO: implement once the send tx as been refactored
// func (api *API) Release(ctx context.Context, chainID uint64, from string, gasPrice *big.Int, gasLimit uint64, password string, username string) (string, error) {
// 	err := validateENSUsername(username)
// 	if err != nil {
// 		return "", err
// 	}

// 	registrar, err := api.contractMaker.newUsernameRegistrar(chainID)
// 	if err != nil {
// 		return "", err
// 	}

// 	txOpts := &bind.TransactOpts{
// 		From: common.HexToAddress(from),
// 		Signer: func(addr common.Address, tx *ethTypes.Transaction) (*ethTypes.Transaction, error) {
// 			// return types.SignTx(tx, types.NewLondonSigner(chainID), selectedAccount.AccountKey.PrivateKey)
// 			return nil, nil
// 		},
// 		GasPrice: gasPrice,
// 		GasLimit: gasLimit,
// 	}
// 	tx, err := registrar.Release(txOpts, nameHash(username))
// 	if err != nil {
// 		return "", err
// 	}
// 	return tx.Hash().String(), nil
// }

func (api *API) getSigner(chainID uint64, from types.Address, password string) bind.SignerFn {
	return func(addr common.Address, tx *ethTypes.Transaction) (*ethTypes.Transaction, error) {
		selectedAccount, err := api.accountsManager.VerifyAccountPassword(api.config.KeyStoreDir, from.Hex(), password)
		if err != nil {
			return nil, err
		}
		s := ethTypes.NewLondonSigner(new(big.Int).SetUint64(chainID))
		return ethTypes.SignTx(tx, s, selectedAccount.PrivateKey)
	}
}

func (api *API) Register(ctx context.Context, chainID uint64, txArgs transactions.SendTxArgs, password string, username string, x [32]byte, y [32]byte) (string, error) {
	err := validateENSUsername(username)
	if err != nil {
		return "", err
	}

	registrar, err := api.contractMaker.newUsernameRegistrar(chainID)
	if err != nil {
		return "", err
	}

	txOpts := txArgs.ToTransactOpts(api.getSigner(chainID, txArgs.From, password))
	tx, err := registrar.Register(
		txOpts,
		nameHash(username),
		common.Address(txArgs.From),
		x,
		y,
	)
	if err != nil {
		return "", err
	}
	return tx.Hash().String(), nil
}

func (api *API) ResourceURL(ctx context.Context, chainID uint64, username string) (*uri, error) {
	scheme := "https"
	contentHash, err := api.ContentHash(ctx, chainID, username)
	if err != nil {
		return nil, err
	}

	if len(contentHash) == 0 {
		return &uri{}, nil
	}

	data, codec, err := multicodec.RemoveCodec(contentHash)
	if err != nil {
		return nil, err
	}
	codecName, err := multicodec.Name(codec)
	if err != nil {
		return nil, err
	}

	switch codecName {
	case "ipfs-ns":
		thisCID, err := cid.Parse(data)
		if err != nil {
			return nil, errors.Wrap(err, "failed to parse CID")
		}
		str, err := thisCID.StringOfBase(multibase.Base32)
		if err != nil {
			return nil, errors.Wrap(err, "failed to obtain base36 representation")
		}
		host := str + ".ipfs.cf-ipfs.com"
		return &uri{scheme, host, ""}, nil
	case "ipns-ns":
		id, offset := binary.Uvarint(data)
		if id == 0 {
			return nil, fmt.Errorf("unknown CID")
		}

		data, _, err := multicodec.RemoveCodec(data[offset:])
		if err != nil {
			return nil, err
		}
		decodedMHash, err := multihash.Decode(data)
		if err != nil {
			return nil, err
		}

		return &uri{scheme, string(decodedMHash.Digest), ""}, nil
	case "swarm-ns":
		id, offset := binary.Uvarint(data)
		if id == 0 {
			return nil, fmt.Errorf("unknown CID")
		}
		data, _, err := multicodec.RemoveCodec(data[offset:])
		if err != nil {
			return nil, err
		}
		decodedMHash, err := multihash.Decode(data)
		if err != nil {
			return nil, err
		}
		path := "/bzz:/" + hex.EncodeToString(decodedMHash.Digest) + "/"
		return &uri{scheme, "swarm-gateways.net", path}, nil
	default:
		return nil, fmt.Errorf("unknown codec name %s", codecName)
	}
}
