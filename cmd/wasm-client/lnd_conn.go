//go:build js
// +build js

package main

import (
	"context"
	"strings"

	"github.com/btcsuite/btcd/btcec/v2"
	"github.com/lightninglabs/lightning-node-connect/mailbox"
	"github.com/lightningnetwork/lnd/keychain"
	"google.golang.org/grpc"
)

func mailboxRPCConnection(mailboxServer, pairingPhrase string,
	localStatic keychain.SingleKeyECDH, remoteStatic *btcec.PublicKey,
	onRemoteStatic func(key *btcec.PublicKey) error,
	onAuthData func(data []byte) error) (func() mailbox.ClientStatus,
	func() (*grpc.ClientConn, error), error) {

	words := strings.Split(pairingPhrase, " ")
	var mnemonicWords [mailbox.NumPassphraseWords]string
	copy(mnemonicWords[:], words)
	entropy := mailbox.PassphraseMnemonicToEntropy(mnemonicWords)

	connData := mailbox.NewConnData(
		localStatic, remoteStatic, entropy[:], nil, onRemoteStatic,
		onAuthData,
	)

	ctx := context.Background()
	transportConn, err := mailbox.NewClient(
		ctx, mailboxServer, connData, true,
	)
	if err != nil {
		return nil, nil, err
	}

	noiseConn := mailbox.NewNoiseGrpcConn(connData)

	dialOpts := []grpc.DialOption{
		grpc.WithContextDialer(transportConn.Dial),
		grpc.WithTransportCredentials(noiseConn),
		grpc.WithPerRPCCredentials(noiseConn),
		grpc.WithDefaultCallOptions(
			grpc.MaxCallRecvMsgSize(1024 * 1024 * 200),
		),
		grpc.WithBlock(),
	}

	return transportConn.ConnStatus, func() (*grpc.ClientConn, error) {
		return grpc.DialContext(ctx, mailboxServer, dialOpts...)
	}, nil
}
