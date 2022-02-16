package mailbox

import (
	"context"
	"crypto/sha512"
	"io"
	"net"
	"sync"

	"github.com/btcsuite/btcd/btcec"
	"github.com/lightningnetwork/lnd/keychain"
)

type SwitchConn struct {
	cfg *SwitchConfig

	ctx context.Context

	sid   [64]byte
	sidMu sync.Mutex

	ProxyConn
}

type SwitchConfig struct {
	ServerHost string

	Password  []byte
	RemoteKey *btcec.PublicKey
	LocalKey  keychain.SingleKeyECDH

	NewProxyConn func(sid [64]byte) (ProxyConn, error)

	RefreshProxyConn func(conn ProxyConn) (ProxyConn, error)

	StopProxyConn func(conn ProxyConn) error
}

func NewSwitchConn(ctx context.Context, cfg *SwitchConfig) (*SwitchConn,
	error) {

	var (
		entropy = cfg.Password
		err     error
	)
	if cfg.RemoteKey != nil {
		entropy, err = ecdh(cfg.RemoteKey, cfg.LocalKey)
		if err != nil {
			return nil, err
		}
	}

	return &SwitchConn{
		ctx: ctx,
		cfg: cfg,
		sid: sha512.Sum512(entropy),
	}, nil
}

func (s *SwitchConn) NextConn() error {
	// If there is currently an active connection, block here until the
	// previous connection as been closed.
	if s.ProxyConn != nil {
		log.Debugf("Accept: have existing mailbox connection, waiting")
		select {
		case <-s.ctx.Done():
			return io.EOF
		case <-s.ProxyConn.Done():
			log.Debugf("Accept: done with existing conn")
		}
	}

	// If this is the first connection, we create a new ServerConn object.
	// otherwise, we just refresh the ServerConn.
	var (
		conn ProxyConn
		err  error
	)
	if s.ProxyConn == nil {
		conn, err = s.cfg.NewProxyConn(s.sid)
		if err != nil {
			log.Errorf("couldn't create new server: %v", err)
			if err := conn.Close(); err != nil {
				return err
			}
			return err
		}
	} else {
		conn, err = s.cfg.RefreshProxyConn(s.ProxyConn)
		if err != nil {
			log.Errorf("couldn't refresh server: %v", err)
			if err := s.cfg.StopProxyConn(conn); err != nil {
				return err
			}

			s.ProxyConn = nil
			return err
		}
	}

	s.ProxyConn = conn
	return nil
}

func (s *SwitchConn) Addr() net.Addr {
	return &Addr{SID: s.sid, Server: s.cfg.ServerHost}
}

func (s *SwitchConn) Switch(remoteKey *btcec.PublicKey) error {

	if err := s.cfg.StopProxyConn(s.ProxyConn); err != nil {
		return err
	}

	entropy, err := ecdh(remoteKey, s.cfg.LocalKey)
	if err != nil {
		return err
	}

	s.sid = sha512.Sum512(entropy)

	conn, err := s.cfg.NewProxyConn(s.sid)
	if err != nil {
		log.Errorf("couldn't create new server: %v", err)
		if err := conn.Close(); err != nil {
			return err
		}
		return err
	}

	s.ProxyConn = conn
	return nil
}

func (s *SwitchConn) Stop() error {
	if s.ProxyConn != nil {
		if err := s.cfg.StopProxyConn(s.ProxyConn); err != nil {
			return err
		}
	}

	return nil
}

func GetSID(sid [64]byte, serverToClient bool) [64]byte {
	if serverToClient {
		return sid
	}

	var clientToServerSID [64]byte
	copy(clientToServerSID[:], sid[:])
	clientToServerSID[63] ^= 0x01

	return clientToServerSID
}
