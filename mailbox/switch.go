package mailbox

import (
	"crypto/sha512"
	"net"
	"sync"

	"github.com/btcsuite/btcd/btcec"
	"github.com/lightningnetwork/lnd/keychain"
)

type SwitchConn struct {
	cfg *SwitchConfig

	ProxyConn

	sid   [64]byte
	sidMu sync.Mutex

	closeOnce sync.Once
	quit      chan struct{}
}

type SwitchConfig struct {
	ServerHost string

	Password  []byte
	RemoteKey *btcec.PublicKey
	LocalKey  keychain.SingleKeyECDH

	NewProxyConn     func(sid [64]byte) (ProxyConn, error)
	RefreshProxyConn func(conn ProxyConn) (ProxyConn, error)
	StopProxyConn    func(conn ProxyConn) error
}

func NewSwitchConn(cfg *SwitchConfig) (*SwitchConn, error) {

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

	sid := sha512.Sum512(entropy)

	mailboxConn, err := cfg.NewProxyConn(sid)
	if err != nil {
		log.Errorf("couldn't create new server: %v", err)
		if err := mailboxConn.Close(); err != nil {
			return nil, &temporaryError{err}
		}
		return nil, &temporaryError{err}
	}

	return &SwitchConn{
		cfg:       cfg,
		sid:       sid,
		ProxyConn: mailboxConn,
		quit:      make(chan struct{}),
	}, nil
}

func RefreshSwitchConn(s *SwitchConn) (*SwitchConn, error) {
	s.sidMu.Lock()
	defer s.sidMu.Unlock()
	sc := &SwitchConn{
		cfg:  s.cfg,
		sid:  s.sid,
		quit: make(chan struct{}),
	}

	conn, err := s.cfg.RefreshProxyConn(s.ProxyConn)
	if err != nil {
		return nil, err
	}

	sc.ProxyConn = conn

	return sc, nil
}

func (s *SwitchConn) Addr() net.Addr {
	return &Addr{SID: s.sid, Server: s.cfg.ServerHost}
}

func (s *SwitchConn) Close() error {
	var returnErr error
	s.closeOnce.Do(func() {
		if err := s.ProxyConn.Close(); err != nil {
			returnErr = err
		}

		close(s.quit)
	})

	return returnErr
}

func (s *SwitchConn) Done() chan struct{} {
	return s.quit
}

func (s *SwitchConn) Switch(remoteKey *btcec.PublicKey) error {
	if err := s.cfg.StopProxyConn(s.ProxyConn); err != nil {
		return err
	}

	entropy, err := ecdh(remoteKey, s.cfg.LocalKey)
	if err != nil {
		return err
	}

	s.sidMu.Lock()
	s.sid = sha512.Sum512(entropy)

	conn, err := s.cfg.NewProxyConn(s.sid)
	s.sidMu.Unlock()
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
