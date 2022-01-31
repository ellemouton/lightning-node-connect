package mailbox

var (
	// XXPattern
	// -> me
	// <- e, ee, s, es
	// -> s, se
	XXPattern = HandshakePattern{
		Name: "XXeke+SPAKE2",
		Pattern: []MessagePattern{
			{
				Tokens:    []Token{me},
				Initiator: true,
				ActNum:    act1,
			},
			{
				Tokens:    []Token{e, ee, s, es},
				Initiator: false,
				ActNum:    act2,
			},
			{
				Tokens:    []Token{s, se},
				Initiator: true,
				ActNum:    act3,
			},
		},
	}

	// KKPattern
	// -> s
	// <- s
	// ...
	// <- e, es, ss
	// -> e, ee, se
	KKPattern = HandshakePattern{
		Name: "KK",
		PreMessages: []MessagePattern{
			{
				Tokens:    []Token{s},
				Initiator: true,
			},
			{
				Tokens:    []Token{s},
				Initiator: false,
			},
		},
		Pattern: []MessagePattern{
			{
				Tokens:    []Token{e, es, ss},
				Initiator: true,
				ActNum:    act1,
			},
			{
				Tokens:    []Token{e, ee, se},
				Initiator: false,
				ActNum:    act2,
			},
		},
	}
)

// HandshakePattern represents the Noise pattern being used.
type HandshakePattern struct {
	PreMessages []MessagePattern
	Pattern     []MessagePattern
	Name        string
}

// A MessagePattern represents a Token or a stream of Tokens. MessagePatterns
// are used to make up a HandshakePattern.
type MessagePattern struct {
	Tokens    []Token
	Initiator bool
	ActNum    ActNum
}

// Token represents either a public key that should be transmitted or received
// from the handshake peer or a DH operation that should be performed. Tokens
// are used to create MessagePatterns.
type Token string

const (
	e  Token = "e"
	s  Token = "s"
	ee Token = "ee"
	es Token = "es"
	se Token = "se"
	ss Token = "ss"
	me Token = "me"
)

// ActNum is the
type ActNum uint8

const (
	act1 ActNum = 1
	act2 ActNum = 2
	act3 ActNum = 3
)
