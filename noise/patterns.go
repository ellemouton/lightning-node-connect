package noise

type HandshakePattern struct {
	PreMessages []MessagePattern
	Pattern     []MessagePattern
	Name        string
}

type MessagePattern struct {
	tokens    []Token
	initiator bool
	actNum    int
}

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

// XXPattern
// -> me
// <- e, ee, s, es
// -> s, se
func XXPattern() HandshakePattern {
	return HandshakePattern{
		Pattern: []MessagePattern{
			{
				tokens:    []Token{me},
				initiator: true,
				actNum:    1,
			},
			{
				tokens:    []Token{e, ee, s, es},
				initiator: false,
				actNum:    2,
			},
			{
				tokens:    []Token{s, se},
				initiator: true,
				actNum:    3,
			},
		},
		Name: "XXeke+SPAKE2",
	}
}

// KKPattern
// -> s
// <- s
// ...
// <- e, es, ss
// -> e, ee, se
func KKPattern() HandshakePattern {
	return HandshakePattern{
		PreMessages: []MessagePattern{
			{
				tokens:    []Token{s},
				initiator: true,
			},
			{
				tokens:    []Token{s},
				initiator: false,
			},
		},
		Pattern: []MessagePattern{
			{
				tokens:    []Token{e, es, ss},
				initiator: true,
				actNum:    1,
			},
			{
				tokens:    []Token{e, ee, se},
				initiator: false,
				actNum:    2,
			},
		},
		Name: "KK",
	}
}
