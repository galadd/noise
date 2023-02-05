package pattern

const (
	E = "e"
	EE = "ee"
	ES = "es"
	S = "s"
	SE = "se"
	SS = "ss"
)

type messages []string

type HandshakePattern struct {
	Name string
	PreMessagePatterns []messages
	MessagePatterns []messages
}

var (
	Noise_N = HandshakePattern{
		Name: "N",
		PreMessagePatterns: []messages{
			{},
			{S},
		},
		MessagePatterns: []messages{
			{E, ES},
		},
	}
	Noise_K = HandshakePattern{
		Name: "K",
		PreMessagePatterns: []messages{
			{S},
			{S},
		},
		MessagePatterns: []messages{
			{E, ES, SS},
		},
	}
	Noise_X = HandshakePattern{
		Name: "X",
		PreMessagePatterns: []messages{
			{},
			{S},
		},
		MessagePatterns: []messages{
			{E, ES, S, SS},
		},
	}
	Noise_NN = HandshakePattern{
		Name: "NN",
		PreMessagePatterns: []messages{
			{},
			{},
		},
		MessagePatterns: []messages{
			{E},
			{E, EE},
		},
	}
	Noise_NK = HandshakePattern{
		Name: "NK",
		PreMessagePatterns: []messages{
			{},
			{S},
		},
		MessagePatterns: []messages{
			{E, ES},
			{E, EE},
		},
	}
	Noise_NX = HandshakePattern{
		Name: "NX",
		PreMessagePatterns: []messages{
			{},
			{S},
		},
		MessagePatterns: []messages{
			{E},
			{E, EE, S, ES},
		},
	}
	Noise_XN = HandshakePattern{
		Name: "XN",
		PreMessagePatterns: []messages{	
			{},
			{},
		},
		MessagePatterns: []messages{
			{E},
			{E, EE},
			{S, SE},
		},
	}
	Noise_XK = HandshakePattern{	
		Name: "XK",
		PreMessagePatterns: []messages{
			{},
			{S},
		},
		MessagePatterns: []messages{
			{E, ES},
			{E, EE},
			{S, SE},
		},
	}
	Noise_XX = HandshakePattern{
		Name: "XX",
		PreMessagePatterns: []messages{
			{},
			{},
		},
		MessagePatterns: []messages{
			{E},
			{E, EE, S, ES},
			{S, SE},
		},
	}
	Noise_KN = HandshakePattern{
		Name: "KN",
		PreMessagePatterns: []messages{
			{S},
			{},
		},
		MessagePatterns: []messages{
			{E},
			{E, EE, SE},
		},
	}
	Noise_KK = HandshakePattern{
		Name: "KK",
		PreMessagePatterns: []messages{
			{S},
			{S},
		},
		MessagePatterns: []messages{
			{E, ES, SS},
			{E, EE, SE},
		},
	}
	Noise_KX = HandshakePattern{
		Name: "KX",	
		PreMessagePatterns: []messages{
			{S},
			{},
		},
		MessagePatterns: []messages{
			{E},
			{E, EE, SE, S, ES},
		},
	}
	Noise_IN = HandshakePattern{
		Name: "IN",
		PreMessagePatterns: []messages{
			{},
			{},
		},
		MessagePatterns: []messages{
			{E, S},
			{E, EE, SE},
		},
	}
	Noise_IK = HandshakePattern{
		Name: "IK",
		PreMessagePatterns: []messages{
			{},
			{S},
		},
		MessagePatterns: []messages{
			{E, ES, S, SS},
			{E, EE, SE},
		},
	}
	Noise_IX = HandshakePattern{
		Name: "IX",
		PreMessagePatterns: []messages{
			{},
			{},
		},
		MessagePatterns: []messages{
			{E, S},
			{E, EE, SE, S, ES},
		},
	}
)

var HandshakePatterns = map[string]HandshakePattern{
	"N": Noise_N,
	"K": Noise_K,
	"X": Noise_X,
	"NN": Noise_NN,
	"NK": Noise_NK,
	"NX": Noise_NX,
	"XN": Noise_XN,
	"XK": Noise_XK,
	"XX": Noise_XX,
	"KN": Noise_KN,
	"KK": Noise_KK,
	"KX": Noise_KX,	
	"IN": Noise_IN,
	"IK": Noise_IK,
	"IX": Noise_IX,
}


