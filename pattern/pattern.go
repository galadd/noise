package pattern

const (
	E string = "e"
	EE = "ee"
	ES = "es"
	S = "s"
	SE = "se"
	SS = "ss"
)

type Messages []string

type HandshakePattern struct {
	Name string
	PreMessagePatterns []Messages
	MessagePatterns []Messages
}

var (
	Noise_N = HandshakePattern{
		Name: "N",
		PreMessagePatterns: []Messages{
			{},
			{S},
		},
		MessagePatterns: []Messages{
			{E, ES},
		},
	}
	Noise_K = HandshakePattern{
		Name: "K",
		PreMessagePatterns: []Messages{
			{S},
			{S},
		},
		MessagePatterns: []Messages{
			{E, ES, SS},
		},
	}
	Noise_X = HandshakePattern{
		Name: "X",
		PreMessagePatterns: []Messages{
			{},
			{S},
		},
		MessagePatterns: []Messages{
			{E, ES, S, SS},
		},
	}
	Noise_NN = HandshakePattern{
		Name: "NN",
		PreMessagePatterns: []Messages{
			{},
			{},
		},
		MessagePatterns: []Messages{
			{E},
			{E, EE},
		},
	}
	Noise_NK = HandshakePattern{
		Name: "NK",
		PreMessagePatterns: []Messages{
			{},
			{S},
		},
		MessagePatterns: []Messages{
			{E, ES},
			{E, EE},
		},
	}
	Noise_NX = HandshakePattern{
		Name: "NX",
		PreMessagePatterns: []Messages{
			{},
			{S},
		},
		MessagePatterns: []Messages{
			{E},
			{E, EE, S, ES},
		},
	}
	Noise_XN = HandshakePattern{
		Name: "XN",
		PreMessagePatterns: []Messages{	
			{},
			{},
		},
		MessagePatterns: []Messages{
			{E},
			{E, EE},
			{S, SE},
		},
	}
	Noise_XK = HandshakePattern{	
		Name: "XK",
		PreMessagePatterns: []Messages{
			{},
			{S},
		},
		MessagePatterns: []Messages{
			{E, ES},
			{E, EE},
			{S, SE},
		},
	}
	Noise_XX = HandshakePattern{
		Name: "XX",
		PreMessagePatterns: []Messages{
			{},
			{},
		},
		MessagePatterns: []Messages{
			{E},
			{E, EE, S, ES},
			{S, SE},
		},
	}
	Noise_KN = HandshakePattern{
		Name: "KN",
		PreMessagePatterns: []Messages{
			{S},
			{},
		},
		MessagePatterns: []Messages{
			{E},
			{E, EE, SE},
		},
	}
	Noise_KK = HandshakePattern{
		Name: "KK",
		PreMessagePatterns: []Messages{
			{S},
			{S},
		},
		MessagePatterns: []Messages{
			{E, ES, SS},
			{E, EE, SE},
		},
	}
	Noise_KX = HandshakePattern{
		Name: "KX",	
		PreMessagePatterns: []Messages{
			{S},
			{},
		},
		MessagePatterns: []Messages{
			{E},
			{E, EE, SE, S, ES},
		},
	}
	Noise_IN = HandshakePattern{
		Name: "IN",
		PreMessagePatterns: []Messages{
			{},
			{},
		},
		MessagePatterns: []Messages{
			{E, S},
			{E, EE, SE},
		},
	}
	Noise_IK = HandshakePattern{
		Name: "IK",
		PreMessagePatterns: []Messages{
			{},
			{S},
		},
		MessagePatterns: []Messages{
			{E, ES, S, SS},
			{E, EE, SE},
		},
	}
	Noise_IX = HandshakePattern{
		Name: "IX",
		PreMessagePatterns: []Messages{
			{},
			{},
		},
		MessagePatterns: []Messages{
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


