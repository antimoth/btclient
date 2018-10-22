package btclient

import (
	"errors"
)

var (
	ErrChainCode = errors.New("unknown chain code")
	ErrSignVin   = errors.New("sign vin out of range")
)
