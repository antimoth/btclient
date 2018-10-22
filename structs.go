package btclient

import (
	"github.com/btcsuite/btcd/wire"
)

type PreparedTx struct {
	Tx            *wire.MsgTx
	TxIx          int
	BlockHeight   int64
	BlockHash     string
	Confirmations int64
}
