package btclient

import (
	"github.com/btcsuite/btcd/chaincfg/chainhash"
)

var (
	EmptyHash = new(chainhash.Hash)
)

func HexToHash(sHexTxHash string) *chainhash.Hash {
	if sHexTxHash[0:2] == "0x" || sHexTxHash[0:2] == "0X" {
		sHexTxHash = sHexTxHash[2:]
	}

	if len(sHexTxHash)%2 == 1 {
		sHexTxHash = "0" + sHexTxHash
	}

	hash, err := chainhash.NewHashFromStr(sHexTxHash)
	if err != nil {
		bcLogger.Warn("decode hex to hash error", "error", err, "hash", sHexTxHash)
		hash = new(chainhash.Hash)
	}

	return hash
}
