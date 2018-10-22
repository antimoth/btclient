package btclient

import (
	"bytes"
	"encoding/binary"
	"encoding/hex"
	"reflect"

	"github.com/ofgp/common/defines"

	"github.com/btcsuite/btcd/chaincfg"
	"github.com/btcsuite/btcd/chaincfg/chainhash"
	"github.com/btcsuite/btcd/txscript"
	"github.com/btcsuite/btcd/wire"
	"github.com/btcsuite/btcutil"
	"github.com/cpacia/bchutil"
	"github.com/spf13/viper"
)

const (
	SigHashForkID txscript.SigHashType = 0x40
	sigHashMask                        = 0x1f
)

var (
	EmptyHash = new(chainhash.Hash)
)

func init() {
	viper.SetDefault("net_param", "mainnet")
}

func GetNetParams() *chaincfg.Params {
	switch viper.GetString("net_param") {
	case "mainnet":
		return &chaincfg.MainNetParams

	case "testnet":
		return &chaincfg.TestNet3Params

	case "regtest":
		return &chaincfg.RegressionNetParams

	default:
		return &chaincfg.MainNetParams
	}
}

func HexToHash(sHexTxHash string) *chainhash.Hash {
	if len(sHexTxHash) > 0 && (sHexTxHash[0:2] == "0x" || sHexTxHash[0:2] == "0X") {
		sHexTxHash = sHexTxHash[2:]
	}

	hash, err := chainhash.NewHashFromStr(sHexTxHash)
	if err != nil {
		bcLogger.Warn("decode hex to hash error", "error", err, "hash", sHexTxHash)
		hash = new(chainhash.Hash)
	}

	return hash
}

//ExtractPkScriptAddr 从输出脚本中提取地址
func ExtractPkScriptAddr(PkScript []byte, coinType uint8, netParam *chaincfg.Params) ([]string, error) {
	var addrs []string

	_, addresses, _, err := txscript.ExtractPkScriptAddrs(PkScript, netParam)

	if err != nil {
		bcLogger.Warn("ExtractPkScriptAddrs error", "error", err)
		return addrs, err
	}

	for _, addr := range addresses {
		if coinType == defines.CHAIN_CODE_BTC {
			addrs = append(addrs, addr.EncodeAddress())

		} else {
			switch reflect.TypeOf(addr).String() {
			case "*btcutil.AddressPubKey":
				addr, err := bchutil.NewCashAddressPubKeyHash(btcutil.Hash160(addr.ScriptAddress()), netParam)
				if err != nil {
					bcLogger.Warn("NewCashAddressPubKeyHash error", "error", err)
					return addrs, err

				} else {
					addrs = append(addrs, addr.String())
				}
			case "*btcutil.AddressPubKeyHash":
				addr, err := bchutil.NewCashAddressPubKeyHash(addr.ScriptAddress(), netParam)
				if err != nil {
					bcLogger.Warn("NewCashAddressPubKeyHash error", "error", err)
					return addrs, err

				} else {
					addrs = append(addrs, addr.String())
				}
			case "*btcutil.AddressScriptHash":
				addr, err := bchutil.NewCashAddressScriptHashFromHash(addr.ScriptAddress(), netParam)
				if err != nil {
					bcLogger.Warn("NewCashAddressScriptHashFromHash error", "error", err)
					return addrs, err

				} else {
					addrs = append(addrs, addr.String())
				}
			}
		}
	}
	return addrs, nil
}

// BCH待签hash计算方式
func CalcBip143SignatureHash(redeemScript []byte, hashType txscript.SigHashType, tx *wire.MsgTx, vinIx int, amt int64) ([]byte, error) {

	if vinIx > len(tx.TxIn)-1 {
		bcLogger.Error("bch sign vin out of range", "vinIx", vinIx, "vinLen", len(tx.TxIn))
		return nil, ErrSignVin
	}

	sigHashes := txscript.NewTxSigHashes(tx)

	var sigHash bytes.Buffer

	binary.Write(&sigHash, binary.LittleEndian, tx.Version)

	var zeroHash chainhash.Hash

	if hashType&txscript.SigHashAnyOneCanPay == 0 {

		sigHash.Write(sigHashes.HashPrevOuts[:])

	} else {
		sigHash.Write(zeroHash[:])
	}

	if hashType&txscript.SigHashAnyOneCanPay == 0 &&
		hashType&sigHashMask != txscript.SigHashSingle &&
		hashType&sigHashMask != txscript.SigHashNone {

		sigHash.Write(sigHashes.HashSequence[:])

	} else {
		sigHash.Write(zeroHash[:])
	}

	vin := tx.TxIn[vinIx]

	sigHash.Write(vin.PreviousOutPoint.Hash[:])

	binary.Write(&sigHash, binary.LittleEndian, vin.PreviousOutPoint.Index)

	wire.WriteVarBytes(&sigHash, 0, redeemScript)

	binary.Write(&sigHash, binary.LittleEndian, amt)

	binary.Write(&sigHash, binary.LittleEndian, vin.Sequence)

	if hashType&sigHashMask != txscript.SigHashSingle && hashType&sigHashMask != txscript.SigHashNone {
		sigHash.Write(sigHashes.HashOutputs[:])

	} else if hashType&sigHashMask == txscript.SigHashSingle && vinIx < len(tx.TxOut) {
		var b bytes.Buffer
		wire.WriteTxOut(&b, 0, 0, tx.TxOut[vinIx])

		sigHash.Write(chainhash.DoubleHashB(b.Bytes()))

	} else {
		sigHash.Write(zeroHash[:])
	}

	binary.Write(&sigHash, binary.LittleEndian, tx.LockTime)

	binary.Write(&sigHash, binary.LittleEndian, hashType|SigHashForkID)

	return chainhash.DoubleHashB(sigHash.Bytes()), nil
}

func CalcSignatureHash(tx *wire.MsgTx, vinIx int, redeemScript []byte, hashType txscript.SigHashType, value int64, coinType uint8) ([]byte, error) {
	switch coinType {
	case defines.CHAIN_CODE_BTC:
		hash, err := txscript.CalcSignatureHash(redeemScript, hashType, tx, vinIx)
		if err != nil {
			bcLogger.Error("Calc btc signHash error", "error", err)
			return nil, err
		}
		return hash, nil

	case defines.CHAIN_CODE_BCH:
		hash, err := CalcBip143SignatureHash(redeemScript, hashType, tx, vinIx, value)
		if err != nil {
			return nil, err
		}
		return hash, nil

	default:
		return nil, ErrChainCode
	}

}

//GetMultiSigAddress 通过公钥列表生成多签地址
func GetMultiSigAddress(hexPubkeyList []string, nRequired int, coinType uint8, netParam *chaincfg.Params) (string, []byte, error) {
	var pubkey []*btcutil.AddressPubKey

	for _, sHexPk := range hexPubkeyList {
		bPk, err := hex.DecodeString(sHexPk)
		if err != nil {
			bcLogger.Error("hex decode pubkey error", "error", err, "sHexPk", sHexPk)
			return "", nil, err
		}

		singleAddr, err := btcutil.NewAddressPubKey(bPk, netParam)
		if err != nil {
			bcLogger.Error("make pubKeyAddr error", "error", err)
			return "", nil, err
		}
		pubkey = append(pubkey, singleAddr)
	}

	script, err := txscript.MultiSigScript(pubkey, nRequired)
	if err != nil {
		bcLogger.Error("make MultiSigScript error", "error", err)
		return "", nil, err
	}

	switch coinType {
	case defines.CHAIN_CODE_BTC:
		multiSigAddr, err := btcutil.NewAddressScriptHash(script, netParam)
		if err != nil {
			bcLogger.Error("make btc multiSigAddr error", "error", err)
			return "", nil, err
		}

		return multiSigAddr.EncodeAddress(), script, err

	case defines.CHAIN_CODE_BCH:
		multiSigAddr, err := bchutil.NewCashAddressScriptHashFromHash(btcutil.Hash160(script), netParam)
		if err != nil {
			bcLogger.Error("make bch multiSigAddr error", "error", err)
			return "", nil, err
		}
		return multiSigAddr.EncodeAddress(), script, err

	default:
		return "", nil, ErrChainCode
	}

}

// DecodeAddress 从地址字符串中decode Address
func DecodeAddress(addr string, coinType uint8, netParam *chaincfg.Params) (btcutil.Address, error) {
	switch coinType {
	case defines.CHAIN_CODE_BTC:
		return btcutil.DecodeAddress(addr, netParam)

	case defines.CHAIN_CODE_BCH:
		return bchutil.DecodeAddress(addr, netParam)

	default:
		return nil, ErrChainCode
	}
}
