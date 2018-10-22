package btclient

import (
	"encoding/hex"

	"github.com/antimoth/btrpc/btcjson"
	"github.com/antimoth/btrpc/rpcclient"
	"github.com/antimoth/logger"
	"github.com/btcsuite/btcd/chaincfg/chainhash"
	"github.com/btcsuite/btcd/wire"
	"github.com/btcsuite/btcutil"
	"github.com/shopspring/decimal"
	"github.com/spf13/viper"
)

var (
	bcLogger = logger.NewLogger("DEBUG", "btclient")
)

//BitCoinClient BTC/BCH RPC操作类
type BitCoinClient struct {
	c *rpcclient.Client
}

//NewBitCoinClient 创建一个bitcoin操作客户端
func NewBitCoinClient(rpcUrl string, rpcUser string, rpcPwd string) (*BitCoinClient, error) {
	bcLogger = logger.NewLogger(viper.GetString("loglevel"), "btclient")

	connCfg := &rpcclient.ConnConfig{
		HTTPPostMode: true, // Bitcoin core only supports HTTP POST mode
		DisableTLS:   true, // Bitcoin core does not provide TLS by default
		Host:         rpcUrl,
		User:         rpcUser,
		Pass:         rpcPwd,
	}

	client, err := rpcclient.New(connCfg, nil)
	if err != nil {
		bcLogger.Error("new rpc client error", "error", err.Error())
		return nil, err
	}

	return &BitCoinClient{c: client}, nil
}

//GetBlockCount 获取当前区块链高度
func (b *BitCoinClient) GetBlockCount() (int64, error) {
	return b.c.GetBlockCount()
}

func (b *BitCoinClient) PreparedTxInfo(txHash *chainhash.Hash) (*PreparedTx, error) {
	txVerbose, err := b.GetRawTransactionVerbose(txHash)
	if err != nil {
		return nil, err
	}
	serializedTx, err := hex.DecodeString(txVerbose.Hex)
	if err != nil {
		bcLogger.Error("decode tranx hex string errror", "hash", txHash.String())
		return nil, err
	}

	// Deserialize the transaction and return it.
	rawTx, err := btcutil.NewTxFromBytes(serializedTx)
	if err != nil {
		bcLogger.Error("deserialize tranx error", "hash", txHash.String())
		return nil, err
	}

	preparedTx := PreparedTx{
		Tx:        rawTx.MsgTx(),
		BlockHash: txVerbose.BlockHash,
	}

	if txVerbose.BlockHash != EMPTY_STR {
		blockInfo, err := b.GetBlockVerboseFromStr(txVerbose.BlockHash)
		if err != nil {
			return nil, err
		}

		sTxHash := txHash.String()
		for ix, hash := range blockInfo.Tx {
			if hash == sTxHash {
				preparedTx.TxIx = ix
				break
			}
		}
		preparedTx.BlockHeight = blockInfo.Height
		preparedTx.Confirmations = blockInfo.Confirmations

	} else {
		preparedTx.TxIx = UNKNOWN_TRANX_INDEX
		preparedTx.BlockHeight = UNKNOWN_BLOCK_HEIGHT
		preparedTx.Confirmations = UNKNOWN_CONFIRMATIONS
	}

	return &preparedTx, nil
}

func (b *BitCoinClient) PreparedTxInfoFromStr(sTxHash string) (*PreparedTx, error) {
	return b.PreparedTxInfo(HexToHash(sTxHash))
}

func (b *BitCoinClient) GetRawTransaction(txHash *chainhash.Hash) (*btcutil.Tx, error) {
	txRaw, err := b.c.GetRawTransaction(txHash)
	if err != nil {
		bcLogger.Error("GetRawTransaction error", "hash", txHash.String(), "e", err)
		return nil, err
	}
	return txRaw, nil

}

func (b *BitCoinClient) GetRawTransactionFromStr(sTxHash string) (*btcutil.Tx, error) {
	return b.GetRawTransaction(HexToHash(sTxHash))
}

//GetRawTransactionVerbose 根据txhash从区块链上查询交易数据（包含区块信息）
func (b *BitCoinClient) GetRawTransactionVerbose(txHash *chainhash.Hash) (*btcjson.TxRawResult, error) {
	txRaw, err := b.c.GetRawTransactionVerbose(txHash)
	if err != nil {
		bcLogger.Error("GetRawTransactionVerbose error", "hash", txHash.String(), "e", err)
		return nil, err
	}
	return txRaw, nil
}

func (b *BitCoinClient) GetRawTransactionVerboseFromStr(sTxHash string) (*btcjson.TxRawResult, error) {
	return b.GetRawTransactionVerbose(HexToHash(sTxHash))
}

func (b *BitCoinClient) GetBlock(blockHash *chainhash.Hash) (*wire.MsgBlock, error) {
	blockInfo, err := b.c.GetBlock(blockHash)
	if err != nil {
		bcLogger.Error("GetBlockVerbose error", "hash", blockHash.String(), "e", err.Error())
		return nil, err
	}
	return blockInfo, nil
}

func (b *BitCoinClient) GetBlockFromStr(sBlockHash string) (*wire.MsgBlock, error) {
	return b.GetBlock(HexToHash(sBlockHash))
}

func (b *BitCoinClient) GetBlockFromHeight(height int64) (*wire.MsgBlock, error) {
	return b.GetBlock(b.GetBlockHashFromHeight(height))
}

func (b *BitCoinClient) GetBlockVerbose(blockHash *chainhash.Hash) (*btcjson.GetBlockVerboseResult, error) {
	blockVerbose, err := b.c.GetBlockVerbose(blockHash)
	if err != nil {
		bcLogger.Error("GetBlockVerbose error", "hash", blockHash.String(), "e", err.Error())
		return nil, err
	}
	return blockVerbose, nil
}

func (b *BitCoinClient) GetBlockVerboseFromStr(sBlockHash string) (*btcjson.GetBlockVerboseResult, error) {
	return b.GetBlockVerbose(HexToHash(sBlockHash))
}

func (b *BitCoinClient) GetBlockHashFromHeight(height int64) *chainhash.Hash {
	blockHash, err := b.c.GetBlockHash(height)
	if err != nil {
		bcLogger.Error("GetBlockHash error", "e", err.Error(), "height", height)
		blockHash = new(chainhash.Hash)
	}
	return blockHash
}

func (b *BitCoinClient) GetBlockVerboseFromHeight(height int64) (*btcjson.GetBlockVerboseResult, error) {
	return b.GetBlockVerbose(b.GetBlockHashFromHeight(height))
}

func (b *BitCoinClient) GetBlockHeaderVerbose(blockHash *chainhash.Hash) (*btcjson.GetBlockHeaderVerboseResult, error) {
	blockHeaderVerbose, err := b.c.GetBlockHeaderVerbose(blockHash)
	if err != nil {
		bcLogger.Error("GetBlockHeaderVerbose error", "e", err)
		return nil, err
	}
	return blockHeaderVerbose, nil
}

func (b *BitCoinClient) GetBlockHeaderVerboseFromStr(sBlockHash string) (*btcjson.GetBlockHeaderVerboseResult, error) {
	return b.GetBlockHeaderVerbose(HexToHash(sBlockHash))
}

func (b *BitCoinClient) GetBlockHeightFromHash(blockHash *chainhash.Hash) (int64, error) {
	blockHeader, err := b.GetBlockHeaderVerbose(blockHash)
	if err != nil {
		return 0, err
	}
	return blockHeader.Height, nil
}

func (b *BitCoinClient) GetBlockHeightFromStr(sBlockHash string) (int64, error) {
	return b.GetBlockHeightFromHash(HexToHash(sBlockHash))
}

//SendRawTransaction 发送交易数据到全节点
func (b *BitCoinClient) SendRawTransaction(tx *wire.MsgTx) (*chainhash.Hash, error) {
	return b.c.SendRawTransaction(tx, true)
}

//EstimateFee 评估交易矿工费
func (b *BitCoinClient) EstimateFee(numBlocks int64) (int64, error) {
	fee, err := b.c.EstimateFee(numBlocks)
	if err != nil {
		return 0, err
	}

	feePerKb := decimal.NewFromFloat(fee).Mul(decimal.NewFromFloat(1E8)).IntPart()
	return feePerKb, err

}

func (b *BitCoinClient) ImportAddressDefault(address string) error {
	return b.ImportAddress(address, DEFAULT_WALLET_ACCOUNT, false)
}

func (b *BitCoinClient) ImportAddress(address string, account string, rescan bool) error {
	return b.c.ImportAddressRescan(address, account, rescan)
}

func (b *BitCoinClient) ListUnspentDefault(address []btcutil.Address) ([]btcjson.ListUnspentResult, error) {
	return b.c.ListUnspentMinMaxAddresses(UNSPENT_MINIMUM_CONFIRMATIONS, UNSPENT_MAXIMUM_CONFIRMATIONS, address)
}

func (b *BitCoinClient) ListUnspentMinConfirm(minConf int, address []btcutil.Address) ([]btcjson.ListUnspentResult, error) {
	return b.c.ListUnspentMinMaxAddresses(minConf, UNSPENT_MAXIMUM_CONFIRMATIONS, address)
}
