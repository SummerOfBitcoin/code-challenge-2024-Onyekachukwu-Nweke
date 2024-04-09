package main

import (
	// "fmt"
	"encoding/json"
	"errors"
	"log"
	"os"
	"path/filepath"
	"sort"
	"strconv"
	"crypto/sha256"
	"math"
	
	"github.com/ethereum/go-ethereum/crypto/secp256k1"
)

/***
    Data Structures
***/

type Transaction struct {
	Version  int    `json:"version"`
	Locktime int    `json:"locktime"`
	Vin      []Vin  `json:"vin"`
	Vout     []Vout `json:"vout"`
	Txid     string    `json:"-"`
	Fee      int64     `json:"-"`
	Priority int64     `json:"-"`
	Valid    bool      `json:"-"`
}

type Vin struct {
	TxID          string `json:"txid"`
	Vout          int    `json:"vout"`
	PrevOut       Output `json:"prevout"`
	ScriptSig     string `json:"scriptsig"`
	ScriptSigAsm  string `json:"scriptsig_asm"`
	Witness       []string `json:"witness"`
	IsCoinbase    bool   `json:"is_coinbase"`
	Sequence      int    `json:"sequence"`
	Verified bool `json:"-"`
}

type Vout struct {
	ScriptPubKey     string `json:"scriptpubkey"`
	ScriptPubKeyAsm  string `json:"scriptpubkey_asm"`
	ScriptPubKeyType string `json:"scriptpubkey_type"`
	ScriptPubKeyAddr string `json:"scriptpubkey_address"`
	Value            int    `json:"value"`
}

type Output struct {
	ScriptPubKey     string `json:"scriptpubkey"`
	ScriptPubKeyAsm  string `json:"scriptpubkey_asm"`
	ScriptPubKeyType string `json:"scriptpubkey_type"`
	ScriptPubKeyAddr string `json:"scriptpubkey_address"`
	Value            int    `json:"value"`
}

// BlockHeader represents the header of a block
type BlockHeader struct {
	Version       int    `json:"version"`
	PrevBlockHash string `json:"prevBlockHash"`
	MerkleRoot    string `json:"merkleRoot"`
	Timestamp     int64  `json:"timestamp"`
	Bits          int    `json:"bits"`
	Nonce         int    `json:"nonce"`
}

// Block represents a complete block
type Block struct {
	Header       BlockHeader  `json:"header"`
	Transactions []Transaction `json:"transactions"`
}

/***
    UTILITY FUNCTIONS NEEDED
**/

// ParseTransactions parses all transactions in a directory
func ParseTransactions(dir string) ([]*Transaction, error) {
	var transactions []*Transaction

	err := filepath.Walk(dir, func(path string, info os.FileInfo, err error) error {
		if err != nil {
			return err
		}

		if !info.IsDir() {
			data, err := os.ReadFile(path)
			if err != nil {
				return err
			}

			var tx Transaction
			err = json.Unmarshal(data, &tx)
			if err != nil {
				return err
			}

			tx.Txid = info.Name()
			if ValidateTransaction(&tx) {
				tx.Valid = true
				CalculateFeeAndPriority(&tx)
				transactions = append(transactions, &tx)
			}
		}

		return nil
	})

	if err != nil {
		return nil, err
	}

	return transactions, nil
}

// CalculateFeeAndPriority calculates the fee and priority for a transaction
func CalculateFeeAndPriority(tx *Transaction) {
	var inputValue int64
	for _, in := range tx.Vin {
		inputValue += int64(in.PrevOut.Value)
	}
	var outputValue int64
	for _, out := range tx.Vout {
		outputValue += int64(out.Value)
	}
	tx.Fee = inputValue - outputValue
	tx.Priority = tx.Fee / int64(len(tx.Vin))
}

// SortTransactionsByFeeAndPriority sorts a list of transactions by fee and priority
func SortTransactionsByFeeAndPriority(transactions []*Transaction) {
	sort.Slice(transactions, func(i, j int) bool {
		if transactions[i].Fee != transactions[j].Fee {
			return transactions[i].Fee > transactions[j].Fee
		}
		return transactions[i].Priority > transactions[j].Priority
	})
}

func ValidateTransaction(tx *Transaction) bool {
    // Initial checks
    if tx.Version < 1 || tx.Version > 2 {
        return false // Invalid version
    }

    // Check for duplicate inputs
    seenInputs := make(map[string]bool)
    for _, in := range tx.Vin {
        if seenInputs[in.TxID+":"+strconv.Itoa(in.Vout)] {
            return false // Duplicate input
        }
        seenInputs[in.TxID+":"+strconv.Itoa(in.Vout)] = true
    }

    // Check input values (assume unspent outputs for now)
    var totalInputValue int64
    for _, in := range tx.Vin {
        totalInputValue += int64(in.PrevOut.Value)
    }

    // Check output values
    var totalOutputValue int64
    for _, out := range tx.Vout {
        if out.Value < 0 {
            return false // Negative output value
        }
        totalOutputValue += int64(out.Value)
    }

    if totalInputValue < totalOutputValue {
        return false // Insufficient input value
    }

    // Signature Validation
    for i := range tx.Vin {
        if !validateInputSignature(tx, i) {
            return false // Invalid signature
        }
    }

    // Script Execution
    for i := range tx.Vin {
        if !validateInputScript(tx, i) {
            return false // Invalid script
        }
    }

    // Locktime Check
    if tx.Locktime > int(math.MaxInt32) {
        return false // Locktime too high
    }

    // Signature Operation Limit Check
    // if countSignatureOperations(tx) > MAX_SIGNATURE_OPERATIONS {
    //     return false // Too many signature operations
    // }

    // Assuming all checks passed, mark transaction as valid
    tx.Valid = true
    return true
}

func validateInputSignature(tx *Transaction, inputIndex int) bool {
    // prevOutScript := tx.Vin[inputIndex].PrevOut.ScriptPubKey
    signature := tx.Vin[inputIndex].ScriptSig

    publicKey, err := extractPublicKey(tx, inputIndex)
    if err != nil {
        return false // Error extracting public key
    }

    txHash := sha256.Sum256([]byte(tx.Txid))
    signatureBytes := []byte(signature)
    publicKeyBytes := publicKey

    // Use secp256k1 library to verify the signature
    return secp256k1.VerifySignature(publicKeyBytes, txHash[:], signatureBytes)
}

func validateInputScript(tx *Transaction, inputIndex int) bool {
    prevOutScript := tx.Vin[inputIndex].PrevOut.ScriptPubKey
    scriptSig := tx.Vin[inputIndex].ScriptSig

    // Implement script execution logic here
    // You can use a script interpreter library like btcsuite/btcd/wire/script
    // or implement the basic script execution logic manually

    return true // Placeholder, replace with actual script execution
}

func extractPublicKey(tx *Transaction, inputIndex int) ([]byte, error) {
    scriptSig := tx.Vin[inputIndex].ScriptSig

    // Check if scriptSig contains a public key directly (e.g., P2PK script)
    if len(scriptSig) > 1 && scriptSig[len(scriptSig)-1] > OP_PUSHDATA[0] {
        return scriptSig[len(scriptSig)-1:], nil
    }

    // Check if transaction uses witness data (SegWit)
    if len(tx.Vin[inputIndex].Witness) > 0 {
        // Extract the public key from the first element of the witness (assuming P2WPKH)
        return tx.Vin[inputIndex].Witness[0], nil
    }

    // Script doesn't contain a public key or witness data
    return nil, errors.New("public key not found")
}

/**
    MAIN FUNCTION
**/

func main() {
    transactions, err := ParseTransactions("./mempool/")
    if err != nil {
        log.Fatalf("Error parsing transactions: %v", err)
    }

	SortTransactionsByFeeAndPriority(transactions)
}


