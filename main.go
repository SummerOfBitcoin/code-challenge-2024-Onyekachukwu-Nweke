package main

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	// "crypto/rand"
	//"crypto/sha256"
	"encoding/hex"
	"fmt"
	"encoding/json"
	"os"
	"path/filepath"
	// "errors"
	// "fmt"
	"log"
	"math/big"
	"scripts"
)

type Transaction struct {
	Version  int    `json:"version"`
	Locktime int    `json:"locktime"`
	Vin      []Vin  `json:"vin"`
	Vout     []Vout `json:"vout"`
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

type Block struct {
	Transactions []Transaction
	PreviousHash string
	Nonce        int
}

func main() {
	transactions, err := parseTransactions("./mempool/")
	if err != nil {
		log.Fatalf("Error parsing transactions: %v", err)
	}

	validTransactions := validateTransactions(transactions)

	// Access the transactions slice here
	fmt.Println("Number of transactions:", len(validTransactions))

	for i := 0; i < 10 && i < len(validTransactions); i++ {
		fmt.Println(validTransactions[i].Version)
	}
}

func parseTransactions(dir string) ([]Transaction, error) {
	var transactions []Transaction

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

			transactions = append(transactions, tx)
		}

		return nil
	})

	if err != nil {
		return nil, err
	}

	return transactions, nil
}

func validateTransactions(transactions []Transaction) []Transaction {
	var validTransactions []Transaction

	for _, tx := range transactions {
		if (tx.Version == 1) {
			if validate_v1_tx(tx) {
				validTransactions = append(validTransactions, tx)
			}
		} else if (tx.Version == 2) {
			fmt.Println("Cannot ascertain transaction version")
		} else {
			fmt.Println("Cannot ascertain transaction version")
		}
	}

	return validTransactions

	// Decode transaction hex to bytes
    // txBytes, err := hex.DecodeString(txHex)
    // if err != nil {
    //     return err
    // }
}

func validate_v1_tx(tx Transaction) bool {
	if tx.Vin[0].PrevOut.ScriptPubKeyType == "p2pkh" {
		// Decode the scriptPubKey
        scriptPubKeyBytes, _ := hex.DecodeString(tx.Vin[0].PrevOut.ScriptPubKey)

        // Decode the scriptSig
        scriptSigBytes, _ := hex.DecodeString(tx.Vin[0].ScriptSig)

        // Extract public key from scriptSig
        // Here, we're assuming a P2PKH scriptSig which consists of signature and public key
        signature := scriptSigBytes[:len(scriptSigBytes)-1] // Remove the last byte (sigHashType)
        publicKey := scriptSigBytes[len(scriptSigBytes)-33:] // Last 33 bytes should be public key

        // Verify signature
        if !verifySignature(scriptPubKeyBytes, signature, publicKey) {
            fmt.Println("Signature verification failed")
            return false
        }
	}

	return true
}
