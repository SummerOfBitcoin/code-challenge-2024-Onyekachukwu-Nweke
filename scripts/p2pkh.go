package scripts

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	// "crypto/rand"
	//"crypto/sha256"
	"encoding/hex"
	"fmt"
	"math/big"
)

func P2PKH_validate(tx []*transaction) bool {
	if len(tx.Vin > 0) {
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

	} else {
		return false
	}
}


func verifySignature(scriptPubKey []byte, signature []byte, publicKey []byte) bool {
// Parse the public key
x, y := elliptic.Unmarshal(elliptic.P256(), publicKey)

// Construct the ecdsa.PublicKey
pubKey := ecdsa.PublicKey{
	Curve: elliptic.P256(),
	X:     x,
	Y:     y,
}

// Parse the signature into `r` and `s` components
r := new(big.Int).SetBytes(signature[:32])
s := new(big.Int).SetBytes(signature[32:64])

// Verify the signature
return ecdsa.Verify(&pubKey, scriptPubKey, r, s)
}
