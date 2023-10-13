package main

import (
	"crypto/ecdsa"
	"encoding/hex"
	"fmt"
	"log"
	"os"
	"strings"

	"github.com/ethereum/go-ethereum/common/hexutil"
	"github.com/ethereum/go-ethereum/crypto"
)

func privateKeyFromHex(hexKey string) (*ecdsa.PrivateKey, error) {
	// Decode the hex-encoded private key
	keyBytes, err := hex.DecodeString(hexKey)
	if err != nil {
		return nil, err
	}

	// Convert the bytes to an ECDSA private key
	privateKey, err := crypto.ToECDSA(keyBytes)
	if err != nil {
		return nil, err
	}

	return privateKey, nil
}

func main() {
	argsWithoutProg := os.Args[1:]

	fmt.Println(argsWithoutProg)
	if len(argsWithoutProg) < 1 {
		fmt.Println("Hex encoded private key not provided")
		os.Exit(1)
	}

	if strings.Index(argsWithoutProg[0], "0x") == 0 {
		argsWithoutProg[0] = argsWithoutProg[0][2:]
	}

	privateKey, err := privateKeyFromHex(argsWithoutProg[0])
	if err != nil {
		fmt.Println("Error converting hex to private key", err)
		os.Exit(1)
	}

	publicKey := privateKey.Public()
	publicKeyECDSA, ok := publicKey.(*ecdsa.PublicKey)
	if !ok {
		log.Fatal("cannot assert type: publicKey is not of type *ecdsa.PublicKey")
	}

	publicKeyBytes := crypto.FromECDSAPub(publicKeyECDSA)
	log.Println("Public Key:", hexutil.Encode(publicKeyBytes))

	address := crypto.PubkeyToAddress(*publicKeyECDSA).Hex()
	log.Println("Address:", address)
}
