package main

import (
	"crypto/rand"
	"encoding/hex"
	"flag"
	"fmt"
	"math/big"
	"os"
	"os/exec"

	bls "github.com/consensys/gnark-crypto/ecc/bls12-381"
)

func main() {
	userID := flag.String("user", "alice", "User identifier in the chain")
	channel := flag.String("channel", "channel2", "Fabric channel name")
	chaincode := flag.String("cc", "keygen", "Chaincode name")
	autoRegister := flag.Bool("register", true, "Automatic registration with peer invoke")
	flag.Parse()

	// BLS12-381 scalar field order (Fr)
	order, ok := new(big.Int).SetString(
		"73eda753299d7d483339d80809a1d80553bda402fffe5bfeffffffff00000001", 16)
	if !ok {
		fmt.Fprintln(os.Stderr, "Internal error: failed to set curve order")
		os.Exit(1)
	}

	// Cryptographically secure random private key generation
	// This runs off-chain, using crypto/rand — secure
	sk, err := rand.Int(rand.Reader, order)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Private key generation error: %v\n", err)
		os.Exit(1)
	}
	if sk.Sign() == 0 {
		// Extremely unlikely, but let's guard against it
		fmt.Fprintln(os.Stderr, "Generated scalar is zero, please run again.")
		os.Exit(1)
	}

	// Public key computation: pk = sk * G1
	var pk bls.G1Affine
	pk.ScalarMultiplicationBase(sk)

	// Validity check
	if !pk.IsOnCurve() || pk.IsInfinity() {
		fmt.Fprintln(os.Stderr, "Invalid keypair generated, please run again.")
		os.Exit(1)
	}

	// Serialization
	skBytes := make([]byte, 32)
	skRaw := sk.Bytes()
	copy(skBytes[32-len(skRaw):], skRaw)
	pkBytesArr := pk.Bytes() // compressed G1Affine, 48 bytes

	fmt.Println("╔══════════════════════════════════════════════════════════════╗")
	fmt.Println("║          BLS12-381 Keypair generate (off-chain)              ║")
	fmt.Println("╚══════════════════════════════════════════════════════════════╝")
	fmt.Println()
	fmt.Println("PRIVATE KEY:")
	fmt.Printf("   %s\n", hex.EncodeToString(skBytes))
	fmt.Println()
	pubHex := hex.EncodeToString(pkBytesArr[:])
	fmt.Println("PUBLIC KEY")
	fmt.Printf("   %s\n", pubHex)
	fmt.Println()
	fmt.Println("Command to register the key:")
	fmt.Printf("peer chaincode invoke -o localhost:7050 --ordererTLSHostnameOverride orderer.example.com --tls --cafile \"$ORDERER_CA\" -C %s -n %s --peerAddresses localhost:7051 --tlsRootCertFiles \"$PWD/organizations/peerOrganizations/org1.example.com/peers/peer0.org1.example.com/tls/ca.crt\" --peerAddresses localhost:9051 --tlsRootCertFiles \"$PWD/organizations/peerOrganizations/org2.example.com/peers/peer0.org2.example.com/tls/ca.crt\" -c '{\"function\":\"RegisterPublicKey\",\"Args\":[\"%s\",\"%s\"]}'\n", *channel, *chaincode, *userID, pubHex)

	if !*autoRegister {
		return
	}

	if os.Getenv("ORDERER_CA") == "" {
		fmt.Fprintln(os.Stderr, "ORDERER_CA is not set. Export the Fabric environment variables.")
		os.Exit(1)
	}

	args := []string{
		"chaincode", "invoke",
		"-o", "localhost:7050",
		"--ordererTLSHostnameOverride", "orderer.example.com",
		"--tls",
		"--cafile", os.Getenv("ORDERER_CA"),
		"-C", *channel,
		"-n", *chaincode,
		"--peerAddresses", "localhost:7051",
		"--tlsRootCertFiles", os.Getenv("PWD") + "/organizations/peerOrganizations/org1.example.com/peers/peer0.org1.example.com/tls/ca.crt",
		"--peerAddresses", "localhost:9051",
		"--tlsRootCertFiles", os.Getenv("PWD") + "/organizations/peerOrganizations/org2.example.com/peers/peer0.org2.example.com/tls/ca.crt",
		"-c", fmt.Sprintf("{\"function\":\"RegisterPublicKey\",\"Args\":[\"%s\",\"%s\"]}", *userID, pubHex),
	}

	cmd := exec.Command("peer", args...)
	cmd.Stdout = os.Stdout
	cmd.Stderr = os.Stderr

	fmt.Println()
	fmt.Println("Automatic registration starting...")
	if err := cmd.Run(); err != nil {
		fmt.Fprintf(os.Stderr, "Registration failed: %v\n", err)
		os.Exit(1)
	}
	fmt.Println("Registration successful.")
}
