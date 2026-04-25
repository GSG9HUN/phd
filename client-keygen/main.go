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

// blsDST is the domain separation tag used for hashing messages to G2.
// Must be identical here and in the chaincode's VerifySignature function.
const blsDST = "BLS_SIG_BLS12381G2_XMD:SHA-256_SSWU_RO_NUL_"

func main() {
	// Keygen flags
	userID := flag.String("user", "alice", "User identifier in the chain")
	channel := flag.String("channel", "channel2", "Fabric channel name")
	chaincode := flag.String("cc", "keygen", "Chaincode name")
	autoRegister := flag.Bool("register", true, "Automatic registration with peer invoke")
	keyFile := flag.String("keyfile", "", "File to save (keygen) or load (sign) the private key")

	// Sign flags
	doSign := flag.Bool("sign", false, "Sign a message instead of generating a key (requires -keyfile or -sk, and -msg)")
	skHex := flag.String("sk", "", "Private key hex for signing (alternative to -keyfile)")
	message := flag.String("msg", "", "Message to sign (required for -sign)")
	raw := flag.Bool("raw", false, "With -sign, output only signature hex")

	// Derive flags
	doDerive := flag.Bool("derive", false, "Derive private key: sk' = (sk * factor) mod Fr")
	factorHex := flag.String("factor", "", "Hex scalar multiplier for -derive")

	flag.Parse()

	if *doDerive {
		cmdDerive(*skHex, *keyFile, *factorHex)
		return
	}

	if *doSign {
		sk := *skHex
		if sk == "" && *keyFile != "" {
			raw, err := os.ReadFile(*keyFile)
			if err != nil {
				fmt.Fprintf(os.Stderr, "Cannot read keyfile %s: %v\n", *keyFile, err)
				os.Exit(1)
			}
			sk = string(raw)
			// trim whitespace/newlines
			for len(sk) > 0 && (sk[len(sk)-1] == '\n' || sk[len(sk)-1] == '\r' || sk[len(sk)-1] == ' ') {
				sk = sk[:len(sk)-1]
			}
		}
		cmdSign(sk, *message, *raw)
		return
	}

	cmdKeygen(*userID, *channel, *chaincode, *autoRegister, *keyFile)
}

// cmdSign computes a BLS12-381 signature over the given message using the private key.
// Signature scheme: σ = sk · HashToG2(message)  (min-pubkey variant, signature in G2)
// Verification on-chain: e(G1_gen, σ) == e(pk, HashToG2(message))
func cmdSign(skHex, message string, rawOutput bool) {
	if skHex == "" || message == "" {
		fmt.Fprintln(os.Stderr, "Error: both -sk and -msg are required for -sign")
		os.Exit(1)
	}

	skBytes, err := hex.DecodeString(skHex)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Private key hex decode error: %v\n", err)
		os.Exit(1)
	}

	sk := new(big.Int).SetBytes(skBytes)
	if sk.Sign() == 0 {
		fmt.Fprintln(os.Stderr, "Error: private key scalar is zero")
		os.Exit(1)
	}

	// Hash message to G2 with the shared DST.
	h, err := bls.HashToG2([]byte(message), []byte(blsDST))
	if err != nil {
		fmt.Fprintf(os.Stderr, "Hash-to-G2 error: %v\n", err)
		os.Exit(1)
	}

	// σ = sk · H(message)
	var sig bls.G2Affine
	sig.ScalarMultiplication(&h, sk)

	if !sig.IsOnCurve() || sig.IsInfinity() {
		fmt.Fprintln(os.Stderr, "Error: produced an invalid signature point")
		os.Exit(1)
	}

	sigBytes := sig.Bytes()
	sigHex := hex.EncodeToString(sigBytes[:])
	if rawOutput {
		fmt.Println(sigHex)
		return
	}

	fmt.Println("╔══════════════════════════════════════════════════════════════╗")
	fmt.Println("║          BLS12-381 Signature (off-chain)                     ║")
	fmt.Println("╚══════════════════════════════════════════════════════════════╝")
	fmt.Println()
	fmt.Printf("MESSAGE:    %s\n", message)
	fmt.Println()
	fmt.Println("SIGNATURE (96-byte G2 point, hex):")
	fmt.Printf("   %s\n", sigHex)
	fmt.Println()
	fmt.Println("Verify on-chain with:")
	fmt.Printf(`peer chaincode query ... -c '{"function":"VerifySignature","Args":["<userID>","%s","%s"]}'`+"\n", message, sigHex)
}

// cmdDerive computes a derived private key: sk' = (sk * factor) mod Fr.
func cmdDerive(skHex, keyFile, factorHex string) {
	if skHex == "" && keyFile != "" {
		raw, err := os.ReadFile(keyFile)
		if err != nil {
			fmt.Fprintf(os.Stderr, "Cannot read keyfile %s: %v\n", keyFile, err)
			os.Exit(1)
		}
		skHex = string(raw)
		for len(skHex) > 0 && (skHex[len(skHex)-1] == '\n' || skHex[len(skHex)-1] == '\r' || skHex[len(skHex)-1] == ' ') {
			skHex = skHex[:len(skHex)-1]
		}
	}

	if skHex == "" || factorHex == "" {
		fmt.Fprintln(os.Stderr, "Error: -derive requires -sk (or -keyfile) and -factor")
		os.Exit(1)
	}

	skBytes, err := hex.DecodeString(skHex)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Private key hex decode error: %v\n", err)
		os.Exit(1)
	}
	factorBytes, err := hex.DecodeString(factorHex)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Factor hex decode error: %v\n", err)
		os.Exit(1)
	}

	sk := new(big.Int).SetBytes(skBytes)
	factor := new(big.Int).SetBytes(factorBytes)

	order, ok := new(big.Int).SetString(
		"73eda753299d7d483339d80809a1d80553bda402fffe5bfeffffffff00000001", 16)
	if !ok {
		fmt.Fprintln(os.Stderr, "Internal error: failed to set curve order")
		os.Exit(1)
	}

	derived := new(big.Int).Mul(sk, factor)
	derived.Mod(derived, order)
	if derived.Sign() == 0 {
		fmt.Fprintln(os.Stderr, "Derived scalar is zero, invalid result")
		os.Exit(1)
	}

	derivedBytes := make([]byte, 32)
	dRaw := derived.Bytes()
	copy(derivedBytes[32-len(dRaw):], dRaw)
	fmt.Println(hex.EncodeToString(derivedBytes))
}

// cmdKeygen generates a BLS12-381 keypair and optionally registers the public key on-chain.
func cmdKeygen(userID, channel, chaincode string, autoRegister bool, keyFile string) {
	order, ok := new(big.Int).SetString(
		"73eda753299d7d483339d80809a1d80553bda402fffe5bfeffffffff00000001", 16)
	if !ok {
		fmt.Fprintln(os.Stderr, "Internal error: failed to set curve order")
		os.Exit(1)
	}

	sk, err := rand.Int(rand.Reader, order)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Private key generation error: %v\n", err)
		os.Exit(1)
	}
	if sk.Sign() == 0 {
		fmt.Fprintln(os.Stderr, "Generated scalar is zero, please run again.")
		os.Exit(1)
	}

	var pk bls.G1Affine
	pk.ScalarMultiplicationBase(sk)

	if !pk.IsOnCurve() || pk.IsInfinity() {
		fmt.Fprintln(os.Stderr, "Invalid keypair generated, please run again.")
		os.Exit(1)
	}

	skBytes := make([]byte, 32)
	skRaw := sk.Bytes()
	copy(skBytes[32-len(skRaw):], skRaw)
	pkBytesArr := pk.Bytes()

	fmt.Println("╔══════════════════════════════════════════════════════════════╗")
	fmt.Println("║          BLS12-381 Keypair generate (off-chain)              ║")
	fmt.Println("╚══════════════════════════════════════════════════════════════╝")
	fmt.Println()
	fmt.Println("PRIVATE KEY:")
	fmt.Printf("   %s\n", hex.EncodeToString(skBytes))
	if keyFile != "" {
		if err := os.WriteFile(keyFile, []byte(hex.EncodeToString(skBytes)), 0600); err != nil {
			fmt.Fprintf(os.Stderr, "Warning: could not save private key to %s: %v\n", keyFile, err)
		} else {
			fmt.Printf("   (saved to %s)\n", keyFile)
		}
	}
	fmt.Println()
	pubHex := hex.EncodeToString(pkBytesArr[:])
	fmt.Println("PUBLIC KEY:")
	fmt.Printf("   %s\n", pubHex)
	fmt.Println()
	fmt.Println("Command to register the key:")
	fmt.Printf("peer chaincode invoke -o localhost:7050 --ordererTLSHostnameOverride orderer.example.com --tls --cafile \"$ORDERER_CA\" -C %s -n %s --peerAddresses localhost:7051 --tlsRootCertFiles \"$PWD/organizations/peerOrganizations/org1.example.com/peers/peer0.org1.example.com/tls/ca.crt\" --peerAddresses localhost:9051 --tlsRootCertFiles \"$PWD/organizations/peerOrganizations/org2.example.com/peers/peer0.org2.example.com/tls/ca.crt\" -c '{\"function\":\"RegisterPublicKey\",\"Args\":[\"%s\",\"%s\"]}'\n", channel, chaincode, userID, pubHex)

	if !autoRegister {
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
		"-C", channel,
		"-n", chaincode,
		"--peerAddresses", "localhost:7051",
		"--tlsRootCertFiles", os.Getenv("PWD") + "/organizations/peerOrganizations/org1.example.com/peers/peer0.org1.example.com/tls/ca.crt",
		"--peerAddresses", "localhost:9051",
		"--tlsRootCertFiles", os.Getenv("PWD") + "/organizations/peerOrganizations/org2.example.com/peers/peer0.org2.example.com/tls/ca.crt",
		"-c", fmt.Sprintf("{\"function\":\"RegisterPublicKey\",\"Args\":[\"%s\",\"%s\"]}", userID, pubHex),
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
