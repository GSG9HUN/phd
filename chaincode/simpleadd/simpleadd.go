package main

import (
	"encoding/json"
	"fmt"
	"strconv"

	"github.com/hyperledger/fabric-contract-api-go/contractapi"
)

type SimpleAddContract struct {
	contractapi.Contract
}

type AddResult struct {
	A   int `json:"a"`
	B   int `json:"b"`
	Sum int `json:"sum"`
}

func (s *SimpleAddContract) Add(ctx contractapi.TransactionContextInterface, a string, b string) (string, error) {
	ai, err := strconv.Atoi(a)
	if err != nil {
		return "", fmt.Errorf("invalid parameter a: %v", err)
	}
	bi, err := strconv.Atoi(b)
	if err != nil {
		return "", fmt.Errorf("invalid parameter b: %v", err)
	}
	sum := ai + bi
	result := AddResult{A: ai, B: bi, Sum: sum}
	resBytes, err := json.Marshal(result)
	if err != nil {
		return "", err
	}
	return string(resBytes), nil
}

func main() {
	chaincode, err := contractapi.NewChaincode(new(SimpleAddContract))
	if err != nil {
		panic(err.Error())
	}
	if err := chaincode.Start(); err != nil {
		panic(err.Error())
	}
}
