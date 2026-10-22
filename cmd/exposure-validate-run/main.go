package main

import (
	"fmt"
	"os"

	"github.com/mrchypark/exposure/internal/usevalidation"
)

func main() {
	if len(os.Args) != 2 {
		fmt.Fprintln(os.Stderr, "usage: exposure-validate-run <absolute-manifest.json>")
		os.Exit(2)
	}
	receipt, err := usevalidation.LoadAndValidate(os.Args[1])
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
	body, err := usevalidation.EncodeReceipt(receipt)
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
	_, _ = os.Stdout.Write(append(body, '\n'))
}
