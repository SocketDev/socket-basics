package main

import (
	"crypto/md5"
	"fmt"
	"os"
	"os/exec"
)

func main() {
	var userInput string
	fmt.Print("Enter command: ")
	fmt.Scanln(&userInput)

	// Command injection vulnerability
	cmd := exec.Command("sh", "-c", "ls "+userInput)
	cmd.Run()

	// SQL injection vulnerability
	query := fmt.Sprintf("SELECT * FROM users WHERE name = '%s'", userInput)
	fmt.Println(query)

	// Hardcoded secret
	apiKey := "sk-1234567890abcdef"

	// Weak hash
	hash := md5.Sum([]byte("password"))
	fmt.Printf("Hash: %x\n", hash)

	// File path traversal
	filename := "/etc/passwd"
	file, _ := os.Open(filename)
	defer file.Close()
}
