package main

import (
	"bufio"
	"fmt"
	"log"
	"os"
)

func main() {
	fmt.Println("Test program started. PID:", os.Getpid())

	// Open first file
	fmt.Println("Opening file1.txt...")
	file1, err := os.Open("file1.txt")
	if err != nil {
		log.Fatalf("Failed to open file1.txt: %v", err)
	}
	defer file1.Close()

	// Read a line from first file
	scanner := bufio.NewScanner(file1)
	if scanner.Scan() {
		fmt.Printf("Read from file1.txt: %s\n", scanner.Text())
	}
	if err := scanner.Err(); err != nil {
		log.Fatalf("Error reading file1.txt: %v", err)
	}

	// Wait for user input
	fmt.Println("Press Enter to open the second file...")
	bufio.NewReader(os.Stdin).ReadBytes('\n')

	// Open second file (this should be blocked if in enforce mode)
	fmt.Println("Opening file2.txt...")
	file2, err := os.Open("file2.txt")
	if err != nil {
		log.Printf("Failed to open file2.txt: %v", err)
		fmt.Println("This is expected if ebpfence is blocking new file opens!")
		return
	}
	defer file2.Close()

	// Read from second file
	scanner2 := bufio.NewScanner(file2)
	if scanner2.Scan() {
		fmt.Printf("Read from file2.txt: %s\n", scanner2.Text())
	}
	if err := scanner2.Err(); err != nil {
		log.Fatalf("Error reading file2.txt: %v", err)
	}

	fmt.Println("Test program completed successfully")
}
