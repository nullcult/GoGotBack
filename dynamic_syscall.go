package main

import (
	"fmt"
	"math/rand"
	"syscall"
	"time"
	"unsafe"
	"strings"

	"golang.org/x/sys/windows"
)

// SyscallInfo stores information about a syscall
type SyscallInfo struct {
	SSN       uint16
	Name      string
	NtFunc    *windows.LazyProc
	Shuffled  bool
	Threshold float64 // Threshold for execution path selection
}

// DynamicSyscallTable maintains a table of syscalls that can be shuffled
type DynamicSyscallTable struct {
	Syscalls       []SyscallInfo
	NtdllBase      uintptr
	ShuffleCounter int
	rng            *rand.Rand
}

// NewDynamicSyscallTable creates a new syscall table with dynamic resolution
func NewDynamicSyscallTable() (*DynamicSyscallTable, error) {
	// Create a new random source with time-based seed
	source := rand.NewSource(time.Now().UnixNano())
	rng := rand.New(source)

	// Get NTDLL module handle
	ntdll := windows.NewLazySystemDLL("ntdll.dll")
	if err := ntdll.Load(); err != nil {
		return nil, fmt.Errorf("failed to load ntdll.dll: %v", err)
	}

	// Create the syscall table
	table := &DynamicSyscallTable{
		Syscalls:       make([]SyscallInfo, 0, 32),
		NtdllBase:      uintptr(ntdll.Handle()),
		ShuffleCounter: 0,
		rng:            rng,
	}

	// Initialize with essential syscalls
	essentialSyscalls := []string{
		"NtAllocateVirtualMemory",
		"NtProtectVirtualMemory",
		"NtCreateThreadEx",
		"NtWaitForSingleObject",
		"NtClose",
		"NtOpenProcess",
		"NtWriteVirtualMemory",
		"NtReadVirtualMemory",
		"NtQueueApcThread",
		"NtCreateSection",
		"NtMapViewOfSection",
		"NtUnmapViewOfSection",
		"NtGetContextThread",
		"NtSetContextThread",
		"NtTerminateThread",
	}

	for _, name := range essentialSyscalls {
		proc := ntdll.NewProc(name)
		if err := proc.Find(); err != nil {
			// Non-critical error, just log and continue
			fmt.Printf("Warning: Could not find syscall %s: %v\n", name, err)
			continue
		}

		// Extract syscall number from the function
		ssn, err := getSyscallNumber(proc)
		if err != nil {
			fmt.Printf("Warning: Could not get syscall number for %s: %v\n", name, err)
			continue
		}

		// Add to our table with a random threshold
		table.Syscalls = append(table.Syscalls, SyscallInfo{
			SSN:       ssn,
			Name:      name,
			NtFunc:    proc,
			Shuffled:  false,
			Threshold: rng.Float64(), // Random threshold between 0 and 1
		})
	}

	// Initial shuffle
	table.ShuffleSyscalls()

	return table, nil
}

// getSyscallNumber extracts the syscall number from a syscall procedure
func getSyscallNumber(proc *windows.LazyProc) (uint16, error) {
	// The syscall number is typically stored in the first few bytes of the function
	// For x64 Windows syscalls, it's usually at offset 4 (mov eax, syscallnumber)
	buf := make([]byte, 16)
	
	// Read the first 16 bytes of the function
	err := windows.ReadProcessMemory(windows.CurrentProcess(), proc.Addr(), &buf[0], uintptr(len(buf)), nil)
	if err != nil {
		return 0, fmt.Errorf("failed to read process memory: %v", err)
	}

	// Check for typical syscall pattern (x64)
	// Usually: 4C 8B D1 B8 [syscall number] 00 00 00
	if buf[0] == 0x4C && buf[1] == 0x8B && buf[2] == 0xD1 && buf[3] == 0xB8 {
		return uint16(buf[4]), nil
	}

	// Alternative pattern removed as it might be unreliable for NT syscalls
	// if buf[0] == 0xB8 { 
	// 	return uint16(buf[1]), nil 
	// }

	// If we can't identify the pattern, return an error
	return 0, fmt.Errorf("could not identify syscall pattern for address %x, bytes: %x", proc.Addr(), buf)
}

// ShuffleSyscalls randomizes the syscall table
func (t *DynamicSyscallTable) ShuffleSyscalls() {
	// Shuffle the syscall order
	t.rng.Shuffle(len(t.Syscalls), func(i, j int) {
		t.Syscalls[i], t.Syscalls[j] = t.Syscalls[j], t.Syscalls[i]
	})

	// Assign new thresholds
	for i := range t.Syscalls {
		t.Syscalls[i].Threshold = t.rng.Float64()
		t.Syscalls[i].Shuffled = true
	}

	t.ShuffleCounter++
}

// MaybeShuffleSyscalls occasionally shuffles the syscall table
func (t *DynamicSyscallTable) MaybeShuffleSyscalls() {
	// Shuffle with 10% probability or every 10 calls
	if t.rng.Float64() < 0.1 || t.ShuffleCounter%10 == 0 {
		t.ShuffleSyscalls()
	}
}

// GetSyscallByName retrieves a syscall by name
func (t *DynamicSyscallTable) GetSyscallByName(name string) (*SyscallInfo, error) {
	for i := range t.Syscalls {
		if t.Syscalls[i].Name == name {
			return &t.Syscalls[i], nil
		}
	}
	return nil, fmt.Errorf("syscall %s not found", name)
}

// ExecuteSyscall chooses between direct and indirect syscall based on threshold
func (t *DynamicSyscallTable) ExecuteSyscall(name string, args ...uintptr) (uintptr, error) {
	info, err := t.GetSyscallByName(name)
	if err != nil {
		return 0, fmt.Errorf("syscall %s not found in table: %v", name, err)
	}

	// Determine execution path
	useDirect := true // Default to direct for safety if threshold logic fails
	if info.Shuffled {
		// Compare random number to threshold
		if t.rng.Float64() < info.Threshold {
			useDirect = false // Use indirect
		} else {
			useDirect = true // Use direct
		}
	} else {
		useDirect = true // Always use direct if not shuffled (shouldn't happen often)
	}

	if useDirect {
		fmt.Printf("[DEBUG] Using directSyscall path for %s.\n", name) // Changed log message slightly
		return t.directSyscall(info, args...) // NEW Call - Pass full info
	} else {
		fmt.Printf("[DEBUG] Using indirectSyscall path for %s.\n", name) // Changed log message slightly
		return t.indirectSyscall(info, args...)
	}
}

// directSyscall executes a syscall directly using the resolved function pointer via syscall.SyscallN
func (t *DynamicSyscallTable) directSyscall(info *SyscallInfo, args ...uintptr) (uintptr, error) {
	
	if info.NtFunc == nil {
		return 0, fmt.Errorf("NtFunc is nil for %s in directSyscall", info.Name)
	}
	
	// Get the actual function address
	procAddr := info.NtFunc.Addr()
	if procAddr == 0 {
		return 0, fmt.Errorf("could not get address for %s", info.Name)
	}

	// Use syscall.SyscallN with the function address
	numArgs := uintptr(len(args))
	const maxArgs = 15
	argsPadded := make([]uintptr, maxArgs)
	copy(argsPadded, args)

	var ret uintptr
	var err syscall.Errno

	switch numArgs {
	case 0:
		ret, _, err = syscall.Syscall(procAddr, 0, 0, 0, 0)
	case 1:
		ret, _, err = syscall.Syscall(procAddr, 1, argsPadded[0], 0, 0)
	case 2:
		ret, _, err = syscall.Syscall(procAddr, 2, argsPadded[0], argsPadded[1], 0)
	case 3:
		ret, _, err = syscall.Syscall(procAddr, 3, argsPadded[0], argsPadded[1], argsPadded[2])
	case 4:
		ret, _, err = syscall.Syscall6(procAddr, 4, argsPadded[0], argsPadded[1], argsPadded[2], argsPadded[3], 0, 0)
	case 5:
		ret, _, err = syscall.Syscall6(procAddr, 5, argsPadded[0], argsPadded[1], argsPadded[2], argsPadded[3], argsPadded[4], 0)
	case 6:
		ret, _, err = syscall.Syscall6(procAddr, 6, argsPadded[0], argsPadded[1], argsPadded[2], argsPadded[3], argsPadded[4], argsPadded[5])
	case 7:
		ret, _, err = syscall.Syscall9(procAddr, 7, argsPadded[0], argsPadded[1], argsPadded[2], argsPadded[3], argsPadded[4], argsPadded[5], argsPadded[6], 0, 0)
	case 8:
		ret, _, err = syscall.Syscall9(procAddr, 8, argsPadded[0], argsPadded[1], argsPadded[2], argsPadded[3], argsPadded[4], argsPadded[5], argsPadded[6], argsPadded[7], 0)
	case 9:
		ret, _, err = syscall.Syscall9(procAddr, 9, argsPadded[0], argsPadded[1], argsPadded[2], argsPadded[3], argsPadded[4], argsPadded[5], argsPadded[6], argsPadded[7], argsPadded[8])
	case 10:
		ret, _, err = syscall.Syscall12(procAddr, 10, argsPadded[0], argsPadded[1], argsPadded[2], argsPadded[3], argsPadded[4], argsPadded[5], argsPadded[6], argsPadded[7], argsPadded[8], argsPadded[9], 0, 0)
	case 11:
		ret, _, err = syscall.Syscall12(procAddr, 11, argsPadded[0], argsPadded[1], argsPadded[2], argsPadded[3], argsPadded[4], argsPadded[5], argsPadded[6], argsPadded[7], argsPadded[8], argsPadded[9], argsPadded[10], 0)
	case 12:
		ret, _, err = syscall.Syscall12(procAddr, 12, argsPadded[0], argsPadded[1], argsPadded[2], argsPadded[3], argsPadded[4], argsPadded[5], argsPadded[6], argsPadded[7], argsPadded[8], argsPadded[9], argsPadded[10], argsPadded[11])
	case 13:
		ret, _, err = syscall.Syscall15(procAddr, 13, argsPadded[0], argsPadded[1], argsPadded[2], argsPadded[3], argsPadded[4], argsPadded[5], argsPadded[6], argsPadded[7], argsPadded[8], argsPadded[9], argsPadded[10], argsPadded[11], argsPadded[12], 0, 0)
	case 14:
		ret, _, err = syscall.Syscall15(procAddr, 14, argsPadded[0], argsPadded[1], argsPadded[2], argsPadded[3], argsPadded[4], argsPadded[5], argsPadded[6], argsPadded[7], argsPadded[8], argsPadded[9], argsPadded[10], argsPadded[11], argsPadded[12], argsPadded[13], 0)
	case 15:
		ret, _, err = syscall.Syscall15(procAddr, 15, argsPadded[0], argsPadded[1], argsPadded[2], argsPadded[3], argsPadded[4], argsPadded[5], argsPadded[6], argsPadded[7], argsPadded[8], argsPadded[9], argsPadded[10], argsPadded[11], argsPadded[12], argsPadded[13], argsPadded[14])
	default:
		return 0, fmt.Errorf("too many arguments for direct syscall (%s): %d", info.Name, numArgs)
	}

	if err != 0 {
		return ret, fmt.Errorf("direct syscall to %s failed: %v", info.Name, err)
	}
	return ret, nil
	
	/* // OLD IMPLEMENTATION using NtFunc.Call()
	ret, _, err := info.NtFunc.Call(args...)
	
	// Check the error returned by Call()
	if err != nil && err.(syscall.Errno) != 0 { // Check if it's a non-zero Errno
	    // The return value 'ret' from Call is usually the NTSTATUS code in case of syscalls.
	    // We return both ret (NTSTATUS) and the Go error.
		return ret, fmt.Errorf("direct call to %s failed: %v", info.Name, err)
	}
	
	// Even if err is nil or errno 0, ret contains the NTSTATUS.
	// The wrapper functions (e.g., NtAllocateVirtualMemory) will check this status.
	return ret, nil
	*/
}

// indirectSyscall executes a syscall indirectly through a dynamically generated stub
func (t *DynamicSyscallTable) indirectSyscall(info *SyscallInfo, args ...uintptr) (uintptr, error) {
	// Generate a syscall stub
	stub, err := t.generateSyscallStub(info.SSN)
	if err != nil {
		return 0, err
	}
	defer windows.VirtualFree(stub, 0, windows.MEM_RELEASE)

	numArgs := uintptr(len(args))
	// Ensure args slice has enough capacity, pad with zeros if needed
	const maxArgs = 15 // Match directSyscall
	argsPadded := make([]uintptr, maxArgs)
	copy(argsPadded, args)

	var ret uintptr
	var callErr syscall.Errno

	// Call the stub address using appropriate SyscallN function
	switch numArgs {
	case 0:
		ret, _, callErr = syscall.Syscall(stub, 0, 0, 0, 0)
	case 1:
		ret, _, callErr = syscall.Syscall(stub, 1, argsPadded[0], 0, 0)
	case 2:
		ret, _, callErr = syscall.Syscall(stub, 2, argsPadded[0], argsPadded[1], 0)
	case 3:
		ret, _, callErr = syscall.Syscall(stub, 3, argsPadded[0], argsPadded[1], argsPadded[2])
	case 4:
		ret, _, callErr = syscall.Syscall6(stub, 4, argsPadded[0], argsPadded[1], argsPadded[2], argsPadded[3], 0, 0)
	case 5:
		ret, _, callErr = syscall.Syscall6(stub, 5, argsPadded[0], argsPadded[1], argsPadded[2], argsPadded[3], argsPadded[4], 0)
	case 6:
		ret, _, callErr = syscall.Syscall6(stub, 6, argsPadded[0], argsPadded[1], argsPadded[2], argsPadded[3], argsPadded[4], argsPadded[5])
	case 7:
		ret, _, callErr = syscall.Syscall9(stub, 7, argsPadded[0], argsPadded[1], argsPadded[2], argsPadded[3], argsPadded[4], argsPadded[5], argsPadded[6], 0, 0)
	case 8:
		ret, _, callErr = syscall.Syscall9(stub, 8, argsPadded[0], argsPadded[1], argsPadded[2], argsPadded[3], argsPadded[4], argsPadded[5], argsPadded[6], argsPadded[7], 0)
	case 9:
		ret, _, callErr = syscall.Syscall9(stub, 9, argsPadded[0], argsPadded[1], argsPadded[2], argsPadded[3], argsPadded[4], argsPadded[5], argsPadded[6], argsPadded[7], argsPadded[8])
	case 10:
		ret, _, callErr = syscall.Syscall12(stub, 10, argsPadded[0], argsPadded[1], argsPadded[2], argsPadded[3], argsPadded[4], argsPadded[5], argsPadded[6], argsPadded[7], argsPadded[8], argsPadded[9], 0, 0)
	case 11:
		ret, _, callErr = syscall.Syscall12(stub, 11, argsPadded[0], argsPadded[1], argsPadded[2], argsPadded[3], argsPadded[4], argsPadded[5], argsPadded[6], argsPadded[7], argsPadded[8], argsPadded[9], argsPadded[10], 0)
	case 12:
		ret, _, callErr = syscall.Syscall12(stub, 12, argsPadded[0], argsPadded[1], argsPadded[2], argsPadded[3], argsPadded[4], argsPadded[5], argsPadded[6], argsPadded[7], argsPadded[8], argsPadded[9], argsPadded[10], argsPadded[11])
	case 13:
		ret, _, callErr = syscall.Syscall15(stub, 13, argsPadded[0], argsPadded[1], argsPadded[2], argsPadded[3], argsPadded[4], argsPadded[5], argsPadded[6], argsPadded[7], argsPadded[8], argsPadded[9], argsPadded[10], argsPadded[11], argsPadded[12], 0, 0)
	case 14:
		ret, _, callErr = syscall.Syscall15(stub, 14, argsPadded[0], argsPadded[1], argsPadded[2], argsPadded[3], argsPadded[4], argsPadded[5], argsPadded[6], argsPadded[7], argsPadded[8], argsPadded[9], argsPadded[10], argsPadded[11], argsPadded[12], argsPadded[13], 0)
	case 15:
		ret, _, callErr = syscall.Syscall15(stub, 15, argsPadded[0], argsPadded[1], argsPadded[2], argsPadded[3], argsPadded[4], argsPadded[5], argsPadded[6], argsPadded[7], argsPadded[8], argsPadded[9], argsPadded[10], argsPadded[11], argsPadded[12], argsPadded[13], argsPadded[14])
	default:
		return 0, fmt.Errorf("too many arguments for indirect syscall: %d", numArgs)
	}

	if callErr != 0 {
		return ret, fmt.Errorf("indirect syscall failed: %v", callErr)
	}
	
	// Check NTSTATUS return value (ret) in the wrapper function
	return ret, nil 
}

// generateSyscallStub creates a dynamic syscall stub in memory
func (t *DynamicSyscallTable) generateSyscallStub(ssn uint16) (uintptr, error) {
	// Choose a random stub pattern
	// pattern := t.rng.Intn(3) // REMOVED Randomization
	pattern := 0 // Always use the standard pattern
	
	var stubCode []byte
	
	switch pattern {
	case 0:
		// Standard x64 syscall stub
		stubCode = []byte{
			0x4C, 0x8B, 0xD1,             // mov r10, rcx
			0xB8, byte(ssn), 0x00, 0x00, 0x00, // mov eax, ssn
			0x0F, 0x05,                   // syscall
			0xC3,                         // ret
		}
	/* // REMOVED Faulty Pattern 1
	case 1:
		// Alternative pattern with register shuffling
		stubCode = []byte{
			0x49, 0x89, 0xCA,             // mov r10, rcx
			0x48, 0x89, 0xD9,             // mov rcx, rbx (example shuffle)
			0xB8, byte(ssn), 0x00, 0x00, 0x00, // mov eax, ssn
			0x0F, 0x05,                   // syscall
			0xC3,                         // ret
		}
	*/
	/* // REMOVED Pattern 2 (Optional)
	case 2:
		// Pattern with junk instructions
		stubCode = []byte{
			0x90, 0x90,                   // nop, nop (junk)
			0x4C, 0x8B, 0xD1,             // mov r10, rcx
			0x48, 0x31, 0xC0,             // xor rax, rax (junk)
			0xB8, byte(ssn), 0x00, 0x00, 0x00, // mov eax, ssn
			0x90,                         // nop (junk)
			0x0F, 0x05,                   // syscall
			0xC3,                         // ret
		}
	*/
	default: // Should not happen now
	    return 0, fmt.Errorf("invalid pattern selected in generateSyscallStub")
	}
	
	// Allocate memory for the stub
	stubAddr, err := windows.VirtualAlloc(0, uintptr(len(stubCode)), 
		windows.MEM_COMMIT|windows.MEM_RESERVE, 
		windows.PAGE_READWRITE)
	if err != nil {
		return 0, fmt.Errorf("failed to allocate memory for syscall stub: %v", err)
	}
	
	// Copy the stub code to the allocated memory
	copy((*[1024]byte)(unsafe.Pointer(stubAddr))[:len(stubCode)], stubCode)
	
	// Change memory protection to executable
	var oldProtect uint32
	err = windows.VirtualProtect(stubAddr, uintptr(len(stubCode)), windows.PAGE_EXECUTE_READ, &oldProtect)
	if err != nil {
		windows.VirtualFree(stubAddr, 0, windows.MEM_RELEASE)
		return 0, fmt.Errorf("failed to change memory protection: %v", err)
	}
	
	return stubAddr, nil
}

// Helper functions for common syscalls

// NtAllocateVirtualMemory allocates memory using dynamic syscall
func (t *DynamicSyscallTable) NtAllocateVirtualMemory(processHandle windows.Handle, baseAddress *uintptr, 
	zeroBits uintptr, regionSize *uintptr, allocationType uint32, protect uint32) error {
	
	ret, err := t.ExecuteSyscall("NtAllocateVirtualMemory", 
		uintptr(processHandle), 
		uintptr(unsafe.Pointer(baseAddress)),
		zeroBits, 
		uintptr(unsafe.Pointer(regionSize)),
		uintptr(allocationType), 
		uintptr(protect))
	
	if err != nil {
		return err
	}
	
	if ret != 0 {
		return fmt.Errorf("NtAllocateVirtualMemory failed with status: 0x%x", ret)
	}
	
	return nil
}

// NtProtectVirtualMemory changes memory protection using dynamic syscall
func (t *DynamicSyscallTable) NtProtectVirtualMemory(processHandle windows.Handle, baseAddress *uintptr, 
	regionSize *uintptr, newProtect uint32, oldProtect *uint32) error {
	
	ret, err := t.ExecuteSyscall("NtProtectVirtualMemory", 
		uintptr(processHandle), 
		uintptr(unsafe.Pointer(baseAddress)),
		uintptr(unsafe.Pointer(regionSize)),
		uintptr(newProtect), 
		uintptr(unsafe.Pointer(oldProtect)))
	
	if err != nil {
		return err
	}
	
	if ret != 0 {
		return fmt.Errorf("NtProtectVirtualMemory failed with status: 0x%x", ret)
	}
	
	return nil
}

// NtCreateThreadEx creates a thread using dynamic syscall
func (t *DynamicSyscallTable) NtCreateThreadEx(threadHandle *windows.Handle, desiredAccess uint32, 
	objectAttributes uintptr, processHandle windows.Handle, startRoutine uintptr, 
	argument uintptr, createFlags uint32, zeroBits uintptr, stackSize uintptr, 
	maximumStackSize uintptr, attributeList uintptr) error {
	
	ret, err := t.ExecuteSyscall("NtCreateThreadEx", 
		uintptr(unsafe.Pointer(threadHandle)),
		uintptr(desiredAccess), 
		objectAttributes, 
		uintptr(processHandle), 
		startRoutine, 
		argument, 
		uintptr(createFlags), 
		zeroBits, 
		stackSize, 
		maximumStackSize, 
		attributeList)
	
	if err != nil {
		return err
	}
	
	if ret != 0 {
		return fmt.Errorf("NtCreateThreadEx failed with status: 0x%x", ret)
	}
	
	return nil
}

// NtWriteVirtualMemory writes to memory using dynamic syscall
func (t *DynamicSyscallTable) NtWriteVirtualMemory(processHandle windows.Handle, baseAddress uintptr, 
	buffer unsafe.Pointer, size uintptr, bytesWritten *uintptr) error {
	
	ret, err := t.ExecuteSyscall("NtWriteVirtualMemory", 
		uintptr(processHandle), 
		baseAddress, 
		uintptr(buffer),
		size, 
		uintptr(unsafe.Pointer(bytesWritten)))
	
	if err != nil {
		return err
	}
	
	if ret != 0 {
		return fmt.Errorf("NtWriteVirtualMemory failed with status: 0x%x", ret)
	}
	
	return nil
}

// NtWaitForSingleObject waits for an object using dynamic syscall
func (t *DynamicSyscallTable) NtWaitForSingleObject(handle windows.Handle, alertable bool, timeout *int64) error {
	var alertableInt uintptr
	if alertable {
		alertableInt = 1
	}
	
	ret, err := t.ExecuteSyscall("NtWaitForSingleObject", 
		uintptr(handle), 
		alertableInt, 
		uintptr(unsafe.Pointer(timeout)))

	fmt.Printf("[DEBUG] NtWaitForSingleObject returned status: 0x%x\n", ret)

	if err != nil {
		return err
	}
	
	if ret != 0 && ret != 0x102 { // STATUS_SUCCESS or STATUS_TIMEOUT
		return fmt.Errorf("NtWaitForSingleObject failed with status: 0x%x", ret)
	}
	
	return nil
}

// NtTerminateThread terminates a thread using dynamic syscalls
func (t *DynamicSyscallTable) NtTerminateThread(threadHandle windows.Handle, exitStatus uint32) error {
	ret, err := t.ExecuteSyscall("NtTerminateThread", uintptr(threadHandle), uintptr(exitStatus))
	if err != nil {
		return fmt.Errorf("ExecuteSyscall(NtTerminateThread) failed: %v", err)
	}
	if ret != 0 { // STATUS_SUCCESS is 0
		return fmt.Errorf("NtTerminateThread failed with status: 0x%x", ret)
	}
	return nil
}

// NtCloseWrapper closes a handle using dynamic syscalls
func (t *DynamicSyscallTable) NtCloseWrapper(handle windows.Handle) error {
	ret, err := t.ExecuteSyscall("NtClose", uintptr(handle))
	if err != nil {
		// Handle case where NtClose might not have been found initially
		if strings.Contains(err.Error(), "syscall NtClose not found") {
			fmt.Println("[DEBUG] NtClose syscall not found in table, using windows.CloseHandle as fallback.")
			return windows.CloseHandle(handle)
		}
		return fmt.Errorf("ExecuteSyscall(NtClose) failed: %v", err)
	}
	if ret != 0 { // STATUS_SUCCESS is 0
		return fmt.Errorf("NtClose failed with status: 0x%x", ret)
	}
	return nil
}
