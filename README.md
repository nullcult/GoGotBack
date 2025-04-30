# GoGotBack – Advanced Shellcode Execution & Evasion Framework

## ⭐️ Why GoGotBack?
GoGotBack is a proof-of-concept toolkit written in Go that showcases modern offensive techniques for **defence evasion** on Windows.  
It combines dynamic syscall resolution, phantom DLL hollowing, and direct memory execution to run arbitrary x64 shellcode while tip-toeing around common EDR / AV heuristics.

> **Educational Use Only** – The code is released to help researchers and blue-teamers understand how these techniques work so they can build better detections.

---

## ✨ Key Features
- **Dynamic Syscall Shuffling** – Resolves & shuffles syscall numbers at run-time to dodge user-mode API hooks (`dynamic_syscall.go`).
- **Phantom DLL Hollowing** – Loads a legitimate DLL, zeros an executable section, and stashes the (decoded) shellcode inside (`phantom_dll.go`).
- **Direct Memory Execution** – Allocates private RW ➜ RX memory, copies the payload, and launches it via `NtCreateThreadEx` without touching Win32 APIs (`direct_executor.go`).
- **Layered Orchestration** – `enhanced_executor.go` glues everything together and prints colourised logs courtesy of `colors.go`.
- **XOR Shellcode Obfuscation** – Tiny helper script `xorme.py` encodes raw shellcode for safer embedding in Go.

---

## 🖼️ Architecture at a Glance
```text
┌──────────────────────────────┐
│   enhanced_executor.go       │
│  (high-level orchestrator)   │
└──────────┬─────────┬─────────┘
           │         │
           │         └──► PhantomDLL (hollow holder)
           │                └─ phantom_dll.go
           │
           ├──► DynamicSyscallTable
           │       └─ dynamic_syscall.go
           │
           └──► DirectExecutor (alloc & run)
                   └─ direct_executor.go
```

---

## 🛠️ Installation
Requires **Go 1.20+** on Windows x64.

```powershell
# Clone
> git clone https://github.com/<you>/GoGotBack.git
> cd GoGotBack

# Grab dependencies & verify
> go mod tidy && go mod verify

# (Optional) update sys/windows
> go get -u golang.org/x/sys/windows
```

---

## 🚀 Building & Running
```powershell
# Compile
go build -o GoGotBack.exe

# Run (will pop calc.exe as the demo payload)
./GoGotBack.exe
```
You should see colourful logging like:
```
=======================================================
        GoGotBack Shellcode Execution Framework        
=======================================================
Techniques active:
  - Dynamic Syscall Shuffling
  - Phantom DLL Hollowing (Shellcode Holding)
  - Direct Memory Allocation Execution
=======================================================
[+] Initializing shellcode executor...
...
```

### Supplying Your Own Shellcode
1. Generate or obtain raw x64 shellcode (e.g. `msfvenom -p windows/x64/exec CMD=whoami -f raw`).
2. Encode it with the helper:
   ```bash
   cat shellcode.raw | python3 xorme.py -t go -x 31 > payload.go
   ```
3. Replace the `buf := []byte{ ... }` slice inside `enhanced_executor.go` with your new array & adjust the XOR key if you changed `-x`.
4. Compile & run.

> **Note**: GoGotBack purposefully does *not* include runtime shellcode download to keep the scope focused.

---

## 📂 Project Layout
| Path | Purpose |
|------|---------|
| `dynamic_syscall.go` | Runtime parsing of `ntdll.dll` to grab syscall numbers & execute them via custom stubs. |
| `phantom_dll.go` | Loads a random benign DLL, hollows a code section, and stores decoded shellcode. |
| `direct_executor.go` | Allocates private memory, copies payload, changes protection to RX, spawns a new thread. |
| `enhanced_executor.go` | High-level CLI application orchestrating the full chain. |
| `colors.go` | ANSI colour helpers using `fatih/color`. |
| `xorme.py` | XOR encoder for shellcode blobs (Go / C# / Python output). |
| `blog.md` | Deep-dive article explaining the techniques (used as reference for this README). |
| `PRD.md` | Detailed Product Requirements Document for future enhancements. |

---

## ⚠️ Disclaimer
This repository is intended **solely for educational and defensive research**.  
Running the compiled binary will execute *real* shellcode on your machine. Use in isolated lab environments and **do not** target systems without prior authorisation.  
The authors accept no liability for misuse.

---
