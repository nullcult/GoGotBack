package main

import "github.com/fatih/color"

// Define color printers for different log levels
var (
	colorSuccess = color.New(color.FgGreen).Add(color.Bold)   // [+] Green, Bold
	colorInfo    = color.New(color.FgCyan)                   // [*] Cyan (for general info)
	colorWarn    = color.New(color.FgYellow)                 // [WARN] Yellow
	colorError   = color.New(color.FgRed).Add(color.Bold)     // [ERROR] Red, Bold
	colorDebug   = color.New(color.FgHiBlack)                // [DEBUG] Grey/Dim Black
	colorHeader  = color.New(color.FgMagenta).Add(color.Bold) // Header Magenta, Bold
)

// Helper functions (optional, but can make calls cleaner)
func printSuccess(format string, a ...interface{}) {
	colorSuccess.PrintfFunc()(format, a...)
}

func printInfo(format string, a ...interface{}) {
	colorInfo.PrintfFunc()(format, a...)
}

func printWarn(format string, a ...interface{}) {
	colorWarn.PrintfFunc()(format, a...)
}

func printError(format string, a ...interface{}) {
	colorError.PrintfFunc()(format, a...)
}

func printDebug(format string, a ...interface{}) {
	colorDebug.PrintfFunc()(format, a...)
}

func printHeaderLine(format string, a ...interface{}) {
	colorHeader.PrintfFunc()(format, a...)
} 