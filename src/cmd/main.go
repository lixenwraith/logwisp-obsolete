package main

import (
	"bufio"
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"os"
	"os/signal"
	"path/filepath"
	"strings"
	"sync"
	"syscall"
	"time"

	"github.com/eiannone/keyboard"
)

const (
	colorReset   = "\033[0m"
	colorBlack   = "\033[30m"
	colorRed     = "\033[31m"
	colorGreen   = "\033[32m"
	colorYellow  = "\033[33m"
	colorBlue    = "\033[34m"
	colorMagenta = "\033[35m"
	colorCyan    = "\033[36m"
	colorWhite   = "\033[37m"
)

var (
	refreshRate     int
	logDir          string
	filter          string
	filterMutex     sync.RWMutex
	lastPrintTime   time.Time
	lastPrintMutex  sync.RWMutex
	gapPrinted      bool
	gapPrintedMutex sync.RWMutex
)

type LogEntry map[string]interface{}

func printHelp() {
	fmt.Println("Usage: logviewer [log directory] [-r <refresh rate in seconds>] [-h|--help]")
	fmt.Println("\nOptions:")
	fmt.Println("  [log directory]      Path to the directory containing log files (default: ./logs/)")
	fmt.Println("  -r, --rate           Refresh rate in seconds (default: 1)")
	fmt.Println("  -h, --help           Show this help message")
	fmt.Println("\nDescription:")
	fmt.Println("  This tool monitors all *.log files in the specified directory.")
	fmt.Println("  It parses JSON log entries and displays them in a colorful, compact format.")
	fmt.Println("  Type any character to add to the filter, backspace to remove the last character.")
	fmt.Println("  Press Ctrl-C to exit.")
}

func formatTimestamp(timestamp string) string {
	t, err := time.Parse(time.RFC3339Nano, timestamp)
	if err != nil {
		return timestamp // Return original if parsing fails
	}
	return t.Format("06-01-02 15:04:05.000000")
}

func padRight(str string, length int) string {
	if len(str) >= length {
		return str
	}
	return str + strings.Repeat(" ", length-len(str))
}

func formatLogEntry(entry LogEntry) string {
	timestamp, _ := entry["time"].(string)
	level, _ := entry["level"].(string)
	msg, _ := entry["msg"].(string)

	formattedTime := formatTimestamp(timestamp)
	paddedLevel := padRight(strings.ToUpper(level), 5)

	var levelColor string
	switch strings.ToUpper(level) {
	case "DEBUG":
		levelColor = colorBlue
	case "INFO":
		levelColor = colorGreen
	case "WARN":
		levelColor = colorYellow
	case "ERROR":
		levelColor = colorRed
	default:
		levelColor = colorWhite
	}

	formattedEntry := fmt.Sprintf("%s%s%s %s%s%s %s",
		colorMagenta, formattedTime, colorReset,
		levelColor, paddedLevel, colorReset,
		msg)

	// Add other fields
	for key, value := range entry {
		if key != "time" && key != "level" && key != "msg" {
			formattedEntry += fmt.Sprintf("\n    %s%s:%s %v", colorCyan, key, colorReset, value)
		}
	}

	return formattedEntry
}

func printLogEntry(entry string) {
	fmt.Println(entry)
	lastPrintMutex.Lock()
	lastPrintTime = time.Now()
	lastPrintMutex.Unlock()
	gapPrintedMutex.Lock()
	gapPrinted = false
	gapPrintedMutex.Unlock()
}

func monitorLogs() {
	filePositions := make(map[string]int64)
	knownFiles := make(map[string]bool)

	for {
		logFiles, err := filepath.Glob(filepath.Join(logDir, "*.log"))
		if err != nil {
			fmt.Printf("%sError reading log directory: %v%s\n", colorRed, err, colorReset)
			time.Sleep(time.Duration(refreshRate) * time.Second)
			continue
		}

		for _, filePath := range logFiles {
			if !knownFiles[filePath] {
				fmt.Printf("%sNew log file detected: %s%s\n", colorGreen, filepath.Base(filePath), colorReset)
				knownFiles[filePath] = true
			}

			file, err := os.OpenFile(filePath, os.O_RDONLY, 0644)
			if err != nil {
				fmt.Printf("%sError opening %s: %v%s\n", colorRed, filepath.Base(filePath), err, colorReset)
				continue
			}

			stat, err := file.Stat()
			if err != nil {
				fmt.Printf("%sError getting file stats for %s: %v%s\n", colorRed, filepath.Base(filePath), err, colorReset)
				file.Close()
				continue
			}

			if stat.Size() < filePositions[filePath] {
				fmt.Printf("%s%s has been truncated, starting from beginning%s\n", colorYellow, filepath.Base(filePath), colorReset)
				filePositions[filePath] = 0
			}

			_, err = file.Seek(filePositions[filePath], io.SeekStart)
			if err != nil {
				fmt.Printf("%sError seeking in %s: %v%s\n", colorRed, filepath.Base(filePath), err, colorReset)
				file.Close()
				continue
			}

			scanner := bufio.NewScanner(file)
			for scanner.Scan() {
				line := scanner.Text()
				var entry LogEntry
				err := json.Unmarshal([]byte(line), &entry)
				if err != nil {
					fmt.Printf("%sError parsing log entry: %v%s\n", colorRed, err, colorReset)
					continue
				}

				formattedEntry := formatLogEntry(entry)
				filterMutex.RLock()
				currentFilter := filter
				filterMutex.RUnlock()
				if currentFilter == "" || strings.Contains(strings.ToLower(formattedEntry), strings.ToLower(currentFilter)) {
					printLogEntry(formattedEntry)
				}
			}

			if err := scanner.Err(); err != nil {
				fmt.Printf("%sError reading %s: %v%s\n", colorRed, filepath.Base(filePath), err, colorReset)
			}

			newPosition, err := file.Seek(0, io.SeekCurrent)
			if err != nil {
				fmt.Printf("%sError getting current position in %s: %v%s\n", colorRed, filepath.Base(filePath), err, colorReset)
			} else {
				filePositions[filePath] = newPosition
			}

			file.Close()
		}

		time.Sleep(50 * time.Millisecond) // Check more frequently than refresh rate
	}
}

func checkAndPrintGap() {
	for {
		time.Sleep(50 * time.Millisecond)
		lastPrintMutex.RLock()
		timeSinceLastPrint := time.Since(lastPrintTime)
		lastPrintMutex.RUnlock()

		if timeSinceLastPrint > 100*time.Millisecond {
			gapPrintedMutex.RLock()
			currentGapPrinted := gapPrinted
			gapPrintedMutex.RUnlock()

			if !currentGapPrinted {
				fmt.Printf("%s◆%s\n", colorMagenta, colorReset)
				gapPrintedMutex.Lock()
				gapPrinted = true
				gapPrintedMutex.Unlock()
			}
		}
	}
}

func handleKeyPress(done chan<- struct{}) {
	for {
		char, key, err := keyboard.GetKey()
		if err != nil {
			fmt.Println("Error reading key:", err)
			done <- struct{}{}
			return
		}

		filterMutex.Lock()
		switch key {
		case keyboard.KeyCtrlC:
			fmt.Println("\nExiting...")
			done <- struct{}{}
			return
		case keyboard.KeyBackspace, keyboard.KeyBackspace2:
			if len(filter) > 0 {
				filter = filter[:len(filter)-1]
			}
		case keyboard.KeySpace:
			filter += " "
		default:
			if char != 0 {
				filter += string(char)
			}
		}
		fmt.Printf("\rCurrent filter: %s", filter)
		filterMutex.Unlock()
	}
}

func cleanup() {
	keyboard.Close()
	// Restore terminal settings
	fmt.Print("\033[?25h")   // Show cursor
	fmt.Print("\033[?1049l") // Restore screen
}

func main() {
	var help bool

	flag.IntVar(&refreshRate, "r", 1, "Refresh rate in seconds")
	flag.IntVar(&refreshRate, "rate", 1, "Refresh rate in seconds")
	flag.BoolVar(&help, "h", false, "Show help")
	flag.BoolVar(&help, "help", false, "Show help")
	flag.Parse()

	if help {
		printHelp()
		os.Exit(0)
	}

	args := flag.Args()
	logDir = "./logs/"
	if len(args) > 0 {
		fileInfo, err := os.Stat(args[0])
		if err == nil && fileInfo.IsDir() {
			logDir = args[0]
		} else {
			fmt.Printf("WARNING: '%s' is not a valid directory. Using default './logs/'\n", args[0])
		}
	}

	if _, err := os.Stat(logDir); os.IsNotExist(err) {
		fmt.Printf("Log directory '%s' does not exist. Please specify a valid directory.\n", logDir)
		os.Exit(1)
	}

	fmt.Printf("Monitoring logs in directory: %s\n", logDir)
	fmt.Printf("Refresh rate: %d second(s)\n", refreshRate)

	lastPrintTime = time.Now()

	if err := keyboard.Open(); err != nil {
		panic(err)
	}
	defer cleanup()

	// Set up signal handling
	sigChan := make(chan os.Signal, 1)
	signal.Notify(sigChan, syscall.SIGINT, syscall.SIGTERM)
	go func() {
		<-sigChan
		fmt.Println("\nExiting...")
		cleanup()
		os.Exit(0)
	}()

	go monitorLogs()
	go checkAndPrintGap()

	done := make(chan struct{})
	go handleKeyPress(done)

	fmt.Println("Start typing to filter logs. Press Ctrl-C to exit.")
	fmt.Print("Current filter: ")

	// Wait for the done signal or for all other goroutines to complete
	select {
	case <-done:
	}
}
