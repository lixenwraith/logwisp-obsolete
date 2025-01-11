#!/bin/bash

# --- Initialization ---

# Default values
DEFAULT_OS="$(go env GOOS)"
DEFAULT_ARCH="$(go env GOARCH)"
DEFAULT_SRC="main.go"
DEFAULT_EXEC="main"

# Variables to store values
TARGET_OS="$DEFAULT_OS"
TARGET_ARCH="$DEFAULT_ARCH"
SRC_PATH="$DEFAULT_SRC"
EXEC_PATH="$DEFAULT_EXEC"
CUSTOM_CONFIG=""  # Variable to store the custom config file path

# Acceptable values for OS and Architecture
VALID_OS="linux freebsd windows darwin"  # Add more as needed
VALID_ARCH="amd64 arm arm64"          # Add more as needed

# Function to print usage help
print_usage() {
  echo "Usage: $0 [-o os] [-a arch] [-s source] [-b binary] [-c config_file]"
  echo "  -o os          : Target operating system. Default: current OS ($(go env GOOS))."
  echo "                   Acceptable values: $VALID_OS"
  echo "  -a arch        : Target architecture. Default: current architecture ($(go env GOARCH))."
  echo "                   Acceptable values: $VALID_ARCH"
  echo "  -s source      : Source file or path. Default: ./main.go"
  echo "  -t target      : Executable binary file or path. Default: ./main"
  echo "  -c config_file : Specify a custom configuration file."
  echo "Options can appear in any order."
  echo "A 'conf.make' file in the current directory is loaded by default if it exists."
  echo "'conf.make' or custom make files can contain any of the functions that overrides default config."
  echo "A line in .make file should contain a single option flag and its value, example: '-b ./bin/main'."
  echo "Command-line arguments override 'conf.make' and any custom config file."
}

# --- Local Configuration File Parsing (conf.make) ---

if [ -f "conf.make" ]; then
  while IFS= read -r line; do
    case "$line" in
      -o\ *) TARGET_OS="${line#*-o }" ;;
      -a\ *) TARGET_ARCH="${line#*-a }" ;;
      -s\ *) SRC_PATH="${line#*-s }" ;;
      -t\ *) EXEC_PATH="${line#*-t }" ;;
      *) ;;  # Ignore lines that don't match the pattern
    esac
  done < "conf.make"
fi

# --- Argument Parsing ---

while [[ $# -gt 0 ]]; do
  key="$1"
  case $key in
    -o)
      TARGET_OS="$2"
      shift # past argument
      shift # past value
      ;;
    -a)
      TARGET_ARCH="$2"
      shift # past argument
      shift # past value
      ;;
    -s)
      SRC_PATH="$2"
      shift # past argument
      shift # past value
      ;;
    -t)
      EXEC_PATH="$2"
      shift # past argument
      shift # past value
      ;;
    -c)
      CUSTOM_CONFIG="$2"  # Store the custom config file path
      shift # past argument
      shift # past value
      ;;
    -h|--help)
      print_usage
      exit 0
      ;;
    *)
      echo "-- Error: Unknown option: $key"
      print_usage
      exit 1
      ;;
  esac
done

# --- Custom Configuration File Parsing (if specified) ---

if [ -n "$CUSTOM_CONFIG" ]; then
  if [ ! -f "$CUSTOM_CONFIG" ]; then
    echo "-- Error: Custom config file not found: $CUSTOM_CONFIG"
    exit 1
  fi

  while IFS= read -r line; do
    case "$line" in
      -o\ *) TARGET_OS="${line#*-o }" ;;
      -a\ *) TARGET_ARCH="${line#*-a }" ;;
      -s\ *) SRC_PATH="${line#*-s }" ;;
      -t\ *) EXEC_PATH="${line#*-t }" ;;
      *) ;;  # Ignore lines that don't match the pattern
    esac
  done < "$CUSTOM_CONFIG"
fi

# --- Validation ---

# Validate OS
if [[ ! " $VALID_OS " =~ " $TARGET_OS " ]]; then
  echo "-- Error: Invalid OS specified: $TARGET_OS"
  echo "   Acceptable values: $VALID_OS"
  exit 1
fi

# Validate Architecture
if [[ ! " $VALID_ARCH " =~ " $TARGET_ARCH " ]]; then
  echo "-- Error: Invalid architecture specified: $TARGET_ARCH"
  echo "   Acceptable values: $VALID_ARCH"
  exit 1
fi

# --- Compilation ---

echo "== Updating dependencies =="
go get -u ./...
go mod tidy

# Disable CGO if enabled
if [ "${CGO_ENABLED:-1}" != "0" ]; then
  echo "// Warning: CGO_ENABLED is being set to 0 for cross-compilation."
  echo "// If your program requires CGO, please modify this script."
  export CGO_ENABLED=0
fi

echo "== Compiling for ${TARGET_OS} ${TARGET_ARCH} =="
export GOOS="$TARGET_OS"
export GOARCH="$TARGET_ARCH"
go build -o "$EXEC_PATH" "$SRC_PATH"

if [ $? -eq 0 ]; then
  echo "++ Compilation successful. ${TARGET_OS} ${TARGET_ARCH} executable created at ${EXEC_PATH}"
else
  echo "-- Compilation failed for ${TARGET_OS} ${TARGET_ARCH}."
fi

# --- Cleanup ---

# Restore original environment variables
export GOOS="$ORIGINAL_GOOS"
export GOARCH="$ORIGINAL_GOARCH"
export CGO_ENABLED="$ORIGINAL_CGO_ENABLED"

echo "// Environment restored to original settings (if applicable)."
echo "== Done! =="
