#!/bin/bash

# ITX Security Shield - Development Menu Script
# Simplified build and test management

set -e  # Exit on error

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
CYAN='\033[0;36m'
NC='\033[0m' # No Color

# Build configuration
LIB_NAME="libintegrity.so"
TEST_NAME="test_integrity"
SRC_FILES="src/integrity_check.c src/debug.c"
INCLUDE_DIR="./include"
LIBS="-lssl -lcrypto"

# Function to print colored messages
print_success() { echo -e "${GREEN}[✓]${NC} $1"; }
print_error() { echo -e "${RED}[✗]${NC} $1"; }
print_info() { echo -e "${CYAN}[i]${NC} $1"; }
print_warning() { echo -e "${YELLOW}[!]${NC} $1"; }

# Function to print section header
print_header() {
    echo -e "\n${BLUE}═══════════════════════════════════════${NC}"
    echo -e "${BLUE}  $1${NC}"
    echo -e "${BLUE}═══════════════════════════════════════${NC}\n"
}

# Function to build production version
build_production() {
    print_header "Building PRODUCTION Version"
    print_info "Compiling without debug support..."

    if gcc -shared -fPIC -o $LIB_NAME $SRC_FILES -I$INCLUDE_DIR $LIBS; then
        print_success "Library compiled: $LIB_NAME"
    else
        print_error "Library compilation failed"
        return 1
    fi

    if gcc -o $TEST_NAME test/test_main.c -I$INCLUDE_DIR -L. -lintegrity $LIBS -Wl,-rpath=.; then
        print_success "Test executable compiled: $TEST_NAME"
    else
        print_error "Test compilation failed"
        return 1
    fi

    print_success "Production build completed!"
    print_warning "Debug messages: DISABLED (compile-time)"
}

# Function to build debug version
build_debug() {
    print_header "Building DEBUG Version"
    print_info "Compiling with debug support enabled..."

    if gcc -DITX_DEBUG_ENABLED -shared -fPIC -o $LIB_NAME $SRC_FILES -I$INCLUDE_DIR $LIBS; then
        print_success "Library compiled: $LIB_NAME (with debug support)"
    else
        print_error "Library compilation failed"
        return 1
    fi

    if gcc -DITX_DEBUG_ENABLED -o $TEST_NAME test/test_main.c -I$INCLUDE_DIR -L. -lintegrity $LIBS -Wl,-rpath=.; then
        print_success "Test executable compiled: $TEST_NAME (with debug support)"
    else
        print_error "Test compilation failed"
        return 1
    fi

    print_success "Debug build completed!"
    print_info "Use ITX_DEBUG=1 to enable debug output at runtime"
}

# Function to run test
run_test() {
    local mode=$1

    if [ ! -f "$TEST_NAME" ]; then
        print_error "Test executable not found. Build first!"
        return 1
    fi

    case $mode in
        "production")
            print_header "Running Test (Production Mode)"
            print_info "No debug output expected"
            echo ""
            ./$TEST_NAME
            ;;
        "debug-on")
            print_header "Running Test (Debug Mode - ENABLED)"
            print_info "Debug output: ENABLED (ITX_DEBUG=1)"
            echo ""
            ITX_DEBUG=1 ./$TEST_NAME
            ;;
        "debug-off")
            print_header "Running Test (Debug Mode - DISABLED)"
            print_info "Debug output: DISABLED at runtime (ITX_DEBUG=0)"
            echo ""
            ITX_DEBUG=0 ./$TEST_NAME
            ;;
    esac

    echo ""
    if [ $? -eq 0 ]; then
        print_success "Test completed successfully"
    else
        print_error "Test failed"
    fi
}

# Function to clean build artifacts
clean_build() {
    print_header "Cleaning Build Artifacts"

    if [ -f "$LIB_NAME" ]; then
        rm -f $LIB_NAME
        print_success "Removed: $LIB_NAME"
    fi

    if [ -f "$TEST_NAME" ]; then
        rm -f $TEST_NAME
        print_success "Removed: $TEST_NAME"
    fi

    # Remove any .o files
    if ls *.o 1> /dev/null 2>&1; then
        rm -f *.o
        print_success "Removed: *.o files"
    fi

    print_success "Clean completed!"
}

# Function to show build info
show_info() {
    print_header "Build Information"

    echo -e "${CYAN}Library:${NC}        $LIB_NAME"
    echo -e "${CYAN}Test Executable:${NC} $TEST_NAME"
    echo -e "${CYAN}Source Files:${NC}   $SRC_FILES"
    echo -e "${CYAN}Include Dir:${NC}    $INCLUDE_DIR"
    echo -e "${CYAN}Libraries:${NC}      $LIBS"
    echo ""

    if [ -f "$LIB_NAME" ]; then
        print_success "Library exists: $LIB_NAME"
        ls -lh $LIB_NAME | awk '{print "  Size: " $5 ", Modified: " $6 " " $7 " " $8}'
    else
        print_warning "Library not found: $LIB_NAME"
    fi

    if [ -f "$TEST_NAME" ]; then
        print_success "Test exists: $TEST_NAME"
        ls -lh $TEST_NAME | awk '{print "  Size: " $5 ", Modified: " $6 " " $7 " " $8}'
    else
        print_warning "Test not found: $TEST_NAME"
    fi

    echo ""
    print_info "Check if debug symbols are present:"
    if [ -f "$LIB_NAME" ]; then
        if strings $LIB_NAME | grep -q "ITX_DEBUG_ENABLED"; then
            print_success "Library compiled with DEBUG support"
        else
            print_info "Library compiled for PRODUCTION (no debug)"
        fi
    fi
}

# Function to run all tests
run_all_tests() {
    print_header "Running ALL Test Scenarios"

    print_info "Step 1/3: Building production version..."
    build_production
    echo ""
    read -p "Press Enter to run production test..." -t 3 || true
    run_test "production"

    echo ""
    print_info "Step 2/3: Building debug version..."
    build_debug
    echo ""
    read -p "Press Enter to run debug test (enabled)..." -t 3 || true
    run_test "debug-on"

    echo ""
    print_info "Step 3/3: Testing debug runtime disable..."
    read -p "Press Enter to run debug test (disabled)..." -t 3 || true
    run_test "debug-off"

    echo ""
    print_success "All test scenarios completed!"
}

# Main menu
show_menu() {
    clear
    echo -e "${GREEN}╔═══════════════════════════════════════════╗${NC}"
    echo -e "${GREEN}║   ITX Security Shield - Dev Menu         ║${NC}"
    echo -e "${GREEN}╚═══════════════════════════════════════════╝${NC}"
    echo ""
    echo -e "${CYAN}BUILD OPTIONS:${NC}"
    echo "  1) Build Production (no debug)"
    echo "  2) Build Debug (with debug support)"
    echo ""
    echo -e "${CYAN}TEST OPTIONS:${NC}"
    echo "  3) Run Test - Production Mode"
    echo "  4) Run Test - Debug ON (ITX_DEBUG=1)"
    echo "  5) Run Test - Debug OFF (ITX_DEBUG=0)"
    echo "  6) Run ALL Tests (full cycle)"
    echo ""
    echo -e "${CYAN}UTILITIES:${NC}"
    echo "  7) Show Build Info"
    echo "  8) Clean Build Files"
    echo ""
    echo "  0) Exit"
    echo ""
    echo -n "Select option: "
}

# Main loop
main() {
    while true; do
        show_menu
        read -r choice

        case $choice in
            1) build_production ;;
            2) build_debug ;;
            3) run_test "production" ;;
            4) run_test "debug-on" ;;
            5) run_test "debug-off" ;;
            6) run_all_tests ;;
            7) show_info ;;
            8) clean_build ;;
            0)
                print_info "Goodbye!"
                exit 0
                ;;
            *)
                print_error "Invalid option. Please try again."
                ;;
        esac

        echo ""
        read -p "Press Enter to continue..." -r
    done
}

# Run main menu if no arguments provided
if [ $# -eq 0 ]; then
    main
else
    # Allow running specific commands directly
    case $1 in
        "prod"|"production") build_production ;;
        "debug") build_debug ;;
        "test") run_test "production" ;;
        "test-debug") run_test "debug-on" ;;
        "test-debug-off") run_test "debug-off" ;;
        "all") run_all_tests ;;
        "clean") clean_build ;;
        "info") show_info ;;
        *)
            echo "Usage: $0 [command]"
            echo ""
            echo "Commands:"
            echo "  prod, production    - Build production version"
            echo "  debug              - Build debug version"
            echo "  test               - Run production test"
            echo "  test-debug         - Run debug test (enabled)"
            echo "  test-debug-off     - Run debug test (disabled)"
            echo "  all                - Run all test scenarios"
            echo "  clean              - Clean build files"
            echo "  info               - Show build information"
            echo ""
            echo "Run without arguments for interactive menu."
            ;;
    esac
fi
