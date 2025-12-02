#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <ctype.h>
#include <errno.h>
#include <sys/ptrace.h>
#include <openssl/sha.h>
#include "integrity_check.h"
#include "debug.h"

// Read file into buffer
static int read_file(const char *path, char *buffer, size_t size) {
    DEBUG_LOG("Reading file: %s", path);
    FILE *fp = fopen(path, "r");
    if (!fp) {
        DEBUG_WARN("Failed to open file: %s (errno: %d - %s)", path, errno, strerror(errno));
        return ITX_ERROR;
    }

    if (fgets(buffer, size, fp)) {
        buffer[strcspn(buffer, "\n")] = 0;  // Remove newline
        fclose(fp);
        DEBUG_LOG("Successfully read from %s: %s", path, buffer);
        return ITX_OK;
    }

    fclose(fp);
    DEBUG_ERROR("Failed to read content from: %s (empty or read error)", path);
    return ITX_ERROR;
}

// Get machine-id
static int read_machine_id(char *buffer, size_t size) {
    if (read_file("/etc/machine-id", buffer, size) == ITX_OK) {
        return ITX_OK;
    }
    return read_file("/var/lib/dbus/machine-id", buffer, size);
}

// Get CPU model
static int read_cpu_model(char *buffer, size_t size) {
    DEBUG_LOG("Reading CPU model from /proc/cpuinfo");
    FILE *fp = fopen("/proc/cpuinfo", "r");
    if (!fp) {
        DEBUG_ERROR("Failed to open /proc/cpuinfo (errno: %d - %s)", errno, strerror(errno));
        return ITX_ERROR;
    }

    char line[512];
    while (fgets(line, sizeof(line), fp)) {
        if (strncmp(line, "model name", 10) == 0) {
            char *colon = strchr(line, ':');
            if (colon) {
                colon += 2; // Skip ": "
                strncpy(buffer, colon, size - 1);
                buffer[size - 1] = '\0';  // Ensure null termination
                buffer[strcspn(buffer, "\n")] = 0;
                fclose(fp);
                DEBUG_LOG("CPU model found: %s", buffer);
                return ITX_OK;
            }
        }
    }

    fclose(fp);
    DEBUG_ERROR("CPU model not found in /proc/cpuinfo");
    return ITX_ERROR;
}

// Get CPU core count
static int get_cpu_cores() {
    DEBUG_LOG("Counting CPU cores from /proc/cpuinfo");
    FILE *fp = fopen("/proc/cpuinfo", "r");
    if (!fp) {
        DEBUG_ERROR("Failed to open /proc/cpuinfo for core count (errno: %d - %s)", errno, strerror(errno));
        return -1;  // Return -1 to indicate error (0 cores is impossible)
    }

    int cores = 0;
    char line[256];
    while (fgets(line, sizeof(line), fp)) {
        if (strncmp(line, "processor", 9) == 0) {
            cores++;
        }
    }

    fclose(fp);

    if (cores == 0) {
        DEBUG_WARN("No processor entries found in /proc/cpuinfo");
        return -1;
    }

    DEBUG_LOG("CPU cores detected: %d", cores);
    return cores;
}

// Get MAC address (first non-loopback interface)
static int read_mac_address(char *buffer, size_t size) {
    DEBUG_LOG("Reading MAC address from /sys/class/net");
    FILE *fp = popen("cat /sys/class/net/*/address 2>/dev/null | grep -v '00:00:00:00:00:00' | head -1", "r");
    if (!fp) {
        DEBUG_ERROR("Failed to execute popen for MAC address (errno: %d - %s)", errno, strerror(errno));
        return ITX_ERROR;
    }

    if (fgets(buffer, size, fp)) {
        buffer[strcspn(buffer, "\n")] = 0;
        pclose(fp);
        if (strlen(buffer) > 0) {
            DEBUG_LOG("MAC address found: %s", buffer);
            return ITX_OK;
        }
    }

    pclose(fp);
    DEBUG_ERROR("No valid MAC address found (no network interfaces or all are loopback)");
    return ITX_ERROR;
}

// Get DMI UUID (SMBIOS UUID)
static int read_dmi_uuid(char *buffer, size_t size) {
    // Try product_uuid first (requires root or permissions)
    if (read_file("/sys/class/dmi/id/product_uuid", buffer, size) == ITX_OK) {
        return ITX_OK;
    }
    
    // Fallback: try board_serial
    if (read_file("/sys/class/dmi/id/board_serial", buffer, size) == ITX_OK) {
        return ITX_OK;
    }
    
    // Fallback: use product_name + board_vendor
    char product[128] = {0};
    char vendor[128] = {0};
    
    read_file("/sys/class/dmi/id/product_name", product, sizeof(product));
    read_file("/sys/class/dmi/id/board_vendor", vendor, sizeof(vendor));
    
    if (strlen(product) > 0 || strlen(vendor) > 0) {
        snprintf(buffer, size, "%s-%s", vendor, product);
        return ITX_OK;
    }
    
    return ITX_ERROR;
}

// Get disk UUID (root filesystem)
static int read_disk_uuid(char *buffer, size_t size) {
    DEBUG_LOG("Reading root filesystem UUID using findmnt");
    FILE *fp = popen("findmnt -no UUID / 2>/dev/null", "r");
    if (!fp) {
        DEBUG_ERROR("Failed to execute findmnt for disk UUID (errno: %d - %s)", errno, strerror(errno));
        return ITX_ERROR;
    }

    if (fgets(buffer, size, fp)) {
        buffer[strcspn(buffer, "\n")] = 0;
        pclose(fp);
        if (strlen(buffer) > 0) {
            DEBUG_LOG("Disk UUID found: %s", buffer);
            return ITX_OK;
        }
    }

    pclose(fp);
    DEBUG_ERROR("Disk UUID not found (root filesystem may not have UUID or findmnt not available)");
    return ITX_ERROR;
}

// Check if running in Docker
int itx_is_docker() {
    DEBUG_LOG("Checking Docker environment");

    // Method 1: Check /.dockerenv
    if (access("/.dockerenv", F_OK) == 0) {
        DEBUG_LOG("Docker detected: /.dockerenv exists");
        return 1;
    }

    // Method 2: Check /proc/1/cgroup
    FILE *fp = fopen("/proc/1/cgroup", "r");
    if (fp) {
        char buffer[256];
        while (fgets(buffer, sizeof(buffer), fp)) {
            if (strstr(buffer, "docker") || strstr(buffer, "containerd")) {
                fclose(fp);
                DEBUG_LOG("Docker detected: found in /proc/1/cgroup");
                return 1;
            }
        }
        fclose(fp);
    }

    DEBUG_LOG("Docker NOT detected");
    return 0;
}

// Check if running in VM
int itx_is_vm() {
    DEBUG_LOG("Checking VM environment");

    // Check DMI system manufacturer
    char manufacturer[128] = {0};

    if (read_file("/sys/class/dmi/id/sys_vendor", manufacturer, sizeof(manufacturer)) == ITX_OK) {
        // Convert to lowercase for comparison
        for (int i = 0; manufacturer[i]; i++) {
            manufacturer[i] = tolower(manufacturer[i]);
        }

        DEBUG_LOG("System vendor: %s", manufacturer);

        if (strstr(manufacturer, "vmware") ||
            strstr(manufacturer, "virtualbox") ||
            strstr(manufacturer, "qemu") ||
            strstr(manufacturer, "kvm") ||
            strstr(manufacturer, "microsoft") ||
            strstr(manufacturer, "xen")) {
            DEBUG_LOG("VM detected: vendor match");
            return 1;
        }
    }

    // Check CPU flags for hypervisor
    FILE *fp = fopen("/proc/cpuinfo", "r");
    if (fp) {
        char line[512];
        while (fgets(line, sizeof(line), fp)) {
            if (strncmp(line, "flags", 5) == 0) {
                if (strstr(line, "hypervisor")) {
                    fclose(fp);
                    DEBUG_LOG("VM detected: hypervisor flag in CPU");
                    return 1;
                }
                break;
            }
        }
        fclose(fp);
    }

    DEBUG_LOG("VM NOT detected");
    return 0;
}

// Check for debugger
int itx_is_debugger() {
    DEBUG_LOG("Checking for debugger");

    // Check TracerPid in /proc/self/status
    FILE *fp = fopen("/proc/self/status", "r");
    if (fp) {
        char buffer[256];
        while (fgets(buffer, sizeof(buffer), fp)) {
            if (strncmp(buffer, "TracerPid:", 10) == 0) {
                int pid = atoi(buffer + 10);
                fclose(fp);
                if (pid != 0) {
                    DEBUG_WARN("Debugger detected! TracerPid: %d", pid);
                    return 1;
                }
                DEBUG_LOG("No debugger detected");
                return 0;
            }
        }
        fclose(fp);
    }

    DEBUG_LOG("Could not check debugger status");
    return 0;
}

// Get hardware info
int itx_get_hardware_info(itx_hardware_info_t *info) {
    DEBUG_INIT();
    DEBUG_LOG("Starting hardware info collection");

    if (!info) {
        DEBUG_ERROR("NULL pointer passed to itx_get_hardware_info");
        return ITX_ERROR;
    }

    memset(info, 0, sizeof(itx_hardware_info_t));

    // Machine ID
    if (read_machine_id(info->machine_id, sizeof(info->machine_id)) != ITX_OK) {
        DEBUG_WARN("Machine ID unavailable - using 'unknown' (may affect fingerprint uniqueness)");
        strcpy(info->machine_id, "unknown");
    }
    DEBUG_LOG("Machine ID: %s", info->machine_id);

    // CPU Model
    if (read_cpu_model(info->cpu_model, sizeof(info->cpu_model)) != ITX_OK) {
        DEBUG_WARN("CPU model unavailable - using 'unknown' (may affect fingerprint uniqueness)");
        strcpy(info->cpu_model, "unknown");
    }
    DEBUG_LOG("CPU Model: %s", info->cpu_model);

    // CPU Cores
    info->cpu_cores = get_cpu_cores();
    if (info->cpu_cores < 0) {
        DEBUG_WARN("CPU core count unavailable, setting to 0");
        info->cpu_cores = 0;
    }
    DEBUG_LOG("CPU Cores: %d", info->cpu_cores);

    // MAC Address
    if (read_mac_address(info->mac_address, sizeof(info->mac_address)) != ITX_OK) {
        DEBUG_WARN("MAC address unavailable - using 'unknown' (may affect fingerprint uniqueness)");
        strcpy(info->mac_address, "unknown");
    }
    DEBUG_LOG("MAC Address: %s", info->mac_address);

    // DMI UUID
    if (read_dmi_uuid(info->dmi_uuid, sizeof(info->dmi_uuid)) != ITX_OK) {
        DEBUG_WARN("DMI UUID unavailable - using 'unknown' (may affect fingerprint uniqueness)");
        strcpy(info->dmi_uuid, "unknown");
    }
    DEBUG_LOG("DMI UUID: %s", info->dmi_uuid);

    // Disk UUID
    if (read_disk_uuid(info->disk_uuid, sizeof(info->disk_uuid)) != ITX_OK) {
        DEBUG_WARN("Disk UUID unavailable - using 'unknown' (may affect fingerprint uniqueness)");
        strcpy(info->disk_uuid, "unknown");
    }
    DEBUG_LOG("Disk UUID: %s", info->disk_uuid);

    // Docker detection
    info->is_docker = (itx_is_docker() == 1);
    DEBUG_LOG("Docker: %s", info->is_docker ? "YES" : "NO");

    // VM detection
    info->is_vm = (itx_is_vm() == 1);
    DEBUG_LOG("VM: %s", info->is_vm ? "YES" : "NO");

    // Debugger detection
    info->debugger_detected = (itx_is_debugger() == 1);
    DEBUG_LOG("Debugger: %s", info->debugger_detected ? "YES" : "NO");

    DEBUG_LOG("Hardware info collection completed successfully");
    return ITX_OK;
}

// Generate fingerprint
char* itx_get_fingerprint() {
    DEBUG_INIT();
    DEBUG_LOG("Starting fingerprint generation");

    static char fingerprint[FINGERPRINT_SIZE];
    itx_hardware_info_t info;

    if (itx_get_hardware_info(&info) != ITX_OK) {
        DEBUG_ERROR("Failed to get hardware info");
        return NULL;
    }

    // Combine all hardware info
    char combined[2048];
    snprintf(combined, sizeof(combined),
             "%s|%s|%s|%s|%s|%d",
             info.machine_id,
             info.mac_address,
             info.dmi_uuid,
             info.disk_uuid,
             info.cpu_model,
             info.cpu_cores);

    DEBUG_LOG("Combined hardware string length: %zu bytes", strlen(combined));

    // SHA-256 hash
    unsigned char hash[SHA256_DIGEST_LENGTH];
    SHA256((unsigned char*)combined, strlen(combined), hash);

    DEBUG_LOG("SHA-256 hash computed");
    DEBUG_DUMP_HEX(hash, SHA256_DIGEST_LENGTH);

    // Convert to hex
    for(int i = 0; i < SHA256_DIGEST_LENGTH; i++) {
        sprintf(fingerprint + (i * 2), "%02x", hash[i]);
    }
    fingerprint[64] = '\0';

    DEBUG_LOG("Final fingerprint: %s", fingerprint);
    return fingerprint;
}