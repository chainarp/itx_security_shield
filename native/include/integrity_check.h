#ifndef INTEGRITY_CHECK_H
#define INTEGRITY_CHECK_H

#include <stdint.h>
#include <stdbool.h>

// Hardware fingerprint (64 chars hex = 32 bytes SHA-256)
#define FINGERPRINT_SIZE 65

// Return codes
#define ITX_OK 0
#define ITX_ERROR -1
#define ITX_HARDWARE_MISMATCH -2

// Hardware fingerprint result
typedef struct {
    char fingerprint[FINGERPRINT_SIZE];
    char machine_id[128];
    char cpu_model[256];
    char mac_address[32];
    char dmi_uuid[128];
    char disk_uuid[128];
    int cpu_cores;
    bool is_docker;
    bool is_vm;
    bool debugger_detected;
} itx_hardware_info_t;

// License data structure - UPDATED with individual fields
typedef struct {
    char customer_name[256];
    char hardware_fingerprint[FINGERPRINT_SIZE];  // Hash for quick check
    
    // Individual hardware fields for detailed comparison
    char machine_id[128];
    char mac_address[32];
    char dmi_uuid[128];
    char disk_uuid[128];
    char cpu_model[256];
    int cpu_cores;
    
    char expiry_date[32];
    int max_users;
    uint64_t created_timestamp;
} itx_license_data_t;

// Verification result with details
typedef struct {
    int result;  // ITX_OK, ITX_ERROR, ITX_HARDWARE_MISMATCH
    char message[1024];
    bool machine_id_match;
    bool mac_match;
    bool dmi_match;
    bool disk_match;
    bool fingerprint_match;
} itx_verify_result_t;

// Hardware detection functions
int itx_get_hardware_info(itx_hardware_info_t *info);
int itx_is_docker();
int itx_is_vm();
int itx_is_debugger();
char* itx_get_fingerprint();

// Crypto functions
int itx_sign_data(const char *data, size_t data_len, 
                  const char *private_key_path, 
                  const char *passphrase,
                  unsigned char **signature, size_t *sig_len);

int itx_verify_signature(const char *data, size_t data_len,
                         const unsigned char *signature, size_t sig_len);

int itx_encrypt_license(const itx_license_data_t *license,
                       const char *private_key_path,
                       const char *passphrase,
                       const char *output_file);

int itx_decrypt_license(const char *input_file,
                       itx_license_data_t *license);

// Verification functions
int itx_verify_hardware_match(const char *license_file, 
                              itx_verify_result_t *result);

#endif // INTEGRITY_CHECK_H