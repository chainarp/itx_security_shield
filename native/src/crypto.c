#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <openssl/pem.h>
#include <openssl/rsa.h>
#include <openssl/evp.h>
#include <openssl/err.h>
#include <openssl/sha.h>
#include <sys/stat.h>
#include "integrity_check.h"

// Load public key from file (Dev mode)
static EVP_PKEY* load_public_key() {
    FILE *fp = fopen("keys/public_dev.pem", "r");
    if (!fp) {
        fprintf(stderr, "Cannot open keys/public_dev.pem\n");
        return NULL;
    }
    
    EVP_PKEY *pkey = PEM_read_PUBKEY(fp, NULL, NULL, NULL);
    fclose(fp);
    
    if (!pkey) {
        ERR_print_errors_fp(stderr);
    }
    
    return pkey;
}

// Read private key from file
static EVP_PKEY* load_private_key(const char *path, const char *passphrase) {
    FILE *fp = fopen(path, "r");
    if (!fp) {
        fprintf(stderr, "Cannot open private key: %s\n", path);
        return NULL;
    }
    
    EVP_PKEY *pkey = PEM_read_PrivateKey(fp, NULL, NULL, (void*)passphrase);
    fclose(fp);
    
    if (!pkey) {
        ERR_print_errors_fp(stderr);
    }
    
    return pkey;
}

// Sign data with private key
int itx_sign_data(const char *data, size_t data_len,
                  const char *private_key_path,
                  const char *passphrase,
                  unsigned char **signature, size_t *sig_len) {
    
    EVP_PKEY *pkey = load_private_key(private_key_path, passphrase);
    if (!pkey) return ITX_ERROR;
    
    EVP_MD_CTX *ctx = EVP_MD_CTX_new();
    if (!ctx) {
        EVP_PKEY_free(pkey);
        return ITX_ERROR;
    }
    
    // Initialize signing
    if (EVP_DigestSignInit(ctx, NULL, EVP_sha256(), NULL, pkey) != 1) {
        EVP_MD_CTX_free(ctx);
        EVP_PKEY_free(pkey);
        return ITX_ERROR;
    }
    
    // Update with data
    if (EVP_DigestSignUpdate(ctx, data, data_len) != 1) {
        EVP_MD_CTX_free(ctx);
        EVP_PKEY_free(pkey);
        return ITX_ERROR;
    }
    
    // Get signature length
    size_t req_len = 0;
    if (EVP_DigestSignFinal(ctx, NULL, &req_len) != 1) {
        EVP_MD_CTX_free(ctx);
        EVP_PKEY_free(pkey);
        return ITX_ERROR;
    }
    
    // Allocate signature buffer
    *signature = malloc(req_len);
    if (!*signature) {
        EVP_MD_CTX_free(ctx);
        EVP_PKEY_free(pkey);
        return ITX_ERROR;
    }
    
    // Get signature
    *sig_len = req_len;
    if (EVP_DigestSignFinal(ctx, *signature, sig_len) != 1) {
        free(*signature);
        EVP_MD_CTX_free(ctx);
        EVP_PKEY_free(pkey);
        return ITX_ERROR;
    }
    
    EVP_MD_CTX_free(ctx);
    EVP_PKEY_free(pkey);
    
    return ITX_OK;
}

// Verify signature with public key
int itx_verify_signature(const char *data, size_t data_len,
                         const unsigned char *signature, size_t sig_len) {
    
    EVP_PKEY *pkey = load_public_key();
    if (!pkey) return ITX_ERROR;
    
    EVP_MD_CTX *ctx = EVP_MD_CTX_new();
    if (!ctx) {
        EVP_PKEY_free(pkey);
        return ITX_ERROR;
    }
    
    // Initialize verification
    if (EVP_DigestVerifyInit(ctx, NULL, EVP_sha256(), NULL, pkey) != 1) {
        EVP_MD_CTX_free(ctx);
        EVP_PKEY_free(pkey);
        return ITX_ERROR;
    }
    
    // Update with data
    if (EVP_DigestVerifyUpdate(ctx, data, data_len) != 1) {
        EVP_MD_CTX_free(ctx);
        EVP_PKEY_free(pkey);
        return ITX_ERROR;
    }
    
    // Verify signature
    int result = EVP_DigestVerifyFinal(ctx, signature, sig_len);
    
    EVP_MD_CTX_free(ctx);
    EVP_PKEY_free(pkey);
    
    return (result == 1) ? ITX_OK : ITX_ERROR;
}

// Encrypt and sign license - UPDATED with all fields
int itx_encrypt_license(const itx_license_data_t *license,
                       const char *private_key_path,
                       const char *passphrase,
                       const char *output_file) {
    
    // Serialize license data with ALL fields
    char data[4096];
    snprintf(data, sizeof(data),
             "customer=%s\n"
             "hardware_fp=%s\n"
             "machine_id=%s\n"
             "mac_address=%s\n"
             "dmi_uuid=%s\n"
             "disk_uuid=%s\n"
             "cpu_model=%s\n"
             "cpu_cores=%d\n"
             "expiry=%s\n"
             "users=%d\n"
             "timestamp=%lu",
             license->customer_name,
             license->hardware_fingerprint,
             license->machine_id,
             license->mac_address,
             license->dmi_uuid,
             license->disk_uuid,
             license->cpu_model,
             license->cpu_cores,
             license->expiry_date,
             license->max_users,
             license->created_timestamp);
    
    // Sign the data
    unsigned char *signature = NULL;
    size_t sig_len = 0;
    
    if (itx_sign_data(data, strlen(data), private_key_path, 
                      passphrase, &signature, &sig_len) != ITX_OK) {
        return ITX_ERROR;
    }
    
    // Write to file
    FILE *fp = fopen(output_file, "wb");
    if (!fp) {
        free(signature);
        return ITX_ERROR;
    }
    
    // Header
    fwrite("ITXS", 4, 1, fp);  // Magic
    uint32_t version = 1;
    fwrite(&version, sizeof(version), 1, fp);
    
    // Data length
    uint32_t data_len = strlen(data);
    fwrite(&data_len, sizeof(data_len), 1, fp);
    
    // Data
    fwrite(data, data_len, 1, fp);
    
    // Signature length
    uint32_t sig_len_32 = sig_len;
    fwrite(&sig_len_32, sizeof(sig_len_32), 1, fp);
    
    // Signature
    fwrite(signature, sig_len, 1, fp);
    
    fclose(fp);
    free(signature);
    
    // Set permissions to 400 (owner read-only)
    // chmod(output_file, S_IRUSR);

    // Set permissions to 600 (owner read/write)
    chmod(output_file, S_IRUSR | S_IWUSR);
    
    return ITX_OK;
}

// Decrypt and verify license - UPDATED to parse all fields
int itx_decrypt_license(const char *input_file,
                       itx_license_data_t *license) {
    
    FILE *fp = fopen(input_file, "rb");
    if (!fp) return ITX_ERROR;
    
    // Read header
    char magic[5] = {0};
    fread(magic, 4, 1, fp);
    if (strcmp(magic, "ITXS") != 0) {
        fclose(fp);
        return ITX_ERROR;
    }
    
    uint32_t version;
    fread(&version, sizeof(version), 1, fp);
    
    // Read data
    uint32_t data_len;
    fread(&data_len, sizeof(data_len), 1, fp);
    
    char *data = malloc(data_len + 1);
    if (!data) {
        fclose(fp);
        return ITX_ERROR;
    }
    fread(data, data_len, 1, fp);
    data[data_len] = '\0';
    
    // Read signature
    uint32_t sig_len;
    fread(&sig_len, sizeof(sig_len), 1, fp);
    
    unsigned char *signature = malloc(sig_len);
    if (!signature) {
        free(data);
        fclose(fp);
        return ITX_ERROR;
    }
    fread(signature, sig_len, 1, fp);
    
    fclose(fp);
    
    // Verify signature
    if (itx_verify_signature(data, data_len, signature, sig_len) != ITX_OK) {
        free(data);
        free(signature);
        return ITX_ERROR;
    }
    
    // Parse data with ALL fields
    sscanf(data, 
           "customer=%[^\n]\n"
           "hardware_fp=%[^\n]\n"
           "machine_id=%[^\n]\n"
           "mac_address=%[^\n]\n"
           "dmi_uuid=%[^\n]\n"
           "disk_uuid=%[^\n]\n"
           "cpu_model=%[^\n]\n"
           "cpu_cores=%d\n"
           "expiry=%[^\n]\n"
           "users=%d\n"
           "timestamp=%lu",
           license->customer_name,
           license->hardware_fingerprint,
           license->machine_id,
           license->mac_address,
           license->dmi_uuid,
           license->disk_uuid,
           license->cpu_model,
           &license->cpu_cores,
           license->expiry_date,
           &license->max_users,
           &license->created_timestamp);
    
    free(data);
    free(signature);
    
    return ITX_OK;
}

// Verify hardware match - HYBRID approach with field-by-field comparison
int itx_verify_hardware_match(const char *license_file, 
                              itx_verify_result_t *result) {
    
    // Initialize result
    if (result) {
        memset(result, 0, sizeof(itx_verify_result_t));
        result->result = ITX_ERROR;
    }
    
    // 1. Load license
    itx_license_data_t license;
    if (itx_decrypt_license(license_file, &license) != ITX_OK) {
        if (result) {
            strcpy(result->message, "Invalid license file or signature verification failed");
        }
        return ITX_ERROR;
    }
    
    // 2. Get current hardware info
    itx_hardware_info_t current;
    if (itx_get_hardware_info(&current) != ITX_OK) {
        if (result) {
            strcpy(result->message, "Failed to read current hardware information");
        }
        return ITX_ERROR;
    }
    
    // 3. Get current fingerprint
    char *current_fp = itx_get_fingerprint();
    if (!current_fp) {
        if (result) {
            strcpy(result->message, "Failed to generate current fingerprint");
        }
        return ITX_ERROR;
    }
    
    // 4. HYBRID: Compare both fingerprint AND individual fields
    bool machine_match = (strcmp(license.machine_id, current.machine_id) == 0);
    bool mac_match = (strcmp(license.mac_address, current.mac_address) == 0);
    bool dmi_match = (strcmp(license.dmi_uuid, current.dmi_uuid) == 0);
    bool disk_match = (strcmp(license.disk_uuid, current.disk_uuid) == 0);
    bool fp_match = (strcmp(license.hardware_fingerprint, current_fp) == 0);
    
    if (result) {
        result->machine_id_match = machine_match;
        result->mac_match = mac_match;
        result->dmi_match = dmi_match;
        result->disk_match = disk_match;
        result->fingerprint_match = fp_match;
    }
    
    // 5. Perfect match - all fields identical
    if (fp_match && machine_match && mac_match && dmi_match && disk_match) {
        if (result) {
            result->result = ITX_OK;
            strcpy(result->message, "✅ Hardware verification passed - all fields match perfectly");
        }
        return ITX_OK;
    }
    
    // 6. Build detailed mismatch report
    char details[1024];
    int mismatches = 0;
    
    strcpy(details, "⚠️  Hardware mismatch detected:\n\n");
    
    if (!machine_match) {
        strcat(details, "  ❌ Machine ID changed\n");
        mismatches++;
    } else {
        strcat(details, "  ✅ Machine ID: OK\n");
    }
    
    if (!mac_match) {
        strcat(details, "  ⚠️  MAC Address changed (network card replaced?)\n");
        mismatches++;
    } else {
        strcat(details, "  ✅ MAC Address: OK\n");
    }
    
    if (!dmi_match) {
        strcat(details, "  ❌ DMI UUID changed (motherboard/VM clone?)\n");
        mismatches++;
    } else {
        strcat(details, "  ✅ DMI UUID: OK\n");
    }
    
    if (!disk_match) {
        strcat(details, "  ❌ Disk UUID changed (disk replaced/cloned?)\n");
        mismatches++;
    } else {
        strcat(details, "  ✅ Disk UUID: OK\n");
    }
    
    if (!fp_match) {
        strcat(details, "  ❌ Overall fingerprint mismatch\n");
    }
    
    char summary[256];
    snprintf(summary, sizeof(summary), 
             "\n%d field(s) changed. This may indicate:\n"
             "- System cloned to different hardware\n"
             "- Hardware components replaced\n"
             "- VM migration\n",
             mismatches);
    strcat(details, summary);
    
    if (result) {
        strcpy(result->message, details);
        result->result = ITX_HARDWARE_MISMATCH;
    }
    
    return ITX_HARDWARE_MISMATCH;
}