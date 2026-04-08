#ifndef VLT_TLS_CONFIG_H
#define VLT_TLS_CONFIG_H

#ifdef __cplusplus
extern "C" {
#endif

/* VaultIC configuration */

/* Definition of VaultIC resources */
#define I2C_BITRATE     400     //400kHz
#define I2C_ADDRESS     0x5F

#define SELF_TESTS_DELAY        200 // 200ms
#define APDU_TIMEOUT            5000 // 5s

#define INITIAL_PAIRING_KEY { 0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0A, 0x0B, 0x0C, 0x0D, 0x0E, 0x0F,\
                              0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17, 0x18, 0x19, 0x1A, 0x1B, 0x1C, 0x1D, 0x1E, 0x1F }

// Device Certificate
#define REC_ID_DEVICE_CERT  1    // device certificate stored in rec 1 of binary area
#define REC_ID_CA_CERT      2    // CA certificate stored in rec 2 of binary area

// Definition of default key index values used by vaultic_tls
// NOTE: the key indexes can be set using vlt_tls_select_static_priv_key() and vlt_tls_select_ephemeral_priv_key func()
#define STATIC_KEY_INDEX    0x00    // Index of default static key pair in VaultIC
#define EPH_KEY_KEY_INDEX   0x00    // Index of default ephemeral key pair in VaultIC

//VAULT-IC KEYS INDEX
#define  VAULTIC_FACTORY_KEY_INDEX    0x00
#define  VAULTIC_OPERATIONAL_KEY_INDEX    0x01

//VAULT-IC CERT INDEX
#define  VAULTIC_FACTORY_CERT_INDEX    0x00


#endif /* VLT_TLS_CONFIG_H */
