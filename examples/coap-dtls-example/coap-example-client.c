/*
 * Copyright (c) 2013, Institute for Pervasive Computing, ETH Zurich
 * All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 * 1. Redistributions of source code must retain the above copyright
 *    notice, this list of conditions and the following disclaimer.
 * 2. Redistributions in binary form must reproduce the above copyright
 *    notice, this list of conditions and the following disclaimer in the
 *    documentation and/or other materials provided with the distribution.
 * 3. Neither the name of the Institute nor the names of its contributors
 *    may be used to endorse or promote products derived from this software
 *    without specific prior written permission.
 *
 * THIS SOFTWARE IS PROVIDED BY THE INSTITUTE AND CONTRIBUTORS ``AS IS'' AND
 * ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
 * IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
 * ARE DISCLAIMED.  IN NO EVENT SHALL THE INSTITUTE OR CONTRIBUTORS BE LIABLE
 * FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL
 * DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS
 * OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION)
 * HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT
 * LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY
 * OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF
 * SUCH DAMAGE.
 *
 * This file is part of the Contiki operating system.
 */

/**
 * \file
 *      Erbium (Er) CoAP client example.
 * \author
 *      Matthias Kovatsch <kovatsch@inf.ethz.ch>
 * \revision
 *      Tómas Þór Helgason
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "contiki.h"
#include "contiki-net.h"
#include "er-coap-engine.h"


#ifdef WITH_DTLS
#include "tinydtls.h"
#include "dtls.h"
#endif

#if FLASH_CCA_CONF_BOOTLDR_BACKDOOR
#include "flash-erase.h"
#endif

#define DEBUG 1
#if DEBUG
#include <stdio.h>
#define PRINTF(...) printf(__VA_ARGS__)
#define PRINT6ADDR(addr) PRINTF("[%02x%02x:%02x%02x:%02x%02x:%02x%02x:%02x%02x:%02x%02x:%02x%02x:%02x%02x]", ((uint8_t *)addr)[0], ((uint8_t *)addr)[1], ((uint8_t *)addr)[2], ((uint8_t *)addr)[3], ((uint8_t *)addr)[4], ((uint8_t *)addr)[5], ((uint8_t *)addr)[6], ((uint8_t *)addr)[7], ((uint8_t *)addr)[8], ((uint8_t *)addr)[9], ((uint8_t *)addr)[10], ((uint8_t *)addr)[11], ((uint8_t *)addr)[12], ((uint8_t *)addr)[13], ((uint8_t *)addr)[14], ((uint8_t *)addr)[15])
#define PRINTLLADDR(lladdr) PRINTF("[%02x:%02x:%02x:%02x:%02x:%02x]", (lladdr)->addr[0], (lladdr)->addr[1], (lladdr)->addr[2], (lladdr)->addr[3], (lladdr)->addr[4], (lladdr)->addr[5])
#else
#define PRINTF(...)
#define PRINT6ADDR(addr)
#define PRINTLLADDR(addr)
#endif

/* FIXME: This server address is hard-coded */
#if CONTIKI_TARGET_NATIVE
#define SET_SERVER_ADDRESS(ipaddr)   uip_ip6addr(ipaddr,0xaaaa,0,0,0,0,0,0,0x0001)
#else
#define SET_SERVER_ADDRESS(ipaddr)   uip_ip6addr(ipaddr,0x2001,0xdb8,0,0,0x0225,0x40ff,0xfef0,0x8bf0)
//#define SET_SERVER_ADDRESS(ipaddr)   uip_ip6addr(ipaddr,0xaaaa,0,0,0,0,0,0,0x0001)
#endif

#ifdef WITH_DTLS
#define REMOTE_PORT     UIP_HTONS(COAP_DEFAULT_PORT + 1)
#else
#define REMOTE_PORT     UIP_HTONS(COAP_DEFAULT_PORT)
#endif

#define TOGGLE_INTERVAL 15
#define LESHAN 0

// Set security related varables and functions
#ifdef WITH_DTLS

//static struct uip_udp_conn *server_conn;

//static dtls_context_t *dtls_context;
//#if SECURITY_MODE == 1
#define PSK_ID_LEN 13
#define PSK_KEY_LEN 9
unsigned char psk_id[PSK_ID_LEN] = "client_server";
unsigned char psk_key[PSK_KEY_LEN] = "secretPSK";

static int
get_psk_info(struct dtls_context_t *ctx, const session_t *session,
	     dtls_credentials_type_t type,
	     const unsigned char *id, size_t id_len,
	     unsigned char *result, size_t result_length) {    
    switch (type) {
        case DTLS_PSK_IDENTITY:
            if (result_length < PSK_ID_LEN) {
              return dtls_alert_fatal_create(DTLS_ALERT_INTERNAL_ERROR);
            }
            memcpy(result, psk_id, PSK_ID_LEN);
            return PSK_ID_LEN;
        case DTLS_PSK_KEY:
            if (id_len != PSK_ID_LEN || memcmp(psk_id, id, id_len) != 0) {
              return dtls_alert_fatal_create(DTLS_ALERT_ILLEGAL_PARAMETER);
            } else if (result_length < PSK_KEY_LEN) {
              return dtls_alert_fatal_create(DTLS_ALERT_INTERNAL_ERROR);
            }
            memcpy(result, psk_key, PSK_KEY_LEN);
            return PSK_KEY_LEN;
        default:
            return dtls_alert_fatal_create(DTLS_ALERT_INTERNAL_ERROR);
    }    
}

/*#elif SECURITY_MODE == 2
static const unsigned char ecdsa_priv_key[] = {
                0xDC, 0x80, 0xE3, 0xFB, 0x27, 0x54, 0x89, 0x77,
                0x8B, 0x4B, 0x95, 0x43, 0x36, 0x4A, 0x0A, 0x48, 
                0x15, 0xB7, 0x17, 0x9B, 0x73, 0x66, 0xE7, 0x45,
                0x4C, 0xFF, 0xE7, 0x63, 0x86, 0x71, 0xB8, 0xF9 };

static const unsigned char ecdsa_pub_key_x[] = {
                0x87, 0x7D, 0x6D, 0xDF, 0x9E, 0x6D, 0x75, 0x3C,
                0x8A, 0xEF, 0xA9, 0x0B, 0x3A, 0x5C, 0x6B, 0xA1,
                0xEB, 0xD1, 0xAB, 0x04, 0x1B, 0x68, 0x04, 0x6A,
                0x59, 0x6A, 0x18, 0x9E, 0x9D, 0xC8, 0xFD, 0xD0 };

static const unsigned char ecdsa_pub_key_y[] = {
                0x70, 0x99, 0xC7, 0x58, 0xF1, 0xB1, 0x9E, 0x44,
                0x16, 0x94, 0xFB, 0xE0, 0x00, 0x1C, 0x15, 0x7A,
                0xEF, 0x5D, 0xBD, 0x8E, 0x62, 0x63, 0x43, 0x78,
                0x72, 0xAE, 0x22, 0xFB, 0x55, 0x81, 0x2F, 0xC8 };

static int
get_ecdsa_key(struct dtls_context_t *ctx,
	      const session_t *session,
	      const dtls_ecdsa_key_t **result) {
  static const dtls_ecdsa_key_t ecdsa_key = {
    .curve = DTLS_ECDH_CURVE_SECP256R1,
    .priv_key = ecdsa_priv_key,
    .pub_key_x = ecdsa_pub_key_x,
    .pub_key_y = ecdsa_pub_key_y,
    .ca_id = (unsigned char *) "SICS-CA",
    .ca_id_length = 7
  };

  *result = &ecdsa_key;
  return 0;
}

static int
verify_ecdsa_key(struct dtls_context_t *ctx,
		 const session_t *session,
		 const unsigned char *other_pub_x,
		 const unsigned char *other_pub_y,
		 size_t key_size) {
  return 0;
}

//#elif (SECURITY_MODE == 3 || SECURITY_MODE == 4)
static const unsigned char decoded_client_cert[] = {
                0x30, 0x82, 0x01, 0x12, 0x30, 0x81, 0xB9, 0x02, 
                0x09, 0x00, 0x9F, 0xC0, 0x95, 0x23, 0xD4, 0x8D, 
                0x02, 0xB9, 0x30, 0x0A, 0x06, 0x08, 0x2A, 0x86, 
                0x48, 0xCE, 0x3D, 0x04, 0x03, 0x02, 0x30, 0x12, 
                0x31, 0x10, 0x30, 0x0E, 0x06, 0x03, 0x55, 0x04, 
                0x03, 0x0C, 0x07, 0x53, 0x49, 0x43, 0x53, 0x2D, 
                0x43, 0x41, 0x30, 0x1E, 0x17, 0x0D, 0x31, 0x35, 
                0x30, 0x34, 0x32, 0x39, 0x31, 0x34, 0x30, 0x38, 
                0x33, 0x32, 0x5A, 0x17, 0x0D, 0x31, 0x36, 0x30, 
                0x34, 0x32, 0x38, 0x31, 0x34, 0x30, 0x38, 0x33, 
                0x32, 0x5A, 0x30, 0x11, 0x31, 0x0F, 0x30, 0x0D, 
                0x06, 0x03, 0x55, 0x04, 0x03, 0x0C, 0x06, 0x43, 
                0x4C, 0x49, 0x45, 0x4E, 0x54, 0x30, 0x59, 0x30, 
                0x13, 0x06, 0x07, 0x2A, 0x86, 0x48, 0xCE, 0x3D, 
                0x02, 0x01, 0x06, 0x08, 0x2A, 0x86, 0x48, 0xCE, 
                0x3D, 0x03, 0x01, 0x07, 0x03, 0x42, 0x00, 0x04, 
                0x87, 0x7D, 0x6D, 0xDF, 0x9E, 0x6D, 0x75, 0x3C, 
                0x8A, 0xEF, 0xA9, 0x0B, 0x3A, 0x5C, 0x6B, 0xA1, 
                0xEB, 0xD1, 0xAB, 0x04, 0x1B, 0x68, 0x04, 0x6A, 
                0x59, 0x6A, 0x18, 0x9E, 0x9D, 0xC8, 0xFD, 0xD0, 
                0x70, 0x99, 0xC7, 0x58, 0xF1, 0xB1, 0x9E, 0x44, 
                0x16, 0x94, 0xFB, 0xE0, 0x00, 0x1C, 0x15, 0x7A, 
                0xEF, 0x5D, 0xBD, 0x8E, 0x62, 0x63, 0x43, 0x78, 
                0x72, 0xAE, 0x22, 0xFB, 0x55, 0x81, 0x2F, 0xC8, 
                0x30, 0x0A, 0x06, 0x08, 0x2A, 0x86, 0x48, 0xCE, 
                0x3D, 0x04, 0x03, 0x02, 0x03, 0x48, 0x00, 0x30, 
                0x45, 0x02, 0x21, 0x00, 0xE6, 0x55, 0x0B, 0xA5, 
                0xC4, 0x57, 0xB2, 0x9C, 0x0F, 0x9F, 0xFC, 0x93, 
                0x4F, 0x68, 0xFF, 0x87, 0x91, 0x49, 0xBE, 0x4F, 
                0x44, 0x0E, 0x25, 0x36, 0xE1, 0x4E, 0x35, 0xA0, 
                0xC1, 0x28, 0xB2, 0xDA, 0x02, 0x20, 0x6B, 0xD4, 
                0xED, 0xFF, 0x1F, 0xE2, 0x3B, 0x6D, 0x28, 0xDE, 
                0x81, 0x8B, 0xE5, 0xF4, 0x0B, 0x1A, 0x28, 0x73, 
                0x69, 0xF5, 0x25, 0x19, 0x0B, 0xD5, 0xB4, 0x81, 
                0x4D, 0xA9, 0x3D, 0xFC, 0xFF, 0x0E };

static const unsigned char ca_public_key[] = {
                0xCE, 0xA9, 0x93, 0x59, 0x39, 0x75, 0x55, 0x6F, 
                0x39, 0xA6, 0xD4, 0xB8, 0x5E, 0x1E, 0x25, 0xB6, 
                0x39, 0xA8, 0xC3, 0x77, 0xD4, 0xFD, 0x2B, 0x1B, 
                0xDA, 0x63, 0x0A, 0xB2, 0x78, 0x55, 0xF0, 0x4E, 
                0x97, 0xCE, 0xDE, 0x08, 0x2E, 0xD2, 0x13, 0xA5, 
                0x43, 0x0E, 0x2C, 0xE8, 0xBE, 0xD1, 0x76, 0xD9, 
                0x49, 0xED, 0x78, 0xE9, 0xF1, 0x4C, 0x5A, 0xC3, 
                0xD6, 0x72, 0xB0, 0xE6, 0x3C, 0x69, 0x88, 0xD7 };

static const unsigned char client_private_key[] = {
                0xDC, 0x80, 0xE3, 0xFB, 0x27, 0x54, 0x89, 0x77, 
                0x8B, 0x4B, 0x95, 0x43, 0x36, 0x4A, 0x0A, 0x48, 
                0x15, 0xB7, 0x17, 0x9B, 0x73, 0x66, 0xE7, 0x45, 
                0x4C, 0xFF, 0xE7, 0x63, 0x86, 0x71, 0xB8, 0xF9 };

static int 
get_ecdsa_certificate(struct dtls_context_t *ctx, 
                      const session_t *session,
                      const dtls_ecdsa_certificate_t **result) {
    static const dtls_ecdsa_certificate_t certificate = {
        .priv_key = client_private_key,
        .certificate = decoded_client_cert,
        .certificate_length = sizeof(decoded_client_cert)
    };
    *result = &certificate;
    return 0;
}

static int 
get_ca_info(struct dtls_context_t *ctx, 
            const session_t *session,
            const dtls_ca_info_t **result) {
    static const dtls_ca_info_t ca_info = {
        .ca_id = (unsigned char *) "SICS-CA",
        .ca_id_length = 7,
        .ca_public_key = ca_public_key
    };
    *result = &ca_info;
    return 0;
}*/
//#elif SECURITY_MODE == 10
/*
#define PSK_ID_LEN 13
#define PSK_KEY_LEN 9
unsigned char psk_id[PSK_ID_LEN] = "client_server";
unsigned char psk_key[PSK_KEY_LEN] = "secretPSK";*/
/*
static int
get_psk_info(struct dtls_context_t *ctx, const session_t *session,
	     dtls_credentials_type_t type,
	     const unsigned char *id, size_t id_len,
	     unsigned char *result, size_t result_length) {    
    switch (type) {
        case DTLS_PSK_IDENTITY:
            if (result_length < PSK_ID_LEN) {
              return dtls_alert_fatal_create(DTLS_ALERT_INTERNAL_ERROR);
            }
            memcpy(result, psk_id, PSK_ID_LEN);
            return PSK_ID_LEN;
        case DTLS_PSK_KEY:
            if (id_len != PSK_ID_LEN || memcmp(psk_id, id, id_len) != 0) {
              return dtls_alert_fatal_create(DTLS_ALERT_ILLEGAL_PARAMETER);
            } else if (result_length < PSK_KEY_LEN) {
              return dtls_alert_fatal_create(DTLS_ALERT_INTERNAL_ERROR);
            }
            memcpy(result, psk_key, PSK_KEY_LEN);
            return PSK_KEY_LEN;
        default:
            return dtls_alert_fatal_create(DTLS_ALERT_INTERNAL_ERROR);
    }    
}
*/
static const unsigned char ecdsa_priv_key[] = {
                0xDC, 0x80, 0xE3, 0xFB, 0x27, 0x54, 0x89, 0x77,
                0x8B, 0x4B, 0x95, 0x43, 0x36, 0x4A, 0x0A, 0x48, 
                0x15, 0xB7, 0x17, 0x9B, 0x73, 0x66, 0xE7, 0x45,
                0x4C, 0xFF, 0xE7, 0x63, 0x86, 0x71, 0xB8, 0xF9 };

static const unsigned char ecdsa_pub_key_x[] = {
                0x87, 0x7D, 0x6D, 0xDF, 0x9E, 0x6D, 0x75, 0x3C,
                0x8A, 0xEF, 0xA9, 0x0B, 0x3A, 0x5C, 0x6B, 0xA1,
                0xEB, 0xD1, 0xAB, 0x04, 0x1B, 0x68, 0x04, 0x6A,
                0x59, 0x6A, 0x18, 0x9E, 0x9D, 0xC8, 0xFD, 0xD0 };

static const unsigned char ecdsa_pub_key_y[] = {
                0x70, 0x99, 0xC7, 0x58, 0xF1, 0xB1, 0x9E, 0x44,
                0x16, 0x94, 0xFB, 0xE0, 0x00, 0x1C, 0x15, 0x7A,
                0xEF, 0x5D, 0xBD, 0x8E, 0x62, 0x63, 0x43, 0x78,
                0x72, 0xAE, 0x22, 0xFB, 0x55, 0x81, 0x2F, 0xC8 };
/*
static int
get_ecdsa_key(struct dtls_context_t *ctx,
	      const session_t *session,
	      const dtls_ecdsa_key_t **result) {
  static const dtls_ecdsa_key_t ecdsa_key = {
    .curve = DTLS_ECDH_CURVE_SECP256R1,
    .priv_key = ecdsa_priv_key,
    .pub_key_x = ecdsa_pub_key_x,
    .pub_key_y = ecdsa_pub_key_y,
    .ca_id = (unsigned char *) "SICS-CA",
    .ca_id_length = 7
  };

  *result = &ecdsa_key;
  return 0;
}

static int
verify_ecdsa_key(struct dtls_context_t *ctx,
		 const session_t *session,
		 const unsigned char *other_pub_x,
		 const unsigned char *other_pub_y,
		 size_t key_size) {
  return 0;
}

static const unsigned char decoded_client_cert[] = {
                0x30, 0x82, 0x01, 0x12, 0x30, 0x81, 0xB9, 0x02, 
                0x09, 0x00, 0x9F, 0xC0, 0x95, 0x23, 0xD4, 0x8D, 
                0x02, 0xB9, 0x30, 0x0A, 0x06, 0x08, 0x2A, 0x86, 
                0x48, 0xCE, 0x3D, 0x04, 0x03, 0x02, 0x30, 0x12, 
                0x31, 0x10, 0x30, 0x0E, 0x06, 0x03, 0x55, 0x04, 
                0x03, 0x0C, 0x07, 0x53, 0x49, 0x43, 0x53, 0x2D, 
                0x43, 0x41, 0x30, 0x1E, 0x17, 0x0D, 0x31, 0x35, 
                0x30, 0x34, 0x32, 0x39, 0x31, 0x34, 0x30, 0x38, 
                0x33, 0x32, 0x5A, 0x17, 0x0D, 0x31, 0x36, 0x30, 
                0x34, 0x32, 0x38, 0x31, 0x34, 0x30, 0x38, 0x33, 
                0x32, 0x5A, 0x30, 0x11, 0x31, 0x0F, 0x30, 0x0D, 
                0x06, 0x03, 0x55, 0x04, 0x03, 0x0C, 0x06, 0x43, 
                0x4C, 0x49, 0x45, 0x4E, 0x54, 0x30, 0x59, 0x30, 
                0x13, 0x06, 0x07, 0x2A, 0x86, 0x48, 0xCE, 0x3D, 
                0x02, 0x01, 0x06, 0x08, 0x2A, 0x86, 0x48, 0xCE, 
                0x3D, 0x03, 0x01, 0x07, 0x03, 0x42, 0x00, 0x04, 
                0x87, 0x7D, 0x6D, 0xDF, 0x9E, 0x6D, 0x75, 0x3C, 
                0x8A, 0xEF, 0xA9, 0x0B, 0x3A, 0x5C, 0x6B, 0xA1, 
                0xEB, 0xD1, 0xAB, 0x04, 0x1B, 0x68, 0x04, 0x6A, 
                0x59, 0x6A, 0x18, 0x9E, 0x9D, 0xC8, 0xFD, 0xD0, 
                0x70, 0x99, 0xC7, 0x58, 0xF1, 0xB1, 0x9E, 0x44, 
                0x16, 0x94, 0xFB, 0xE0, 0x00, 0x1C, 0x15, 0x7A, 
                0xEF, 0x5D, 0xBD, 0x8E, 0x62, 0x63, 0x43, 0x78, 
                0x72, 0xAE, 0x22, 0xFB, 0x55, 0x81, 0x2F, 0xC8, 
                0x30, 0x0A, 0x06, 0x08, 0x2A, 0x86, 0x48, 0xCE, 
                0x3D, 0x04, 0x03, 0x02, 0x03, 0x48, 0x00, 0x30, 
                0x45, 0x02, 0x21, 0x00, 0xE6, 0x55, 0x0B, 0xA5, 
                0xC4, 0x57, 0xB2, 0x9C, 0x0F, 0x9F, 0xFC, 0x93, 
                0x4F, 0x68, 0xFF, 0x87, 0x91, 0x49, 0xBE, 0x4F, 
                0x44, 0x0E, 0x25, 0x36, 0xE1, 0x4E, 0x35, 0xA0, 
                0xC1, 0x28, 0xB2, 0xDA, 0x02, 0x20, 0x6B, 0xD4, 
                0xED, 0xFF, 0x1F, 0xE2, 0x3B, 0x6D, 0x28, 0xDE, 
                0x81, 0x8B, 0xE5, 0xF4, 0x0B, 0x1A, 0x28, 0x73, 
                0x69, 0xF5, 0x25, 0x19, 0x0B, 0xD5, 0xB4, 0x81, 
                0x4D, 0xA9, 0x3D, 0xFC, 0xFF, 0x0E };

static const unsigned char ca_public_key[] = {
                0xCE, 0xA9, 0x93, 0x59, 0x39, 0x75, 0x55, 0x6F, 
                0x39, 0xA6, 0xD4, 0xB8, 0x5E, 0x1E, 0x25, 0xB6, 
                0x39, 0xA8, 0xC3, 0x77, 0xD4, 0xFD, 0x2B, 0x1B, 
                0xDA, 0x63, 0x0A, 0xB2, 0x78, 0x55, 0xF0, 0x4E, 
                0x97, 0xCE, 0xDE, 0x08, 0x2E, 0xD2, 0x13, 0xA5, 
                0x43, 0x0E, 0x2C, 0xE8, 0xBE, 0xD1, 0x76, 0xD9, 
                0x49, 0xED, 0x78, 0xE9, 0xF1, 0x4C, 0x5A, 0xC3, 
                0xD6, 0x72, 0xB0, 0xE6, 0x3C, 0x69, 0x88, 0xD7 };

static const unsigned char client_private_key[] = {
                0xDC, 0x80, 0xE3, 0xFB, 0x27, 0x54, 0x89, 0x77, 
                0x8B, 0x4B, 0x95, 0x43, 0x36, 0x4A, 0x0A, 0x48, 
                0x15, 0xB7, 0x17, 0x9B, 0x73, 0x66, 0xE7, 0x45, 
                0x4C, 0xFF, 0xE7, 0x63, 0x86, 0x71, 0xB8, 0xF9 };

static int 
get_ecdsa_certificate(struct dtls_context_t *ctx, 
                      const session_t *session,
                      const dtls_ecdsa_certificate_t **result) {
    static const dtls_ecdsa_certificate_t certificate = {
        .priv_key = client_private_key,
        .certificate = decoded_client_cert,
        .certificate_length = sizeof(decoded_client_cert)
    };
    *result = &certificate;
    return 0;
}

static int 
get_ca_info(struct dtls_context_t *ctx, 
            const session_t *session,
            const dtls_ca_info_t **result) {
    static const dtls_ca_info_t ca_info = {
        .ca_id = (unsigned char *) "SICS-CA",
        .ca_id_length = 7,
        .ca_public_key = ca_public_key
    };
    *result = &ca_info;
    return 0;
}
*/
//#endif

static int connected = 0;
static int
event(struct dtls_context_t *ctx, session_t *session, 
		dtls_alert_level_t level, unsigned short code){
    if(code == DTLS_EVENT_CONNECTED){
       connected = 1;
    }
    if(code == DTLS_EVENT_CONNECT){
       connected = 0;
    }
    return 0;
}
#endif

PROCESS(coap_example_client, "CoAP Example Client");

/*#if CONTIKI_TARGET_NATIVE
#include "border-router.h"
PROCESS_NAME(border_router_process);
PROCESS_NAME(border_router_cmd_process);
AUTOSTART_PROCESSES(&border_router_process, &border_router_cmd_process, &coap_example_client);
#elif FLASH_CCA_CONF_BOOTLDR_BACKDOOR
AUTOSTART_PROCESSES(&flash_erase_process, &coap_example_client);
#else*/
AUTOSTART_PROCESSES(&coap_example_client);
//#endif


uip_ipaddr_t server_ipaddr;
static struct etimer et;
/* Example URIs that can be queried. */
#define NUMBER_OF_URLS 4
#define NUMBER_OF_QUERY 4
/* leading and ending slashes only for demo purposes, get cropped automatically when setting the Uri-Path */
char *service_urls[NUMBER_OF_URLS] = { ".well-known/core", "/actuators/toggle", "/actuators/leds", "/secure"};
char *service_query[NUMBER_OF_QUERY] = { "?color=r", "?color=o", "?color=y", "?color=g"};

/* This function is will be passed to COAP_BLOCKING_REQUEST() to handle responses. */
void
client_chunk_handler(void *response)
{
  const uint8_t *chunk;
  int len = coap_get_payload(response, &chunk);
  printf("|%.*s\n", len, (char *)chunk);
}

static int
get_ecdsa_key(struct dtls_context_t *ctx,
	      const session_t *session,
	      const dtls_ecdsa_key_t **result) {
  static const dtls_ecdsa_key_t ecdsa_key = {
    .curve = DTLS_ECDH_CURVE_SECP256R1,
    .priv_key = ecdsa_priv_key,
    .pub_key_x = ecdsa_pub_key_x,
    .pub_key_y = ecdsa_pub_key_y
  };

  *result = &ecdsa_key;
  return 0;
}

static int
verify_ecdsa_key(struct dtls_context_t *ctx,
		 const session_t *session,
		 const unsigned char *other_pub_x,
		 const unsigned char *other_pub_y,
		 size_t key_size) {
  return 0;
}

static int
read_from_peer(struct dtls_context_t *ctx, 
	       session_t *session, uint8 *data, size_t len) {
  size_t i;
  for (i = 0; i < len; i++)
    PRINTF("%c", data[i]);
  return 0;
}

static int
send_to_peer(struct dtls_context_t *ctx, 
	     session_t *session, uint8 *data, size_t len) {

  struct uip_udp_conn *conn = (struct uip_udp_conn *)dtls_get_app_data(ctx);

  uip_ipaddr_copy(&conn->ripaddr, &session->addr);
  conn->rport = session->port;

  PRINTF("send to ");
  PRINT6ADDR(&conn->ripaddr);
  PRINTF(":%u\n", uip_ntohs(conn->rport));

  uip_udp_packet_send(conn, data, len);

  /* Restore server connection to allow data from any node */
  /* FIXME: do we want this at all? */
  memset(&conn->ripaddr, 0, sizeof(conn->ripaddr));
  memset(&conn->rport, 0, sizeof(conn->rport));

  return len;
}

PROCESS_THREAD(coap_example_client, ev, data)
{
  PROCESS_BEGIN();
 volatile unsigned int *resetreas_reg = (unsigned int*) 0x40000400;
 printf("Started Reset reason: %d \n", *resetreas_reg);
 *resetreas_reg = 0xF00F;
  
  static coap_packet_t request[1];      /* This way the packet can be treated as pointer as usual. */
  //SET_SERVER_ADDRESS(&server_ipaddr);
  //uiplib_ipaddrconv(ADDR, server_ipaddr);
  coap_init_engine();
  /* Initialize the CoAP */
 

#ifdef WITH_DTLS
 static session_t session;
  uip_ipaddr_copy(&session.addr, &server_ipaddr);
  session.port = REMOTE_PORT;
  session.size = sizeof(session.addr) + sizeof(session.port);
  session.ifindex = 1;
  static dtls_handler_t cb = {
    .write = send_to_peer,
    .read  = read_from_peer,
    .event = event,
    .get_psk_info = get_psk_info,
    .get_ecdsa_key = get_ecdsa_key,
    .verify_ecdsa_key = verify_ecdsa_key
  };

  //server_conn = udp_new(NULL, 0, NULL);
  //udp_bind(server_conn, UIP_HTONS(20220));
//#if SECURITY_MODE == 1
  //printf("DTLS Security mode 1: PSK\n"); 
  //dtls_set_handler(event, get_psk_info);
  dtls_set_handler(NULL, &cb);
/*#elif SECURITY_MODE == 2
  printf("DTLS Security mode 2: RPK\n"); 
  dtls_set_handler(event, verify_ecdsa_key, get_ecdsa_key);
#elif SECURITY_MODE == 3
  printf("DTLS Security mode 3: CERT\n"); 
  dtls_set_handler(event, NULL, NULL, get_ca_info, get_ecdsa_certificate);
#elif SECURITY_MODE == 4
  printf("DTLS Security mode 3: CERT no client\n"); 
  dtls_set_handler(event, NULL, NULL, get_ca_info, NULL);
#elif SECURITY_MODE == 10
  printf("DTLS Security mode ALL!\n"); 
  dtls_set_handler(event, get_psk_info, verify_ecdsa_key, get_ecdsa_key, get_ca_info, get_ecdsa_certificate);
#endif*/

#endif

  etimer_set(&et, TOGGLE_INTERVAL * CLOCK_SECOND);
  static int round = 0;
  
  while(1) {
    PROCESS_YIELD();
    
    if(etimer_expired(&et)) {
	printf("timer expired\n");
#ifdef WITH_DTLS      
      if (!connected){
         dtls_connect(NULL, &session);
	 printf("connect\n");
      } else {
#endif          
/*#if LESHAN
        printf("Registering lwm2m endpoint\n");
        
        coap_init_message(request, COAP_TYPE_CON, COAP_POST, round);
        coap_set_header_uri_path(request, "/rd");
#if SECURITY_MODE == 1
        coap_set_header_uri_query(request, "?ep=test-client-psk");
#elif SECURITY_MODE == 2
        coap_set_header_uri_query(request, "?ep=test-client-rpk");
#endif
        const char msg[] = "</3>,</3303/0>";
        coap_set_payload(request, (uint8_t *)msg, sizeof(msg) - 1);
        COAP_BLOCKING_REQUEST(&server_ipaddr, REMOTE_PORT, request, client_chunk_handler);
#else*/
        printf("--Toggle LEDS--\n");
        coap_init_message(request, COAP_TYPE_CON, COAP_POST, 0);
	printf("sending post\n");
        if(round > 3){
            coap_set_header_uri_path(request, service_urls[1]);
            round = 0;
        } else {
            coap_set_header_uri_path(request, service_urls[2]);
            coap_set_header_uri_query(request, service_query[round]);
            const char msg[] = "mode=on";
            coap_set_payload(request, (uint8_t *)msg, sizeof(msg) - 1);
            round++;
        }
        COAP_BLOCKING_REQUEST(&server_ipaddr, REMOTE_PORT, request, client_chunk_handler);
//#endif
        printf("\n--Done--\n");
#ifdef WITH_DTLS  
	coap_init_message(request, COAP_TYPE_CON, COAP_GET, 0);
	printf("sending get\n");
        coap_set_header_uri_path(request, service_urls[3]);
	COAP_BLOCKING_REQUEST(&server_ipaddr, REMOTE_PORT, request, client_chunk_handler);
      }
#endif
      etimer_reset(&et);
    }
  }
  PROCESS_END();
}
