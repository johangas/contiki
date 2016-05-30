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
 *      Erbium (Er) REST Engine example.
 * \author
 *      Matthias Kovatsch <kovatsch@inf.ethz.ch>
 * \revision
 *      Tómas Þór Helgason
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "contiki.h"
#include "contiki-lib.h"
#include "contiki-net.h"
#include "rest-engine.h"
#include "er-coap.h"
#include "er-coap-engine.h"

#if UIP_CONF_IPV6_RPL
#include "net/rpl/rpl.h"
#endif /* UIP_CONF_IPV6_RPL */

#ifdef WITH_DTLS
#include "tinydtls.h"
#include "dtls.h"
#ifndef DTLS_LOG_DEBUG
#define DTLS_LOG_DEBUG 1
#endif
#endif

#if FLASH_CCA_CONF_BOOTLDR_BACKDOOR
#include "flash-erase.h"
#endif

#ifdef ENABLE_POWERTRACE
#include "powertrace.h"
#endif

#ifndef DEBUG
#include <stdio.h>
#define PRINTF(...) printf(__VA_ARGS__)
#define PRINT6ADDR(addr) PRINTF("[%02x%02x:%02x%02x:%02x%02x:%02x%02x:%02x%02x:%02x%02x:%02x%02x:%02x%02x]", ((uint8_t *)addr)[0], ((uint8_t *)addr)[1], ((uint8_t *)addr)[2], ((uint8_t *)addr)[3], ((uint8_t *)addr)[4], ((uint8_t *)addr)[5], ((uint8_t *)addr)[6], ((uint8_t *)addr)[7], ((uint8_t *)addr)[8], ((uint8_t *)addr)[9], ((uint8_t *)addr)[10], ((uint8_t *)addr)[11], ((uint8_t *)addr)[12], ((uint8_t *)addr)[13], ((uint8_t *)addr)[14], ((uint8_t *)addr)[15])
#define PRINTLLADDR(lladdr) PRINTF("[%02x:%02x:%02x:%02x:%02x:%02x]", (lladdr)->addr[0], (lladdr)->addr[1], (lladdr)->addr[2], (lladdr)->addr[3], (lladdr)->addr[4], (lladdr)->addr[5])
#else/*
#define PRINTF(...)
#define PRINT6ADDR(addr)
#define PRINTLLADDR(addr)*/
#endif

/*
 * Resources to be activated need to be imported through the extern keyword.
 * The build system automatically compiles the 
 * resources in the corresponding sub-directory.
 */
extern resource_t res_hello;
#if PLATFORM_HAS_LEDS
extern resource_t res_leds, res_toggle;
#endif
#if WITH_OPENBATTERY
extern resource_t temperature;
#endif



// Set security related varables and functions
/*
static struct uip_udp_conn *server_conn;

static dtls_context_t *dtls_context;


struct keymap_t { unsigned char *id; size_t id_length;
                  unsigned char *key; size_t key_length;
} psk[1] = {
    { (unsigned char *)"client_server", 13,
      (unsigned char *)"secretPSK", 9 }
};

static int
get_psk_info(struct dtls_context_t *ctx, const session_t *session,
	     dtls_credentials_type_t type,
	     const unsigned char *id, size_t id_len,
	     unsigned char *result, size_t result_length) {
    
    if (type != DTLS_PSK_KEY) return 0;
    if (id) {
        int i;
        for (i = 0; i < sizeof(psk)/sizeof(struct keymap_t); i++) {
            if (id_len == psk[i].id_length && 
                memcmp(id, psk[i].id, id_len) == 0) {
                if (result_length < psk[i].key_length) {
                    return dtls_alert_fatal_create(DTLS_ALERT_INTERNAL_ERROR);
                }
                memcpy(result, psk[i].key, psk[i].key_length);
                return psk[i].key_length;
            }
        }
    }
    return dtls_alert_fatal_create(DTLS_ALERT_DECRYPT_ERROR);
}

static const unsigned char ecdsa_priv_key[] = {
                0x02, 0xBE, 0x78, 0xA5, 0xF2, 0xCE, 0x03, 0xC1, 
                0xC0, 0x35, 0xEC, 0x71, 0xBD, 0xFD, 0x78, 0xC2, 
                0x54, 0x13, 0x35, 0x59, 0xEA, 0xF3, 0x0C, 0x27, 
                0x10, 0x81, 0xE1, 0xF3, 0xC8, 0x7E, 0x42, 0xEC };

static const unsigned char ecdsa_pub_key_x[] = {
                0x23, 0xC1, 0xD9, 0xE7, 0x62, 0x30, 0x1C, 0x96,
                0x1F, 0xAD, 0x4E, 0xAA, 0x8E, 0xB5, 0x67, 0x62,
                0xAF, 0x65, 0x71, 0x03, 0xC7, 0xD8, 0xF9, 0xE9,
                0x24, 0x33, 0xBF, 0xA9, 0xDC, 0x79, 0x02, 0x7F };

static const unsigned char ecdsa_pub_key_y[] = {
                0x84, 0x90, 0xA9, 0x8E, 0x2C, 0x88, 0xE6, 0x4D, 
                0xDE, 0x5F, 0x59, 0x1E, 0xA0, 0x4E, 0x9A, 0x71, 
                0x0D, 0x13, 0x03, 0x67, 0x79, 0x30, 0x93, 0x8E, 
                0x05, 0x47, 0x05, 0x57, 0x57, 0xBB, 0x1F, 0x67 };


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

static const unsigned char decoded_server_cert[] = {
                0x30, 0x82, 0x01, 0x11, 0x30, 0x81, 0xB9, 0x02, 
                0x09, 0x00, 0x9F, 0xC0, 0x95, 0x23, 0xD4, 0x8D, 
                0x02, 0xB8, 0x30, 0x0A, 0x06, 0x08, 0x2A, 0x86, 
                0x48, 0xCE, 0x3D, 0x04, 0x03, 0x02, 0x30, 0x12, 
                0x31, 0x10, 0x30, 0x0E, 0x06, 0x03, 0x55, 0x04, 
                0x03, 0x0C, 0x07, 0x53, 0x49, 0x43, 0x53, 0x2D, 
                0x43, 0x41, 0x30, 0x1E, 0x17, 0x0D, 0x31, 0x35, 
                0x30, 0x34, 0x32, 0x39, 0x31, 0x34, 0x30, 0x36, 
                0x33, 0x30, 0x5A, 0x17, 0x0D, 0x31, 0x36, 0x30, 
                0x34, 0x32, 0x38, 0x31, 0x34, 0x30, 0x36, 0x33, 
                0x30, 0x5A, 0x30, 0x11, 0x31, 0x0F, 0x30, 0x0D, 
                0x06, 0x03, 0x55, 0x04, 0x03, 0x0C, 0x06, 0x53, 
                0x45, 0x52, 0x56, 0x45, 0x52, 0x30, 0x59, 0x30, 
                0x13, 0x06, 0x07, 0x2A, 0x86, 0x48, 0xCE, 0x3D, 
                0x02, 0x01, 0x06, 0x08, 0x2A, 0x86, 0x48, 0xCE, 
                0x3D, 0x03, 0x01, 0x07, 0x03, 0x42, 0x00, 0x04, 
                0x23, 0xC1, 0xD9, 0xE7, 0x62, 0x30, 0x1C, 0x96, 
                0x1F, 0xAD, 0x4E, 0xAA, 0x8E, 0xB5, 0x67, 0x62, 
                0xAF, 0x65, 0x71, 0x03, 0xC7, 0xD8, 0xF9, 0xE9, 
                0x24, 0x33, 0xBF, 0xA9, 0xDC, 0x79, 0x02, 0x7F, 
                0x84, 0x90, 0xA9, 0x8E, 0x2C, 0x88, 0xE6, 0x4D, 
                0xDE, 0x5F, 0x59, 0x1E, 0xA0, 0x4E, 0x9A, 0x71, 
                0x0D, 0x13, 0x03, 0x67, 0x79, 0x30, 0x93, 0x8E, 
                0x05, 0x47, 0x05, 0x57, 0x57, 0xBB, 0x1F, 0x67, 
                0x30, 0x0A, 0x06, 0x08, 0x2A, 0x86, 0x48, 0xCE, 
                0x3D, 0x04, 0x03, 0x02, 0x03, 0x47, 0x00, 0x30, 
                0x44, 0x02, 0x20, 0x1C, 0xDC, 0x77, 0x5F, 0x8E, 
                0x35, 0x1C, 0x43, 0x59, 0x7A, 0x1D, 0x2D, 0x32, 
                0xDC, 0xFF, 0xA9, 0xE1, 0x23, 0xB4, 0x8C, 0xA8, 
                0xF7, 0x3F, 0x07, 0xEB, 0xB9, 0xE2, 0x18, 0x6E, 
                0x1F, 0x64, 0x0D, 0x02, 0x20, 0x3F, 0x7D, 0x4F, 
                0xC9, 0x2C, 0x7B, 0xA2, 0xAF, 0x83, 0xCE, 0x90, 
                0xEE, 0x96, 0xB9, 0x78, 0xD3, 0x17, 0x0E, 0x39, 
                0xE6, 0xA2, 0x30, 0x8D, 0xA1, 0x6C, 0xA7, 0x15, 
                0x95, 0xA6, 0x30, 0x39, 0x40 };

static const unsigned char ca_public_key[] = {
                0xCE, 0xA9, 0x93, 0x59, 0x39, 0x75, 0x55, 0x6F, 
                0x39, 0xA6, 0xD4, 0xB8, 0x5E, 0x1E, 0x25, 0xB6, 
                0x39, 0xA8, 0xC3, 0x77, 0xD4, 0xFD, 0x2B, 0x1B, 
                0xDA, 0x63, 0x0A, 0xB2, 0x78, 0x55, 0xF0, 0x4E, 
                0x97, 0xCE, 0xDE, 0x08, 0x2E, 0xD2, 0x13, 0xA5, 
                0x43, 0x0E, 0x2C, 0xE8, 0xBE, 0xD1, 0x76, 0xD9, 
                0x49, 0xED, 0x78, 0xE9, 0xF1, 0x4C, 0x5A, 0xC3, 
                0xD6, 0x72, 0xB0, 0xE6, 0x3C, 0x69, 0x88, 0xD7 };

static const unsigned char server_private_key[] = {
                0x02, 0xBE, 0x78, 0xA5, 0xF2, 0xCE, 0x03, 0xC1, 
                0xC0, 0x35, 0xEC, 0x71, 0xBD, 0xFD, 0x78, 0xC2, 
                0x54, 0x13, 0x35, 0x59, 0xEA, 0xF3, 0x0C, 0x27, 
                0x10, 0x81, 0xE1, 0xF3, 0xC8, 0x7E, 0x42, 0xEC };


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

  // Restore server connection to allow data from any node 
  // FIXME: do we want this at all? 
  memset(&conn->ripaddr, 0, sizeof(conn->ripaddr));
  memset(&conn->rport, 0, sizeof(conn->rport));

  return len;
}

*/

PROCESS(coap_example_server, "CoAP Example Server");

#if CONTIKI_TARGET_NATIVE
#include "border-router.h"
PROCESS_NAME(border_router_process);
PROCESS_NAME(border_router_cmd_process);
AUTOSTART_PROCESSES(&border_router_process, &border_router_cmd_process, &coap_example_server);
#elif FLASH_CCA_CONF_BOOTLDR_BACKDOOR
AUTOSTART_PROCESSES(&flash_erase_process, &coap_example_server);
#else
AUTOSTART_PROCESSES(&coap_example_server);
#endif

PROCESS_THREAD(coap_example_server, ev, data)
{
  PROCESS_BEGIN(); 
  
#if CONTIKI_TARGET_NATIVE
  border_router_set_mac((uint8_t *)&uip_lladdr.addr);
#endif
  
  /* Initialize the REST engine. */
#ifdef WITH_DTLS
  /*static dtls_handler_t cb = {
    .write = send_to_peer,
    .read  = read_from_peer,
    .event = NULL,
    .get_psk_info = get_psk_info,
    .get_ecdsa_key = get_ecdsa_key,
    .verify_ecdsa_key = verify_ecdsa_key
  };*/

  //server_conn = udp_new(NULL, 0, NULL);
  //udp_bind(server_conn, UIP_HTONS(20220));

  //dtls_set_log_level(DTLS_LOG_DEBUG);

  //dtls_context = dtls_new_context(server_conn);
  //dtls_set_handler(NULL, &cb);

#endif
  rest_init_engine();

  /*
   * Bind the resources to their Uri-Path.
   * WARNING: Activating twice only means alternate path, not two instances!
   * All static variables are the same for each URI path.
   */
  rest_activate_resource(&res_hello, "secure");
#if PLATFORM_HAS_LEDS
  rest_activate_resource(&res_leds, "actuators/leds");
  rest_activate_resource(&res_toggle, "actuators/toggle");
#endif
  
#if WITH_OPENBATTERY
  rest_activate_resource(&temperature, "test/temperature");
#endif

  /* Define application-specific events here. */
  while(1) {
    PROCESS_WAIT_EVENT();
  }                             /* while (1) */
  PROCESS_END();
}
