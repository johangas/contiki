/*

Test application for the Contiki implementation for nRF52832

Simple keypad model which communicates with a security authority, opening doors only for authorized keys.

Written by Johan Gasslander, master thesis worker at SICS ICT Stockholm

*/

//Imports
#include <stdio.h>
#include <inttypes.h>
#include "clock.h"
#include "contiki.h"
#include "er-coap-engine.h"
#include "dev/button-sensor.h"
#include "dev/leds.h"
#include "uip.h"
#include "er-coap-observe-client.h"
#include "tinydtls.h"
#include "dtls.h"

//Defines
#define COAP_PORT 	UIP_HTONS(COAP_DEFAULT_PORT)
#define REMOTE_PORT     UIP_HTONS(COAP_DEFAULT_PORT)
#define DOOR_OBS_URI "doors/door"
#define WITH_DTLS 1

//Process handling
PROCESS(keypad_process, "keypad process");
PROCESS(door_process, "door process");

static uip_ipaddr_t authority_addr[1];
unsigned char led = 0;
long starttime = 0;
long stoptime = 0;

AUTOSTART_PROCESSES(
	&door_process,
	&keypad_process
);

//TODO: increase accuracy
void starttimer(){
	//starttime = clock_seconds();
	starttime = (long) clock_time();
	printf("starttime: %ld \n", starttime);
}

void stoptimer(){
	//stoptime = clock_seconds() - starttime;
	stoptime = ((long) clock_time()) - starttime;
	printf("stoptime: %ld \n", stoptime + starttime);
}

static void response(void *response){
	const uint8_t *payload = NULL;
	coap_get_payload(response, &payload);
	stoptimer();
	//stop performance counter
	leds_set(*payload);
	printf("%x\n",*payload);
	
	//print round trip time	
	printf("Response: Notification from server received: %d Response time was %ld ms.\n", *payload, stoptime);
}

static void callback(coap_observee_t *obst, void *notification, coap_notification_flag_t flag){
	//if authorized, shine for three seconds
	//if not authorised, blink for two seconds
	if (flag == NOTIFICATION_OK || flag == OBSERVE_OK) {
		if (notification){
			const uint8_t *payload = NULL;
			coap_get_payload(notification, &payload);
			//stoptimer();
			//stop performance counter
			/*if(*payload != '0')
				leds_set(*payload);
			else {
				leds_set(0);
			}*/
			//print round trip time	
			//printf("Callback: Notification from server received: %d Response time was %ld ms.\n", *payload, stoptime);
			
		}
	}
}

/*void post_to_door(int value){
	static coap_packet_t request[1];
			coap_init_message(request, COAP_TYPE_CON, COAP_POST, 0);
			coap_set_header_uri_path(request, "/doors/door");
			char str[4];
			sprintf(str, "%d", value);
			coap_set_payload(request, (uint8_t *) str, sizeof(str) - 1);
			COAP_BLOCKING_REQUEST(&authority_addr[0], REMOTE_PORT, request, response);
}*/

/*
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
    printf("%c", data[i]);
  return 0;
}

static int
send_to_peer(struct dtls_context_t *ctx, 
	     session_t *session, uint8 *data, size_t len) {

  struct uip_udp_conn *conn = (struct uip_udp_conn *)dtls_get_app_data(ctx);

  uip_ipaddr_copy(&conn->ripaddr, &session->addr);
  conn->rport = session->port;

  printf("send to ");
  printf(":%u\n", uip_ntohs(conn->rport));

  uip_udp_packet_send(conn, data, len);

  // Restore server connection to allow data from any node 
  // FIXME: do we want this at all? 
  memset(&conn->ripaddr, 0, sizeof(conn->ripaddr));
  memset(&conn->rport, 0, sizeof(conn->rport));

  return len;
}
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
}*/


PROCESS_THREAD(door_process, ev, data){
	PROCESS_BEGIN();

	/*volatile unsigned int *resetreas_reg = (unsigned int*) 0x40000400;
	if(*resetreas_reg != 1)	
		printf("\n Reset reason: %d \n", *resetreas_reg);
	*resetreas_reg = 0xF00F;
	*/
	uiplib_ipaddrconv(ADDR, authority_addr);
	printf("Server addr: %s\n", ADDR);
	
	/*static session_t session;
	uip_ipaddr_copy(&session.addr, authority_addr);
	session.port = REMOTE_PORT;
	session.size = sizeof(session.addr) + sizeof(session.port);
	session.ifindex = 1;
*/
	//dtls_init();

	coap_init_engine();

	//SENSORS_ACTIVATE(button_3);
	//clock_init();
	/*static dtls_handler_t cb = {
    		.write = send_to_peer,
    		.read  = read_from_peer,
    		.event = event,
    		.get_psk_info = get_psk_info,
	    	.get_ecdsa_key = get_ecdsa_key,
    		.verify_ecdsa_key = verify_ecdsa_key
  		};
	dtls_set_handler(NULL, &cb);
	coap_register_as_transaction_handler();*/
	//while(1){
		//PROCESS_WAIT_EVENT();
		//observe authority and open door (set LED)
	//	if (data == &button_3 && button_3.value(BUTTON_SENSOR_VALUE_STATE) == 0){
			coap_obs_request_registration(authority_addr, COAP_PORT, DOOR_OBS_URI, callback, NULL);
			printf("Observing...");
	//	}
	//}

	PROCESS_END();
}

session_t session;
static struct uip_udp_conn *server_conn;

PROCESS_THREAD(keypad_process, ev, data){
	PROCESS_BEGIN();
	//SENSORS_ACTIVATE(button_1);	//auth door 1
  	//SENSORS_ACTIVATE(button_2);	//not auth door 1
	printf("keypad process\n");
//	static struct etimer et_print;
//	etimer_set(&et_print, CLOCK_SECOND);
	while(1){
		PROCESS_WAIT_EVENT();
	/*	//while(!connected)
		//	PROCESS_PAUSE();
		//different button send different codes
		if (data == &button_1 && button_1.value(BUTTON_SENSOR_VALUE_STATE) == 0) {			
			//POST auth1
			printf("Button 1\n");
			starttimer();
			//post_to_door(4711);
	*/		static coap_packet_t request[1];
			coap_init_message(request, COAP_TYPE_CON, COAP_POST, 0);
			printf("init message\n");
			coap_set_header_uri_path(request, "/doors/door");
			printf("set header\n");
			coap_set_payload(request, (uint8_t *) "4711", 4);
			printf("set payload\n");
			//FIXME
			server_conn = uip_udp_new(&authority_addr[0], 5683);
			udp_bind(server_conn, UIP_HTONS(5684));
			session.port = 5683;
		 	session.size = sizeof(session.addr) + sizeof(session.port);
			COAP_BLOCKING_REQUEST(&authority_addr[0], REMOTE_PORT, request, response, dtls_new_context(server_conn), &session);
			printf("blocking request\n");
			//start performance counter
	/*		
		}
		if (data == &button_2 && button_2.value(BUTTON_SENSOR_VALUE_STATE) == 0) {
			//POST auth2 - not authorized
			printf("Button 2\n");
			starttimer();
			//post_to_door(3342);
			static coap_packet_t request[1];
			coap_init_message(request, COAP_TYPE_CON, COAP_POST, 0);
			coap_set_header_uri_path(request, "/doors/door");
			coap_set_payload(request, (uint8_t *) "1234", 4);
			COAP_BLOCKING_REQUEST(&authority_addr[0], REMOTE_PORT, request, response, NULL, NULL);
			//start performance counter

		}
	*/	
	}
	
	PROCESS_END();
}

