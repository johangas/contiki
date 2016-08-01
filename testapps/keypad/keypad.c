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
#include "contiki-net.h"
#include "er-coap-engine.h"
#include "dev/button-sensor.h"
#include "dev/leds.h"
#include "uip.h"
#include "er-coap-observe-client.h"
//#include "net/rpl/rpl.h"

#if WITH_MASTER
#include "ble-core.h"
#include "ble-mac.h"

#endif

#if WITH_IPSO
#include "ipso-objects.h"
#endif

//Defines
#if WITH_DTLS
#define COAP_PORT 	UIP_HTONS(COAP_DEFAULT_PORT)
#define REMOTE_PORT     UIP_HTONS(COAP_DEFAULT_SECURE_PORT)
#else
#define COAP_PORT 	UIP_HTONS(COAP_DEFAULT_PORT)
#define REMOTE_PORT     UIP_HTONS(COAP_DEFAULT_PORT)
#endif
#define DEBUG 1
#define DOOR_OBS_URI "doors/door"



//Process handling
PROCESS(keypad_process, "keypad process");
PROCESS(door_process, "door process");

static uip_ipaddr_t authority_addr[1];
unsigned char led = 0;
long starttime = 0;
long t= 0;

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
	//time = clock_seconds() - starttime;
	t= ((long) clock_time()) - starttime;
	printf("stoptime: %ld \n", t+ starttime);
}

static void response(void *response){
	/*//TODO: what is this do
		//USELESS
	const uint8_t *payload = NULL;
	stoptimer();
	//stop performance counter
	int len = coap_get_payload(response, &payload);
	if(len){
		//leds_set(*payload);
	} else {
		//leds_set(0);
	}
	//print round trip time	
	printf("Response: Notification from server received: %.*s Response time was %ld ms.\n", len, payload, t);
*/
}

static void callback(coap_observee_t *obst, void *notification, coap_notification_flag_t flag){
	//if authorized, shine for three seconds
	//if not authorised, blink for two seconds
	if (flag == NOTIFICATION_OK || flag == OBSERVE_OK) {
		if (notification){
			const uint8_t *payload = NULL;
			coap_get_payload(notification, &payload);
			stoptimer();
			//stop performance counter
			if(payload)
				leds_set(*payload);
			else {
				leds_set(0);
			}
			//print round trip time	
			printf("Callback: Notification from server received: %d Response time was %ld ms.\n", *payload, t*10); //Usually takes 810-900 
			
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

PROCESS_THREAD(door_process, ev, data){
	PROCESS_BEGIN();

#ifdef DEBUG
	volatile unsigned int *resetreas_reg = (unsigned int*) 0x40000400;
	if(*resetreas_reg != 1){
		printf("\n Reset reason: %d \n", *resetreas_reg);
		PROCESS_WAIT_EVENT();
	}
	*resetreas_reg = 0xF00F;
#endif
	uiplib_ipaddrconv(ADDR, authority_addr);
	uint8_t ad[16] = {0xfe, 0x80, 0, 0, 0, 0, 0, 0, 0x02, 0x25, 0x40, 0xff, 0xfe, 0xf0, 0x8b, 0xf0};
	memcpy(authority_addr->u8, ad, 16);
//	coap_init_engine();
	rest_init_engine();
#if WITH_IPSO
	ipso_objects_init();
#endif

	SENSORS_ACTIVATE(button_3);
	//clock_init();
	while(1){
		PROCESS_WAIT_EVENT();
		//observe authority and open door (set LED)
		if (data == &button_3 && button_3.value(BUTTON_SENSOR_VALUE_STATE) == 0){
			coap_obs_request_registration(NULL, authority_addr, COAP_PORT, DOOR_OBS_URI, callback, NULL);
			printf("Observing...");
		}
	}

	PROCESS_END();
}



PROCESS_THREAD(keypad_process, ev, data){
	PROCESS_BEGIN();
	SENSORS_ACTIVATE(button_1);	//auth door 1
  	SENSORS_ACTIVATE(button_2);	//not auth door 1
  	SENSORS_ACTIVATE(button_4);	//scan for auth
	
	while(1){
		PROCESS_WAIT_EVENT();
		//different button send different codes
		if (data == &button_1 && button_1.value(BUTTON_SENSOR_VALUE_STATE) == 0) {
			//POST auth1
			printf("Button 1\n");
			starttimer();
			//post_to_door(4711);
			static coap_packet_t request[1];
			coap_init_message(request, COAP_TYPE_CON, COAP_POST, 0);
			coap_set_header_uri_path(request, "/doors/door");
			coap_set_payload(request, (uint8_t *) "4711", 4);
			COAP_BLOCKING_REQUEST(&authority_addr[0], REMOTE_PORT, request, response);
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
			COAP_BLOCKING_REQUEST(&authority_addr[0], REMOTE_PORT, request, response);
			//start performance counter

		}
		#if WITH_MASTER
		if (data == &button_4 && button_4.value(BUTTON_SENSOR_VALUE_STATE) == 0) {
			
			printf("Started scanning.\n");
			ble_scan_start();
			//rpl_init();
			/*uip_ipaddr_t ipaddr;
			struct uip_ds6_addr *root_if;
  			uip_ds6_set_addr_iid(&ipaddr, &uip_lladdr);
			uip_ds6_addr_add(&ipaddr, 0, 3);
			root_if = uip_ds6_addr_lookup(&ipaddr);
			uip_ds6_neighbors_init();
			if(root_if != NULL) {
				//rpl_dag_t *dag;
				//dag = rpl_set_root(RPL_DEFAULT_INSTANCE,(uip_ip6addr_t *)&ipaddr);

				//uip_ip6addr(&ipaddr, 0xfe80, 0, 0, 0, 0x200, 0xf7ff, 0xfed1, 0xab65);

				//rpl_set_prefix(dag, &ipaddr, 64);
				printf("created a new RPL dag\n");

				//udp_bind(udp_new(NULL, UIP_HTONS(5683), NULL), UIP_HTONS(8765)); 
			} else {
				printf("failed to create a new RPL DAG\n");
  			}*/
		}
		#endif
	}

	PROCESS_END();
}

