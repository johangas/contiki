/*

Test application for the Contiki implementation for nRF52832

Authorizes requests to open doors from keypad application.

Written by Johan Gasslander, master thesis worker at SICS ICT Stockholm.

*/
 

//Imports
#include <stdio.h>
#include <inttypes.h>
#include "contiki.h"
#include "contiki-net.h"
#include "dev/button-sensor.h"
#include <er-coap-engine.h>
#include "er-coap-observe-client.h"
#include "dev/leds.h"


#if WITH_IPSO
#include "ipso-objects.h"
#endif

//Process handling
PROCESS(authority_process, "authority process");

//Variables
extern resource_t res_door;

//Contiki process handling
AUTOSTART_PROCESSES(
	&authority_process
);

//Reads button presses and adds to variable for LEDs
PROCESS_THREAD(authority_process, ev, data){
	PROCESS_BEGIN();
#ifdef DEBUG
	volatile unsigned int *resetreas_reg = (unsigned int*) 0x40000400;
	if(*resetreas_reg != 1){
		printf("\n Reset reason: %d \n", *resetreas_reg);
		PROCESS_WAIT_EVENT(); //This single line made things work and not crash? What is this unstable hell-machine?
	}

	*resetreas_reg = 0xF00F;
#endif
	rest_init_engine();
	

#if WITH_IPSO
	ipso_objects_init();
#endif
  	rest_activate_resource(&res_door, "doors/door");
	while(1){
		PROCESS_WAIT_EVENT();
		//wait for requests and process data
	}

	PROCESS_END();
}

