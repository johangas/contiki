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
 *      Example resource
 * \author
 *      Tómas Þór Helgason based on work of
 *      Matthias Kovatsch <kovatsch@inf.ethz.ch>
 */

#include "contiki.h"

#include <string.h>
#include <math.h>
#include "rest-engine.h"
#if WITH_OPENBATTERY
#include "dev/sht21.h"
#endif

#define TEXT_PLAIN         0
#define APPLICATION_JSON   50

static void res_get_handler(void *request, void *response, uint8_t *buffer, uint16_t preferred_size, int32_t *offset);

/* A simple getter example. Returns the reading from temperature and humidity sensor */
RESOURCE(temperature,
         "title=\"Temperature and humidity status\";rt=\"SHT21 sensor\"",
         res_get_handler,
         NULL,
         NULL,
         NULL);

static void
res_get_handler(void *request, void *response, uint8_t *buffer, uint16_t preferred_size, int32_t *offset)
{
#if WITH_OPENBATTERY  
  unsigned temperature = sht21_read_temperature();
  float result = sht21_convert_temperature(temperature);
  int temp1 = result;            
  float result2 = result - temp1;
  int temp2 = trunc(result2 * 100); 
  
  unsigned humidity = sht21_read_humidity();
  float result_hum = sht21_convert_humidity(humidity);
  int hum1 = result_hum;
  float result_hum2 = result_hum - hum1;
  int hum2 = trunc(result_hum2 * 100); 

  unsigned int accept = -1;
  REST.get_header_accept(request, &accept);
  if(accept == -1 || accept == TEXT_PLAIN) {
    REST.set_header_content_type(response, TEXT_PLAIN);
    snprintf((char *)buffer, REST_MAX_CHUNK_SIZE, "%d.%02d - %d.%02d", temp1, temp2, hum1, hum2);
    REST.set_response_payload(response, (uint8_t *)buffer, strlen((char *)buffer));
    
  } else if(accept == APPLICATION_JSON) {
    REST.set_header_content_type(response, APPLICATION_JSON);
    snprintf((char *)buffer, REST_MAX_CHUNK_SIZE, "{'temperature': %d.%02d, 'humidity': %d.%02d}", temp1, temp2, hum1, hum2);
    REST.set_response_payload(response, buffer, strlen((char *)buffer));
    
  } else {
    REST.set_response_status(response, REST.status.NOT_ACCEPTABLE);
    const char *msg = "Supporting content-types text/plain and application/json";
    REST.set_response_payload(response, msg, strlen(msg));
  }
#endif
    REST.set_header_content_type(response, REST.status.NOT_ACCEPTABLE);
    snprintf((char *)buffer, REST_MAX_CHUNK_SIZE, "NOT SUPPORTED");
    REST.set_response_payload(response, (uint8_t *)buffer, strlen((char *)buffer));
}
