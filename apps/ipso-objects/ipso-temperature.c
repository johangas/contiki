/*
 * Copyright (c) 2015, SICS, Swedish ICT AB.
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
 */

/**
 * \file
 *         OMA LWM2M / IPSO Temperature
 * \author
 *         Niclas Finne <nfi@sics.se>
 *         Joakim Eriksson <joakime@sics.se>
 */

#include <stdint.h>
#include "lwm2m-object.h"
#include "lwm2m-engine.h"
#include "er-coap-engine.h"

static int32_t min_temp;
static int32_t max_temp;
static int read_temp(int32_t *value);

static int
temp(lwm2m_context_t *ctx, uint8_t *outbuf, size_t outsize)
{
  int32_t value;
  if(read_temp(&value)) {
    return ctx->writer->write_float32fix(ctx, outbuf, outsize, value, 10);
  }
  return 0;
}

/*---------------------------------------------------------------------------*/
LWM2M_RESOURCES(temperature_resources,
                LWM2M_RESOURCE_CALLBACK(5700, { temp, NULL, NULL }),
		/* Temperature (Current) */
                LWM2M_RESOURCE_STRING(5701, "Celcius"),
		/* Units */
                LWM2M_RESOURCE_FLOATFIX(5603, -40 * 1024L),
		/* Min Range Value */
                LWM2M_RESOURCE_FLOATFIX(5604, 80 * 1024L),
		/* Max Range Value */
                LWM2M_RESOURCE_FLOATFIX_VAR(5601, &min_temp),
		/* Min Meas Value */
                LWM2M_RESOURCE_FLOATFIX_VAR(5602, &max_temp),
		/* Max Meas Value */
                );

LWM2M_INSTANCES(temperature_instances,
		LWM2M_INSTANCE(0, temperature_resources));
LWM2M_OBJECT(temperature, 3303, temperature_instances);
/*---------------------------------------------------------------------------*/

static int
read_temp(int32_t *value)
{
#ifdef PLATFORM_GET_TEMPERATURE
  int32_t mk = PLATFORM_GET_TEMPERATURE();
  if(mk > 0) {
    mk = mk - 273150;
    *value = (mk * 1024) / 1000;
  } else {
    return 0;
  }
#else
  /* 23.5 degrees */
  *value = 23 * 1024 + 512;
#endif

  if(*value < min_temp) {
    min_temp = *value;
    lwm2m_object_notify_observers(&temperature, "/0/5601");
  }
  if(*value > max_temp) {
    max_temp = *value;
    lwm2m_object_notify_observers(&temperature, "/0/5602");
  }
  return 1;
}


static struct ctimer periodic_timer;
static void
handle_periodic_timer(void *ptr)
{
  static int32_t last_value = -100 * 1024L;
  int32_t v;

  /* Only notify when the value has changed since last */
  if(read_temp(&v) && v != last_value) {
    last_value = v;
    lwm2m_object_notify_observers(&temperature, "/0/5700");
  }
  ctimer_reset(&periodic_timer);
}


void
ipso_temperature_init(void)
{
  int32_t v;
  min_temp = 100 * 1024L;
  max_temp = -100 * 1024L;

  /* register this device and its handlers - the handlers automatically
     sends in the object to handle */
  lwm2m_engine_register_object(&temperature);

  /* update temp and min/max + notify any listeners */
  read_temp(&v);
  ctimer_set(&periodic_timer, CLOCK_SECOND * 10, handle_periodic_timer, NULL);
}
/*---------------------------------------------------------------------------*/