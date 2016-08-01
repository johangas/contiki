/*
 * Copyright (c) 2015, Nordic Semiconductor
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
 */
/**
 * \addtogroup cpu
 * @{
 *
 * \addtogroup nrf52832
 * @{
 *
 * \addtogroup nrf52832-ble Bluetooth Low Energy drivers
 * @{
 *
 * \file
 *         Basic BLE functions.
 * \author
 *         Wojciech Bober <wojciech.bober@nordicsemi.no>
 *         Johan Gasslander <johangas@kth.se>
 *
 */
#include <stdbool.h>
#include <stdint.h>
#include "boards.h"
#include "nordic_common.h"
#include "nrf_delay.h"
#include "nrf_sdm.h"
#include "ble_advdata.h"
#include "ble_srv_common.h"
#include "ble_ipsp.h"
#include "softdevice_handler.h"
#include "app_error.h"
#include "iot_defines.h"
#include "ble-core.h"
#include "net/linkaddr.h"
#include "net/packetbuf.h"


#define DEBUG 1
#if DEBUG
#include <stdio.h>
#define PRINTF(...) printf(__VA_ARGS__)
#else
#define PRINTF(...)
#endif

#define IS_SRVC_CHANGED_CHARACT_PRESENT 1
#define APP_ADV_TIMEOUT                 0                                  /**< Time for which the device must be advertising in non-connectable mode (in seconds). 0 disables timeout. */
#define APP_ADV_ADV_INTERVAL            MSEC_TO_UNITS(333, UNIT_0_625_MS)  /**< The advertising interval. This value can vary between 100ms to 10.24s). */

#if WITH_MASTER
#define MIN_CONNECTION_INTERVAL   MSEC_TO_UNITS(7.5, UNIT_1_25_MS)           /**< Determines minimum connection interval in milliseconds. */
#define MAX_CONNECTION_INTERVAL   MSEC_TO_UNITS(30, UNIT_1_25_MS)            /**< Determines maximum connection interval in milliseconds. */
#define SLAVE_LATENCY             15                                          /**< Determines slave latency in terms of connection events. */
#define SUPERVISION_TIMEOUT       MSEC_TO_UNITS(4000, UNIT_10_MS)            /**< Determines supervision time-out in units of 10 milliseconds. */
typedef struct
{
	uint8_t * p_data; /**< Pointer to data. */
	uint16_t data_len; /**< Length of data. */
}data_t;
uint8_t* ble_scan_start();
static uint32_t parse_adv_report(uint8_t type, data_t * p_advdata, data_t * p_typedata);
static const ble_gap_scan_params_t m_scan_param = {0, 0, NULL, 0x400, 0xEE, 0}; //< Scan parameters requested for scanning and connection.>
static uint8_t * target;//set to what should be the peer. this design possibly limits the active connections
#endif

static ble_gap_adv_params_t m_adv_params; /**< Parameters to be passed to the stack when starting advertising. */

static void
ble_evt_dispatch(ble_evt_t * p_ble_evt);
/*---------------------------------------------------------------------------*/
/**
 * \brief Initialize and enable the BLE stack.
 */
void ble_stack_init(void) {
	uint32_t err_code;

	// Enable BLE stack.
	ble_enable_params_t ble_enable_params;
	memset(&ble_enable_params, 0, sizeof(ble_enable_params));
	ble_enable_params.gatts_enable_params.attr_tab_size =
			BLE_GATTS_ATTR_TAB_SIZE_DEFAULT;
	ble_enable_params.gatts_enable_params.service_changed =
	IS_SRVC_CHANGED_CHARACT_PRESENT;
	err_code = sd_ble_enable(&ble_enable_params);
	APP_ERROR_CHECK(err_code);

	// Register with the SoftDevice handler module for BLE events.
	err_code = softdevice_ble_evt_handler_set(ble_evt_dispatch);
	APP_ERROR_CHECK(err_code);

	// Setup address
	ble_gap_addr_t ble_addr;
	err_code = sd_ble_gap_address_get(&ble_addr);
	APP_ERROR_CHECK(err_code);

	ble_addr.addr[5] = 0x00;
	ble_addr.addr_type = BLE_GAP_ADDR_TYPE_PUBLIC;

	err_code = sd_ble_gap_address_set(BLE_GAP_ADDR_CYCLE_MODE_NONE, &ble_addr);
	APP_ERROR_CHECK(err_code);
}
/*---------------------------------------------------------------------------*/
/**
 * \brief Return device EUI64 MAC address
 * \param addr pointer to a buffer to store the address
 */
void ble_get_mac(uint8_t addr[8]) {
	uint32_t err_code;
	ble_gap_addr_t ble_addr;

	err_code = sd_ble_gap_address_get(&ble_addr);
	APP_ERROR_CHECK(err_code);

	IPV6_EUI64_CREATE_FROM_EUI48(addr, ble_addr.addr, ble_addr.addr_type);
}
/*---------------------------------------------------------------------------*/
/**
 * \brief Initialize BLE advertising data.
 * \param name Human readable device name that will be advertised
 */
void ble_advertising_init(const char *name) {
	uint32_t err_code;
	ble_advdata_t advdata;
	uint8_t flags = BLE_GAP_ADV_FLAG_BR_EDR_NOT_SUPPORTED;
	ble_gap_conn_sec_mode_t sec_mode;

	BLE_GAP_CONN_SEC_MODE_SET_OPEN(&sec_mode);

	err_code = sd_ble_gap_device_name_set(&sec_mode, (const uint8_t *) name,
			strlen(name));
	APP_ERROR_CHECK(err_code);

	ble_uuid_t adv_uuids[] = { { BLE_UUID_IPSP_SERVICE, BLE_UUID_TYPE_BLE } };

	// Build and set advertising data.
	memset(&advdata, 0, sizeof(advdata));

	advdata.name_type = BLE_ADVDATA_FULL_NAME;
	advdata.flags = flags;
	advdata.uuids_complete.uuid_cnt = sizeof(adv_uuids) / sizeof(adv_uuids[0]);
	advdata.uuids_complete.p_uuids = adv_uuids;

	err_code = ble_advdata_set(&advdata, NULL);
	APP_ERROR_CHECK(err_code);

	// Initialize advertising parameters (used when starting advertising).
	memset(&m_adv_params, 0, sizeof(m_adv_params));

	m_adv_params.type = BLE_GAP_ADV_TYPE_ADV_IND;
	m_adv_params.p_peer_addr = NULL; // Undirected advertisement.
	m_adv_params.fp = BLE_GAP_ADV_FP_ANY;
	m_adv_params.interval = APP_ADV_ADV_INTERVAL;
	m_adv_params.timeout = APP_ADV_TIMEOUT;
}
/*---------------------------------------------------------------------------*/
/**
 * \brief Start BLE advertising.
 */
void ble_advertising_start(void) {
	uint32_t err_code;

	err_code = sd_ble_gap_adv_start(&m_adv_params);
	APP_ERROR_CHECK(err_code);

	PRINTF("ble-core: advertising started\n");
}
/*---------------------------------------------------------------------------*/
/**
 * \brief Print GAP address.
 * \param addr a pointer to address
 */
void ble_gap_addr_print(const ble_gap_addr_t *addr) {
	unsigned int i;
	for (i = 0; i < sizeof(addr->addr); i++) {
		if (i > 0) {
			PRINTF(":");
		}PRINTF("%02x", addr->addr[i]);
	}PRINTF(" (%d)", addr->addr_type);
}

#if WITH_MASTER
static const ble_gap_conn_params_t m_connection_param =
{
	(uint16_t)MIN_CONNECTION_INTERVAL,
	(uint16_t)MAX_CONNECTION_INTERVAL,
	(uint16_t)SLAVE_LATENCY,
	(uint16_t)SUPERVISION_TIMEOUT
};

int scompare(uint8_t *str, uint8_t *payload) {

//	printf("Same size: %d\n", sizeof(str));
	//PRINTF("Compare \"%s\" and \"%s\"...\n", str, payload);
	while(*str == *payload) {
		if(*str == '\0' || *payload == '\0') {
			PRINTF("reached end for one string\n");
			break;
		}
		str++;
		payload++;
	}
	if(*str == '\0' && *payload == '\0')
	return 1;
	else
	return 0;

}

#endif
/*
static void reverse_addr(ble_gap_addr_t *addr) {
	ble_gap_addr_t t = *addr;
	t.addr[0] = addr->addr[5];
	t.addr[1] = addr->addr[4];
	t.addr[2] = addr->addr[3];
	t.addr[3] = addr->addr[2];
	t.addr[4] = addr->addr[1];
	t.addr[5] = addr->addr[0];
	t.addr_type = addr->addr_type;
	addr = &t;
}
*/
/*---------------------------------------------------------------------------*/
/**
 * \brief Function for handling the Application's BLE Stack events.
 * \param[in]   p_ble_evt   Bluetooth stack event.
 */
static void on_ble_evt(ble_evt_t *p_ble_evt) {

	switch (p_ble_evt->header.evt_id) {
	case BLE_GAP_EVT_CONNECTED:
		PRINTF("ble-core: connected [handle:%d, peer: ", p_ble_evt->evt.gap_evt.conn_handle);
		ble_gap_addr_print(&(p_ble_evt->evt.gap_evt.params.connected.peer_addr));
		PRINTF("]\n");

		sd_ble_gap_rssi_start(p_ble_evt->evt.gap_evt.conn_handle, BLE_GAP_RSSI_THRESHOLD_INVALID, 0);

#if WITH_MASTER
		ble_ipsp_handle_t ipsp_handle = {p_ble_evt->evt.gap_evt.conn_handle, 0x23};
		//ble_mac_interface_add(peer, p_ble_evt->evt.gap_evt.conn_handle);
		ble_ipsp_connect(&ipsp_handle);
#endif
		break;

#if WITH_MASTER

		case BLE_GAP_EVT_ADV_REPORT:
		{
			uint32_t err;
			PRINTF("ble-core: found advertisement. length: %d\n", p_ble_evt->evt.gap_evt.params.adv_report.dlen);
			data_t data;
			data_t type;

			data.p_data = p_ble_evt->evt.gap_evt.params.adv_report.data;
			data.data_len = p_ble_evt->evt.gap_evt.params.adv_report.dlen;
			//parse data
			err = parse_adv_report(BLE_GAP_AD_TYPE_16BIT_SERVICE_UUID_MORE_AVAILABLE, &data, &type);
			//PRINTF("ERR: %ld", err);

			if (err != NRF_SUCCESS)
				err = parse_adv_report(BLE_GAP_AD_TYPE_16BIT_SERVICE_UUID_COMPLETE, &data, &type);

			if(err == NRF_SUCCESS)
			{
				//uint16_t uuid;
				PRINTF("ble-core: Succeeded parsing advdata\n");
				//find uuid which is set beforehand by the connect function
				//FIXME: HACK crop four first chars which are only garbage in contiki nrf52832
				type.p_data = &type.p_data[4];
				PRINTF("ble-core: advertising data: %s\n", type.p_data);

//	  if((sizeof(target) != 0) && scompare(type.p_data, target))
//        if((sizeof(target) != 0) && (memcmp(m_target_periph_name, dev_name.p_data, dev_name.data_len ) == 0))
				if(1)//FIXME: no matter the target
				{
					//actual attempt to connect

					err = sd_ble_gap_connect(&p_ble_evt->evt.gap_evt.params.adv_report.peer_addr, &m_scan_param, &m_connection_param);
					peer_addr_workaround(&p_ble_evt->evt.gap_evt.params.adv_report.peer_addr);
					if(err != NRF_SUCCESS)
					PRINTF("ble-core: Connection failed - %ld\n", err);
					if (err == NRF_SUCCESS) {
						//PRINTF("ble-core: Stopping scanning...");


						err = sd_ble_gap_scan_stop();
						if (err == NRF_SUCCESS);
						PRINTF("ble-core: Stopped scanning.\n");
					}
					break;
				} else {
					for(int i = 0; i<24; i++) {
						PRINTF("%c", type.p_data[i]);
					}
				}
				//printf("uuid:");
				//}*/
			} else
			{
				PRINTF("ble-core: Failed parsing advdata\n");
			}
			break;
		}

		//TODO: handle timeout of scan

		case BLE_GAP_EVT_TIMEOUT:
		{
			if(p_ble_evt->evt.gap_evt.params.timeout.src == BLE_GAP_TIMEOUT_SRC_SCAN)
			{
				PRINTF("Scan timed out\n");
				//ble_scan_start();
			}
			else if (p_ble_evt->evt.gap_evt.params.timeout.src == BLE_GAP_TIMEOUT_SRC_CONN)
			{

				PRINTF("Connection request timed out\n");
			}
			break;
		}
#endif
	case BLE_GAP_EVT_DISCONNECTED:
		PRINTF("ble-core: disconnected [handle:%d]\n",
				p_ble_evt->evt.gap_evt.conn_handle);

#if WITH_MASTER
		//Do we want this?
		ble_scan_start();
#else
		ble_advertising_start();
#endif
		break;
	default:
		break;
	}
}
/*---------------------------------------------------------------------------*/
/**
 * \brief SoftDevice BLE event callback.
 * \param[in]   p_ble_evt   Bluetooth stack event.
 */
static void ble_evt_dispatch(ble_evt_t *p_ble_evt) {
	ble_ipsp_evt_handler(p_ble_evt);
	on_ble_evt(p_ble_evt);

}

#if WITH_MASTER
//Put data in data pointer
static uint32_t parse_adv_report(uint8_t type, data_t * p_advdata, data_t * p_typedata)
{
	uint32_t i = 0;
	uint8_t * data;

	data = p_advdata->p_data;
	while(i < p_advdata->data_len)
	{
		uint8_t field_len = data[i];
		uint8_t field_type = data[i+1];
		if(field_type == type)
		{
			p_typedata->p_data = &data[i+2];
			p_typedata->data_len = field_len-1;
			return NRF_SUCCESS;
		}
		i += field_len + 1;
	}

	return NRF_ERROR_NOT_FOUND;
}

/*---------------------------------------------------------------------------*/
/**
 * \brief scanning
 */
uint8_t*
ble_scan_start()
{
	uint32_t err = 1;

	(void) sd_ble_gap_scan_stop();
	sd_ble_gap_adv_stop();
	PRINTF("ble-core: starting lescan\n");
	err = sd_ble_gap_scan_start(&m_scan_param);
	if (err == NRF_SUCCESS) {
		PRINTF("ble-core: Started scanning\n");
		//scanning = 1;
	}
	else
	{
		PRINTF("ble-core: Scanning failed - %lx\n", err);
		return 0;
	}
	return NRF_SUCCESS;
}

/*---------------------------------------------------------------------------*/
/**
 * \brief select peer to connect to
 * \param[in]   IPv6 adress to peer
 */
void
ble_set_target(uint8_t * t)
{
	//TODO: add several targets, change to ble_uuid_t, requires that the matching can extract the UUID. Unclear if this is a faster or more safe approach.
	target = t;
	PRINTF("ble-core: set target to %s\n", target);
}

/*-------------------------------------------------------------------------*/
/**
 * \brief disconnect
 */
void
ble_disconnect()
{
	sd_ble_gap_connect_cancel();
}
#endif
/*---------------------------------------------------------------------------*/
/**
 * @}
 * @}
 * @}
 */
