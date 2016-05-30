all: coap-example-server coap-example-client
###########################################################
# Here you set the security mode you want to use with CoAP
#    0 - No Security
#    1 - Pre Shared Key
#    2 - Raw Public Key ECC
#    3 - Certificate ECC
#    4 - Certificate ECC without Client Certificate
#    10 - All security modes
SECURITY_MODE=0
###########################################################
# Here you set the DTLS log level
# 0 - EMERGENCY
# 1 - ALERT
# 2 - CRIT
# 3 - WARN
# 4 - NOTICE
# 5 - INFO
# 6 - DEBUG
DTLS_LOG_LEVEL=6
###########################################################
# Here you enable handshake statistics like 
# completion time and retransmission count
HANDSHAKE_STATS=0
HANDSHAKE_STATS_DETAIL=0
###########################################################

NRF52_SDK_ROOT=/home/johan/Downloads/nrf5_iot_sdk_3288530

CONTIKI=../..
CONTIKI_WITH_IPV6=1
SOCKET_IPV6_ENABLE=1
WITH_UIP6=1
#CONTIKI_WITH_RPL=0

ifneq ($(SECURITY_MODE), 0)
# Set security mode
CFLAGS += -DSECURITY_MODE=$(SECURITY_MODE)

# Enable DTLS in CoAP
COAP_WITH_DTLS=0
WITH_DTLS=0

# Enable support for Openmote
ifeq ($(TARGET), openmote)
TARGET_CC2538DK=1
WITH_HW_SHA256=1
WITH_HW_ECC=1
WITH_HW_AES=1
endif

ifeq ($(SECURITY_MODE), 1)
# Enable support for PSK
WITH_DTLS_PSK=1
endif

ifeq ($(SECURITY_MODE), 2)
# Enable support for ECC
WITH_DTLS_ECC=1
endif

ifeq ($(SECURITY_MODE), 3)
# Enable support for Certificate ECC
WITH_DTLS_ECC=1
WITH_DTLS_CERT=1
endif

ifeq ($(SECURITY_MODE), 4)
# Enable support for Certificate ECC
WITH_DTLS_ECC=1
WITH_DTLS_CERT=1
endif

ifeq ($(SECURITY_MODE), 10)
WITH_DTLS_PSK=1
WITH_DTLS_ECC=1
WITH_DTLS_CERT=1
endif

# Set handshake statistics measurements
ifeq ($(HANDSHAKE_STATS), 1)
CFLAGS += -DWITH_HANDSHAKE_STATS=1
endif

ifeq ($(HANDSHAKE_STATS_DETAIL), 1)
CFLAGS += -DDETAIL_HANDSHAKE_STATS=1
#CFLAGS += -DAES_CRYPTO_STATS=1
CFLAGS += -DENABLE_POWERTRACE=1
APPS += powertrace
CFLAGS += -DCONTIKIMAC_CONF_COMPOWER=1 -DWITH_COMPOWER=1
endif

APPS += tinydtls/aes tinydtls/sha2 tinydtls/ecc tinydtls

endif


# Optimizations
SMALL=1
CFLAGS += -ffunction-sections
LDFLAGS += -Wl,--gc-sections,--undefined=_reset_vector__,--undefined=InterruptVectors,--undefined=_copy_data_init__,--undefined=_clear_bss_init__,--undefined=_end_of_init__
CFLAGS += -DPROJECT_CONF_H=\"project-conf.h\"


# Automatically build RESTful resources
REST_RESOURCES_DIR = ./resources
REST_RESOURCES_FILES = $(notdir $(shell find $(REST_RESOURCES_DIR) -name '*.c'))
PROJECTDIRS += $(REST_RESOURCES_DIR)
PROJECT_SOURCEFILES += $(REST_RESOURCES_FILES)


# Include apps needed for CoAP
APPS += er-coap
APPS += rest-engine

# Include apps needed for DTLS
ifneq ($(SECURITY_MODE), 0)


endif

# Are we targeting the native (i.e. your PC) platform? If so, enable the native border router.
ifeq ($(TARGET), native)
PROJECTDIRS += $(CONTIKI)/examples/ipv6/native-border-router
CONTIKI_SOURCEFILES += border-router-cmds.c tun-bridge.c border-router-rdc.c \
slip-config.c slip-dev.c border-router.c
APPS += slip-cmd
CFLAGS += -DCMD_CONF_OUTPUT=border_router_cmd_output -DUIP_FALLBACK_INTERFACE=rpl_interface -DCONTIKI_TARGET_NATIVE=1
endif




# Include flash erase app if using Openmote
ifeq ($(TARGET), openmote)
CFLAGS += -DSHA2_USE_INTTYPES_H
APPS += flash-erase
endif

# Set if used with the OpenBattery board for Openmote
#CFLAGS += -DWITH_OPENBATTERY=1

# Include Contiki main makefile
include $(CONTIKI)/Makefile.include

$(info APPS is $(APPS))

# Run "make router-server" or "make router-client" in order to set up the IPv6 tunnel
router-server: coap-example-server.native
	sudo ./coap-example-server.native -s /dev/null aaaa::1/64

router-client: coap-example-client.native
	sudo ./coap-example-client.native -s /dev/null aaaa::1/64
