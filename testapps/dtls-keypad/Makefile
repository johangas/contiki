CONTIKI_PROJECT = keypad

CFLAGS += -DPROJECT_CONF_H=\"project-conf.h\"
NRF52_SDK_ROOT=/home/johan/Downloads/nrf5_iot_sdk_3288530

NRF52_WITHOUT_SOFTDEVICE=0
CONTIKI_WITH_IPV6 = 1
WITH_DTLS = 1
WITH_CONTIKI = 1

CFLAGS += -DADDR=\"$(ADDR)\" -DWITH_DTLS=1 -DWITH_CONTIKI=1 


all: $(CONTIKI_PROJECT) 

PROJECTDIRS += $(REST_RESOURCES_DIR)
PROJECT_SOURCEFILES += $(REST_RESOURCES_FILES)

# linker optimizations
SMALL=1

# REST Engine shall use Erbium CoAP implementation
APPS += tinydtls/aes tinydtls/sha2 tinydtls/ecc tinydtls
APPS += er-coap
APPS += rest-engine



CONTIKI = ../..
include $(CONTIKI)/Makefile.include
