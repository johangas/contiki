CONTIKI_PROJECT = keypad
APPS=servreg-hack
CFLAGS += -DPROJECT_CONF_H=\"project-conf.h\"
NRF52_SDK_ROOT=/home/johan/Downloads/nrf5_iot_sdk_3288530

CONTIKI_WITH_RPL=0
NRF52_WITHOUT_SOFTDEVICE=0
CONTIKI_WITH_IPV6 = 1
CFLAGS += -DUIP_CONF_IPV6
CFLAGS += -DWITH_MASTER=1
WITH_MASTER=1
UIP_CONF_ROUTER = 1


CFLAGS += -DADDR=\"$(ADDR)\"


all: $(CONTIKI_PROJECT) 

PROJECTDIRS += $(REST_RESOURCES_DIR)
PROJECT_SOURCEFILES += $(REST_RESOURCES_FILES)

# linker optimizations
SMALL=0

# REST Engine shall use Erbium CoAP implementation
APPS += er-coap
APPS += rest-engine
#APPS += tinydtls/aes tinydtls/sha2 tinydtls/ecc tinydtls

ifdef WITH_IPSO
APPS += ipso-objects
endif

CONTIKI = ../..
include $(CONTIKI)/Makefile.include
