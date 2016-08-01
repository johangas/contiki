#Compile and flash
#Make requires correct directory
cd authority
make erase TARGET=nrf52dk NRF52_JLINK_SN=682049342
make softdevice.flash TARGET=nrf52dk NRF52_JLINK_SN=682049342
make authority.flash TARGET=nrf52dk NRF52_USE_RTT=1 NRF52_JLINK_SN=682049342
#make authority.flash TARGET=nrf52dk NRF52_JLINK_SN=682049342
cd ..

cd keypad
make erase TARGET=nrf52dk NRF52_JLINK_SN=682531037
make softdevice.flash TARGET=nrf52dk NRF52_JLINK_SN=682531037
#make keypad.flash TARGET=nrf52dk ADDR=ff02::225:40ff:fef0:8bf0 NRF52_JLINK_SN=682531037 
make keypad.flash TARGET=nrf52dk NRF52_USE_RTT=1 ADDR=fe80::225:40ff:fef0:8bf0 NRF52_JLINK_SN=682531037 
#make keypad.flash TARGET=nrf52dk NRF52_USE_RTT=1 ADDR=fe80::200:FF:FE00:3205 NRF52_JLINK_SN=682531037 
cd ..


exit
