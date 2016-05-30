#Compile and flash
#Make requires correct directory
cd authority
make authority TARGET=native
./authority.native &
cd ..

cd keypad

make keypad TARGET=native ADDR=2001:db8::225:40ff:fef0:8bf0
./keypad.native

