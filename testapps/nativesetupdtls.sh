#Compile and flash
#Make requires correct directory
export WITH_DTLS=1
cd dtls-authority
make authority TARGET=native HAVE_ASSERT_H=1
./authority.native &
cd ..

cd dtls-keypad
make keypad TARGET=native ADDR=fe80:0000:0000:0000:0302:0304:0506:0708
./keypad.native
