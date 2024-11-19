#!/bin/bash -e
#=======================================
#SEAL SQ 2024
#Zero Touch Provisioning Demo with INeS
#IoT / Tools / Provisioning / Firmware Team
#=======================================

#SPDX-License-Identifier: Apache-2.0*/

############################################################
# Help                                                     #
############################################################
FIRST_CONFIG_FILE=.firstconfig.txt

Help()
{
   # Display Help
   echo "This script allow you to run instalation and working INES ZTP"
   echo "If you want to reexecute first install, remove .firstconfig.txt files"

   echo
}

checkoutLibs()
{   
   pushd "lib/ines_sdk_c"
   #echo "----------| Checkout to INeS VERSION : ${INES_SDK_TAG} |----------"
   #git checkout ${INES_SDK_TAG}   
   popd

   pushd "lib/wolfMQTT"
   echo "----------| Checkout to WOLFMQTT VERSION : ${WOLFMQTT_TAG} |----------"
   git checkout ${WOLFMQTT_TAG}   
   popd
}

install()
{
   sudo apt-get update
   sudo apt-get --yes --force-yes install cmake	
   sudo apt-get --yes --force-yes install python3
   configureZTPlib
   checkoutLibs
   echo done, remove this file if you want to do first setup again > ${FIRST_CONFIG_FILE}


}

configureZTPlib()
{
   echo "---INeS CLI : Configure ZTP lib START---"
   pushd lib/ines_sdk_c/
   
   chmod +x build.sh
   ./build.sh
   popd
   echo "---INeS CLI : Configure ZTP lib END---"

}

buildapp()
{
   echo "---INeS CLI : Build APP START---"
   source lib/ines_sdk_c/config.cfg

   CMAKE_OPTS="-DVAULTIC_PRODUCT=${VAULTIC_PRODUCT}"
   
   CMAKE_OPTS+=" -DWOLFSSL_USER_SETTINGS=yes -DWOLFSSL_EXAMPLES=no -DWOLFSSL_CRYPT_TESTS=no"
   
   if([ ! -z ${COMPILATION_MODE} ] ); then 
    CMAKE_OPTS+=" -DCOMPILATION_MODE=${COMPILATION_MODE}"
   fi

   if([ ! -z ${INTERFACE} ] ); then 
    CMAKE_OPTS+=" -DVAULTIC_COMM=${INTERFACE}"
   fi

    CMAKE_OPTS+=" -DWITH_WOLFSSL=${CMAKE_BINARY_DIR}/lib/ines_sdk_c/extlibs/libwolfssl/wolfssl"

   echo "Running CMAKE"
   rm -rf build/
   mkdir build
   cd build/
   cmake ${CMAKE_OPTS} ..
   echo "Cleaning"
   make clean
   echo "Building"
   make all

   if [ -f "./zeroTouchProvisioning_app" ];then
      echo "Zero Touch Provisioning App in C build";
   else
      exit
   fi
}

############################################################
############################################################
# Main program                                             #
############################################################
############################################################
############################################################
# Process the input options. Add options as needed.        #
############################################################
# Get the options

source ZTP.cfg

while getopts ":hbizg" option; do
   case $option in
      h) # display Help
         Help
         exit;;
      b) # Force building
	   echo "force building"
         buildapp
         exit;;
      i) # Install Prerequities
		 echo "Install Requierment"
         install
         exit;;
      g) # Git checkouts
		 echo "Install Requierment"
         checkoutLibs
         exit;;
      \?) # Invalid option
         echo "Error: Invalid option"
         Help
         exit;;
   esac
done

echo "ZTP Configuration and Building"
if [ -e ${FIRST_CONFIG_FILE} ]
then
    echo "First config Already done"
else
    echo "Do first config"
    install
fi


buildapp