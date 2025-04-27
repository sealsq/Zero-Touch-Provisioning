/*=======================================
SEAL SQ 2024
Zero Touch Provisioning Demo with INeS
IoT / Tools / Provisioning / Firmware Team
=======================================

SPDX-License-Identifier: Apache-2.0*/

// System libs
#include <time.h>

// SEAL SQ Libs
#include "wisekey_Ines_API.h"
#include "wisekey_ZTP_settings.h"
#include "wisekey_Crypto_Tools.h"
#include <math.h>
#include "aws_demo.h"

#define SNTP_SERVER_FQDN "pool.ntp.org"
#define WIFI_CONNECTED_BIT BIT0
#define WIFI_FAIL_BIT BIT1

int createDeviceCertificateFromInes(config_values_t config, int protocol)
{
    wkey_log(LOG_STEP_INDICATOR, "INES AGENT - Starting Zero Touch Provisioning via Ines");
    char *DeviceCertpem =NULL;
    char *csr=NULL;
    char *subjects=NULL;

    generatekeyAndCSR(config,&csr,&subjects);

    wkey_log(LOG_STEP_INDICATOR, "INES AGENT - Get certificate from Ines");
    certificate_t certificate;

    switch (protocol)
    {
    case API_EST:
        certificate.certificate = apiEST(config,config.FACTORY_CERT_PATH,config.FACTORY_KEY_PATH,ENROLL_CERTIFICATE, csr, NULL);
        //certificate.certificate = apiEST(config,"data/certs/RENEW_cert.pem","data/certs/RENEW_pkey.pem",RE_ENROLL_CERTIFICATE,csr,NULL);

        if (strcmp(certificate.certificate, "NULL") == 0)
            return -1;
        DeviceCertpem = estRawCartificatetoFormatedcert(certificate.certificate);

        break;

    default:
        certificate = apiREST_issueCertificate(config, config.INES_TEMPLATE_ID, subjects, csr);
        // certificate = apiREST_renewCertificate(config,34865,TRUE,csr);
        if (strcmp(certificate.certificate, "NULL") == 0)
            return -1;
        DeviceCertpem = inesRawCartificatetoFormatedcert(certificate.certificate);
        freeResultStruct(INES_RESPONSE_TYPE_CERTIFICATE,&certificate);
        if(subjects)
            free(subjects);
        break;
    }

    if (csr)
        free(csr);

    writeAndSaveFile(config.DEVICE_CERT_PATH, DeviceCertpem, strlen(DeviceCertpem));

    if (DeviceCertpem)
        free(DeviceCertpem);

    wkey_log(LOG_SUCCESS, "Certificate Saved - End of INES AGENT");

    return 0;
}

int inesDemo_ZeroTouchProv(config_values_t config, int protocol)
{
    printf("-------------\r\nInes Agent\r\n-------------\r\n");


    if(protocol==API_EST)
    {
        if(verifyConfigStruc(CONFIG_FILE_EST_API,&config)<0)
        {
            wkey_log(LOG_ERROR, "Invalid ZTP config provided");
            return -1;
        }

        if(verifyConfigStruc(CONFIG_FILE_ZTP_EST,&config)<0)
        {
            wkey_log(LOG_ERROR, "Invalid ZTP config provided");
            return -1;
        }
    }
    else
    {
        if(verifyConfigStruc(CONFIG_FILE_REST_API,&config)<0)
        {
            wkey_log(LOG_ERROR, "Invalid ZTP config provided");
            return -1;
        }

        if(verifyConfigStruc(CONFIG_FILE_ZTP_REST,&config)<0)
        {
            wkey_log(LOG_ERROR, "Invalid ZTP config provided");
            return -1;
        }

    }

    int ret = -1;
    bool need_verify_key=TRUE;


    if(strcmp(config.USE_VAULTIC,"TRUE")==0)
    {
        need_verify_key=FALSE;
    }

    // Check if files exist
    if (checkCertificateAndKeyDisponibility(config,need_verify_key) != 0)
    {
        wkey_log(LOG_WARNING, "Device Certificate DOES NOT exist. Launching the INeS Agent for requesting device certificate...");
        ret = createDeviceCertificateFromInes(config, protocol);
    }
    else
    {
        wkey_log(LOG_SUCCESS, "Device Certificate Chain exists: %s. If you want to request a new one, please remove it and launch the INeS agent again.", config.DEVICE_CERT_PATH);
        ret = 0;
    }

    return ret;
}

void main(int argc, char *argv[])
{
    
    printf("SEAL SQ\n\n------------------------------------\nZERO TOUCH PROVISIONING TO INES\n------------------------------------\n\n");
    wkey_log(LOG_INFO,"VERSION : %s",ZTP_DEMO_VERSION);
    wkey_log(LOG_STEP_INDICATOR,"INES DEMOS INITIALIZING");

    int ret;
    time_t seconds;
     
    seconds = time(NULL);
    printf("Seconds since January 1, 1970 = %ld\n", seconds);

    /* Extract the data from the config file */
    config_values_t config;
    initConfigFile(&config);

    for (int i = 0; i < argc; i++) {
        
        if(strcmp(argv[i],"-c")==0)
        {
            if(argv[i+1]!=NULL)
            {
                ret = parseConfigFile(argv[i+1], &config);
            }

        }
    }


    wkey_log(LOG_STEP_INDICATOR,"INES DEMOS INITIALIZED");

    //INES Zero Touch Demo
    int protocol = API_REST;

    if (config.PROTOCOL)
    {
        if(strcmp(config.PROTOCOL,"EST")==0)
            protocol=API_EST;
    }
    
    int inesStatus = inesDemo_ZeroTouchProv(config,protocol);

    if (inesStatus!=0)
        wkey_log(LOG_ERROR, "Ines Agent Malfunction, please see previous error");

    char*out;
    
    //Display OP Private Key
    if(config.SECURE_KEY_PATH)
    {
        out = openFile(config.SECURE_KEY_PATH);
        if(out)
            wkey_log(LOG_SUCCESS,"Device Operational Key at %s : \n%s\n",config.SECURE_KEY_PATH,out);
    }

    //Display OP Certificate
    if(config.DEVICE_CERT_PATH)
    {
        out = openFile(config.DEVICE_CERT_PATH);
        if(out)
        {
            wkey_log(LOG_SUCCESS,"Device Operational certificate at %s : \n%s\n",config.DEVICE_CERT_PATH,out);

            if(launchAwsDemo(&config)<0)
            {
                wkey_log(LOG_ERROR,"AWS_demo error");
            }

        }
    }



    if(out)
        free(out);
    
    freeConfigStruct(&config);
}
