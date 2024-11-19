/*=======================================
SEAL SQ 2024
Zero Touch Provisioning Demo with INeS
IoT / Tools / Provisioning / Firmware Team
=======================================

SPDX-License-Identifier: Apache-2.0*/

/*
 *  AWS mqtt client demonstration program
 *  based on wolfMQTT example (awsiot.c)
 */

#ifdef HAVE_CONFIG_H
    #include <config.h>
#endif

#include "wolfmqtt/mqtt_client.h"
#include "wisekey_Tools.h"

#if defined(TARGETCHIP_VAULTIC_292)||defined(TARGETCHIP_VAULTIC_408)
#include "vaultic_tls_config.h"
#include <vaultic_tls.h>
#include <wolfssl/wolfcrypt/port/wisekey/vaultic.h>
#include <vaultic_tls.h>
#endif



/* This example only works with ENABLE_MQTT_TLS (wolfSSL library) */
#if defined(ENABLE_MQTT_TLS)
    #if !defined(WOLFSSL_USER_SETTINGS) && !defined(USE_WINDOWS_API)
        #include <wolfssl/options.h>
    #endif
    #include <wolfssl/wolfcrypt/settings.h>
    #include <wolfssl/version.h>

    #undef  ENABLE_AWSIOT_EXAMPLE
    #define ENABLE_AWSIOT_EXAMPLE
#endif


#ifdef ENABLE_AWSIOT_EXAMPLE

#include <wolfssl/ssl.h>
#include <wolfssl/wolfcrypt/asn_public.h>
#include <wolfssl/wolfcrypt/coding.h>
#include <wolfssl/wolfcrypt/hmac.h>

#define WOLFMQTT_NO_STDIN_CAP

#include "aws_demo.h"
#include "examples/mqttexample.h"
#include "examples/mqttnet.h"
#include <wolfmqtt/version.h>




config_values_t configfile;

/* Locals */
static int mStopRead = 0;

/* Configuration */
#define APP_HARDWARE         "wolf_aws_iot_demo"
#define APP_FIRMWARE_VERSION LIBWOLFMQTT_VERSION_STRING

#define MAX_BUFFER_SIZE         512    /* Maximum size for network read/write callbacks */

#define AWSIOT_DEVICE_ID        "WOLFMQTT_KRIKRI"
#define AWSIOT_QOS              MQTT_QOS_0
#define AWSIOT_KEEP_ALIVE_SEC   DEFAULT_KEEP_ALIVE_SEC
#define AWSIOT_CMD_TIMEOUT_MS   DEFAULT_CMD_TIMEOUT_MS

#define AWSIOT_SUBSCRIBE_TOPIC  "/topic/qos0"
#define AWSIOT_PUBLISH_TOPIC    "/topic/qos0"

#define AWSIOT_PUBLISH_MSG_SZ   400

static int mqtt_aws_tls_verify_cb(int preverify, WOLFSSL_X509_STORE_CTX* store)
{
    char buffer[WOLFSSL_MAX_ERROR_SZ];

    PRINTF("MQTT TLS Verify Callback: PreVerify %d, Error %d (%s)", preverify,
        store->error, store->error != 0 ?
            wolfSSL_ERR_error_string(store->error, buffer) : "none");
    PRINTF("  Subject's domain name is %s", store->domain);

    if (store->error != 0) {
        /* Allowing to continue */
        /* Should check certificate and return 0 if not okay */
        PRINTF("  Allowing cert anyways");
    }

    return 1;
}

/* Use this callback to setup TLS certificates and verify callbacks */
static int mqtt_aws_tls_cb(MqttClient* client)
{
    int rc = WOLFSSL_FAILURE;

    /* Use highest available and allow downgrade. If wolfSSL is built with
     * old TLS support, it is possible for a server to force a downgrade to
     * an insecure version. */
    client->tls.ctx = wolfSSL_CTX_new(wolfSSLv23_client_method());
    if (client->tls.ctx) {
        wolfSSL_CTX_set_verify(client->tls.ctx, WOLFSSL_VERIFY_NONE,
                               mqtt_aws_tls_verify_cb);

        if ((rc =wolfSSL_CTX_load_system_CA_certs(client->tls.ctx))!= SSL_SUCCESS) {
            fprintf(stderr, "ERROR: failed to load CA err !%d\n",rc);
            wolfSSL_CTX_free(client->tls.ctx); 
            rc = -1;
            return rc;
        }
#if defined(TARGETCHIP_VAULTIC_292)||defined(TARGETCHIP_VAULTIC_408)

        if(strcmp(configfile.USE_VAULTIC,"TRUE")==0)  
        {
            wkey_log(LOG_INFO,"Use Vaultic Credencial for MQTT");

            /* Open session with VaultIC */
            if(vlt_tls_init() !=0) {
                printf("ERROR: vic_tls_init error\n");
            }
            else {

#if defined(TARGETCHIP_VAULTIC_408)
                set_CurrenVaultickeyIndex(ECC_OPERATIONAL_Privk_Index);
#elif defined(TARGETCHIP_VAULTIC_292)
        vlt_tls_select_static_priv_key(VAULTIC_OPERATIONAL_KEY_INDEX);
#endif

                if ((rc =  wolfSSL_CTX_use_certificate_file(client->tls.ctx, configfile.DEVICE_CERT_PATH,SSL_FILETYPE_PEM))
                    != SSL_SUCCESS) {
                    fprintf(stderr, "ERROR: %d failed to load client certificate %s, please check the file.\n",
                            rc,configfile.DEVICE_CERT_PATH);
                    wolfSSL_CTX_free(client->tls.ctx);  /* Free the wolfSSL context object          */
                    return -1;
                }

                
                WOLFSSL_VAULTIC_SetupPkCallbacks(client->tls.ctx);
                rc = WOLFSSL_SUCCESS;
                
            }
        }
#endif
        
        if(strcmp(configfile.USE_VAULTIC,"TRUE")!=0)
        {
            if ((rc =  wolfSSL_CTX_use_certificate_file(client->tls.ctx, configfile.DEVICE_CERT_PATH,SSL_FILETYPE_PEM))
                != SSL_SUCCESS) {
                fprintf(stderr, "ERROR: %d failed to load client certificate %s, please check the file.\n",
                        rc,configfile.DEVICE_CERT_PATH);
                wolfSSL_CTX_free(client->tls.ctx);  /* Free the wolfSSL context object          */
                return -1;
            }

            if ((rc =  wolfSSL_CTX_use_PrivateKey_file(client->tls.ctx, configfile.SECURE_KEY_PATH,SSL_FILETYPE_PEM))
            != SSL_SUCCESS) {
                fprintf(stderr, "ERROR: %d failed to load client key %s, please check the file.\n",
                        rc,configfile.SECURE_KEY_PATH);
                wolfSSL_CTX_free(client->tls.ctx);  /* Free the wolfSSL context object          */
            return -1;
        }
        }
    }
    
    PRINTF("MQTT TLS Setup (%d)", rc);

    return rc;
}

static int mqtt_message_cb(MqttClient *client, MqttMessage *msg,
    byte msg_new, byte msg_done)
{
    MQTTCtx* mqttCtx = (MQTTCtx*)client->ctx;
    byte buf[PRINT_BUFFER_SIZE+1];
    word32 len;

    (void)mqttCtx;

    if (msg_new) {
        /* Determine min size to dump */
        len = msg->topic_name_len;
        if (len > PRINT_BUFFER_SIZE) {
            len = PRINT_BUFFER_SIZE;
        }
        XMEMCPY(buf, msg->topic_name, len);
        buf[len] = '\0'; /* Make sure its null terminated */

        /* Print incoming message */
        PRINTF("MQTT Message: Topic %s, Qos %d, Len %u",
            buf, msg->qos, msg->total_len);
    }

    /* Print message payload */
    len = msg->buffer_len;
    if (len > PRINT_BUFFER_SIZE) {
        len = PRINT_BUFFER_SIZE;
    }
    XMEMCPY(buf, msg->buffer, len);
    buf[len] = '\0'; /* Make sure its null terminated */
    PRINTF("Payload (%d - %d) printing %d bytes:" LINE_END "%s",
        msg->buffer_pos, msg->buffer_pos + msg->buffer_len, len, buf);

    if (msg_done) {
        PRINTF("MQTT Message: Done");
    }

    /* Return negative to terminate publish processing */
    return MQTT_CODE_SUCCESS;
}

#ifdef WOLFMQTT_PROPERTY_CB
/* The property callback is called after decoding a packet that contains at
   least one property. The property list is deallocated after returning from
   the callback. */
static int mqtt_property_cb(MqttClient *client, MqttProp *head, void *ctx)
{
    MqttProp *prop = head;
    int rc = 0;
    MQTTCtx* mqttCtx;

    if ((client == NULL) || (client->ctx == NULL)) {
        return MQTT_CODE_ERROR_BAD_ARG;
    }
    mqttCtx = (MQTTCtx*)client->ctx;

    while (prop != NULL) {
        PRINTF("Property CB: Type %d", prop->type);
        switch (prop->type) {
            case MQTT_PROP_SUBSCRIPTION_ID_AVAIL:
                mqttCtx->subId_not_avail =
                        prop->data_byte == 0;
                break;

            case MQTT_PROP_TOPIC_ALIAS_MAX:
                mqttCtx->topic_alias_max =
                 (mqttCtx->topic_alias_max < prop->data_short) ?
                 mqttCtx->topic_alias_max : prop->data_short;
                break;

            case MQTT_PROP_MAX_PACKET_SZ:
                if ((prop->data_int > 0) &&
                    (prop->data_int <= MQTT_PACKET_SZ_MAX))
                {
                    client->packet_sz_max =
                        (client->packet_sz_max < prop->data_int) ?
                         client->packet_sz_max : prop->data_int;
                }
                else {
                    /* Protocol error */
                    rc = MQTT_CODE_ERROR_PROPERTY;
                }
                break;

            case MQTT_PROP_SERVER_KEEP_ALIVE:
                mqttCtx->keep_alive_sec = prop->data_short;
                break;

            case MQTT_PROP_MAX_QOS:
                client->max_qos = prop->data_byte;
                break;

            case MQTT_PROP_RETAIN_AVAIL:
                client->retain_avail = prop->data_byte;
                break;

            case MQTT_PROP_REASON_STR:
                PRINTF("Reason String: %.*s",
                        prop->data_str.len, prop->data_str.str);
                break;

            case MQTT_PROP_USER_PROP:
                PRINTF("User property: key=\"%.*s\", value=\"%.*s\"",
                        prop->data_str.len, prop->data_str.str,
                        prop->data_str2.len, prop->data_str2.str);
                break;

            case MQTT_PROP_ASSIGNED_CLIENT_ID:
            case MQTT_PROP_PAYLOAD_FORMAT_IND:
            case MQTT_PROP_MSG_EXPIRY_INTERVAL:
            case MQTT_PROP_CONTENT_TYPE:
            case MQTT_PROP_RESP_TOPIC:
            case MQTT_PROP_CORRELATION_DATA:
            case MQTT_PROP_SUBSCRIPTION_ID:
            case MQTT_PROP_SESSION_EXPIRY_INTERVAL:
            case MQTT_PROP_TOPIC_ALIAS:
            case MQTT_PROP_TYPE_MAX:
            case MQTT_PROP_RECEIVE_MAX:
            case MQTT_PROP_WILDCARD_SUB_AVAIL:
            case MQTT_PROP_SHARED_SUBSCRIPTION_AVAIL:
            case MQTT_PROP_RESP_INFO:
            case MQTT_PROP_SERVER_REF:
            case MQTT_PROP_AUTH_METHOD:
            case MQTT_PROP_AUTH_DATA:
            case MQTT_PROP_NONE:
                break;
            case MQTT_PROP_REQ_PROB_INFO:
            case MQTT_PROP_WILL_DELAY_INTERVAL:
            case MQTT_PROP_REQ_RESP_INFO:
            default:
                /* Invalid */
                rc = MQTT_CODE_ERROR_PROPERTY;
                break;
        }
        prop = prop->next;
    }

    (void)ctx;

    return rc;
}
#endif /* WOLFMQTT_PROPERTY_CB */


int awsiot_test(MQTTCtx *mqttCtx)
{
    int rc = MQTT_CODE_SUCCESS, i;


    switch (mqttCtx->stat)
    {
        case WMQ_BEGIN:
        {
            PRINTF("AwsIoT Client: QoS %d, Use TLS %d", mqttCtx->qos, mqttCtx->use_tls);

            /* Aws IoT requires TLS */
            if (!mqttCtx->use_tls) {
                return MQTT_CODE_ERROR_BAD_ARG;
            }
        }
        FALL_THROUGH;

        case WMQ_NET_INIT:
        {
            mqttCtx->stat = WMQ_NET_INIT;

            /* Initialize Network */
            rc = MqttClientNet_Init(&mqttCtx->net, mqttCtx);
            if (rc == MQTT_CODE_CONTINUE) {
                return rc;
            }
            PRINTF("MQTT Net Init: %s (%d)",
                MqttClient_ReturnCodeToString(rc), rc);
            if (rc != MQTT_CODE_SUCCESS) {
                goto exit;
            }

            /* setup tx/rx buffers */
            mqttCtx->tx_buf = (byte*)WOLFMQTT_MALLOC(MAX_BUFFER_SIZE);
            mqttCtx->rx_buf = (byte*)WOLFMQTT_MALLOC(MAX_BUFFER_SIZE);
        }
        FALL_THROUGH;

        case WMQ_INIT:
        {
            mqttCtx->stat = WMQ_INIT;

            /* Initialize MqttClient structure */
            rc = MqttClient_Init(&mqttCtx->client, &mqttCtx->net, mqtt_message_cb,
                mqttCtx->tx_buf, MAX_BUFFER_SIZE, mqttCtx->rx_buf, MAX_BUFFER_SIZE,
                mqttCtx->cmd_timeout_ms);
            if (rc == MQTT_CODE_CONTINUE) {
                return rc;
            }
            PRINTF("MQTT Init: %s (%d)",
                MqttClient_ReturnCodeToString(rc), rc);
            if (rc != MQTT_CODE_SUCCESS) {
                goto exit;
            }
            mqttCtx->client.ctx = mqttCtx;
#ifdef WOLFMQTT_PROPERTY_CB
            rc = MqttClient_SetPropertyCallback(&mqttCtx->client,
                    mqtt_property_cb, NULL);
            if (rc != MQTT_CODE_SUCCESS) {
                goto exit;
            }
#endif
        }
        FALL_THROUGH;

        case WMQ_TCP_CONN:
        {
            mqttCtx->stat = WMQ_TCP_CONN;

            /* Connect to broker */
            rc = MqttClient_NetConnect(&mqttCtx->client, mqttCtx->host, mqttCtx->port,
                DEFAULT_CON_TIMEOUT_MS, mqttCtx->use_tls, mqtt_aws_tls_cb);
            if (rc == MQTT_CODE_CONTINUE) {
                return rc;
            }
            PRINTF("MQTT Socket Connect: %s (%d)",
                MqttClient_ReturnCodeToString(rc), rc);
            if (rc != MQTT_CODE_SUCCESS) {
                goto exit;
            }

            /* Build connect packet */
            XMEMSET(&mqttCtx->connect, 0, sizeof(MqttConnect));
            mqttCtx->connect.keep_alive_sec = mqttCtx->keep_alive_sec;
            mqttCtx->connect.clean_session = mqttCtx->clean_session;
            mqttCtx->connect.client_id = mqttCtx->client_id;

            /* Last will and testament sent by broker to subscribers
                of topic when broker connection is lost */
            XMEMSET(&mqttCtx->lwt_msg, 0, sizeof(mqttCtx->lwt_msg));
            mqttCtx->connect.lwt_msg = &mqttCtx->lwt_msg;
            mqttCtx->connect.enable_lwt = mqttCtx->enable_lwt;
            if (mqttCtx->enable_lwt) {
                /* Send client id in LWT payload */
                mqttCtx->lwt_msg.qos = mqttCtx->qos;
                mqttCtx->lwt_msg.retain = 0;
                mqttCtx->lwt_msg.topic_name = AWSIOT_PUBLISH_TOPIC"lwt";
                mqttCtx->lwt_msg.buffer = (byte*)mqttCtx->client_id;
                mqttCtx->lwt_msg.total_len = (word16)XSTRLEN(mqttCtx->client_id);
            }
            /* Optional authentication */
            mqttCtx->connect.username = mqttCtx->username;
            mqttCtx->connect.password = mqttCtx->password;
#ifdef WOLFMQTT_V5
            {
                /* Request Response Information */
                MqttProp* prop = MqttClient_PropsAdd(&mqttCtx->connect.props);
                prop->type = MQTT_PROP_REQ_RESP_INFO;
                prop->data_byte = 1;
            }
            {
                /* Request Problem Information */
                MqttProp* prop = MqttClient_PropsAdd(&mqttCtx->connect.props);
                prop->type = MQTT_PROP_REQ_PROB_INFO;
                prop->data_byte = 1;
            }
#endif
        }
        FALL_THROUGH;

        case WMQ_MQTT_CONN:
        {
            mqttCtx->stat = WMQ_MQTT_CONN;

            /* Send Connect and wait for Connect Ack */
            rc = MqttClient_Connect(&mqttCtx->client, &mqttCtx->connect);
            if (rc == MQTT_CODE_CONTINUE) {
                return rc;
            }
#ifdef WOLFMQTT_V5
            if (mqttCtx->connect.props != NULL) {
                /* Release the allocated properties */
                MqttClient_PropsFree(mqttCtx->connect.props);
            }
#endif
            PRINTF("MQTT Connect: Proto (%s), %s (%d)",
                MqttClient_GetProtocolVersionString(&mqttCtx->client),
                MqttClient_ReturnCodeToString(rc), rc);
            if (rc != MQTT_CODE_SUCCESS) {
                goto disconn;
            }

            /* Validate Connect Ack info */
            PRINTF("MQTT Connect Ack: Return Code %u, Session Present %d",
                mqttCtx->connect.ack.return_code,
                (mqttCtx->connect.ack.flags &
                    MQTT_CONNECT_ACK_FLAG_SESSION_PRESENT) ?
                    1 : 0
            );

            /* Build list of topics */
            mqttCtx->topics[0].topic_filter = mqttCtx->topic_name;
            mqttCtx->topics[0].qos = mqttCtx->qos;

            /* Subscribe Topic */
            XMEMSET(&mqttCtx->subscribe, 0, sizeof(MqttSubscribe));
            mqttCtx->subscribe.packet_id = mqtt_get_packetid();
            mqttCtx->subscribe.topic_count = sizeof(mqttCtx->topics)/sizeof(MqttTopic);
            mqttCtx->subscribe.topics = mqttCtx->topics;
        }
        FALL_THROUGH;

        case WMQ_SUB:
        {
            mqttCtx->stat = WMQ_SUB;

            rc = MqttClient_Subscribe(&mqttCtx->client, &mqttCtx->subscribe);
            if (rc == MQTT_CODE_CONTINUE) {
                return rc;
            }
            PRINTF("MQTT Subscribe: %s (%d)",
                MqttClient_ReturnCodeToString(rc), rc);
            if (rc != MQTT_CODE_SUCCESS) {
                goto disconn;
            }

            /* show subscribe results */
            for (i = 0; i < mqttCtx->subscribe.topic_count; i++) {
                MqttTopic *topic = &mqttCtx->subscribe.topics[i];
                PRINTF("  Topic %s, Qos %u, Return Code %u",
                    topic->topic_filter,
                    topic->qos, topic->return_code);
            }

            /* Publish Topic */
            XSNPRINTF((char*)mqttCtx->app_ctx, AWSIOT_PUBLISH_MSG_SZ,
                "{\"message\": \"hello from rpi (VaultIC)\"}"
                );

            XMEMSET(&mqttCtx->publish, 0, sizeof(MqttPublish));
            mqttCtx->publish.retain = 0;
            mqttCtx->publish.qos = mqttCtx->qos;
            mqttCtx->publish.duplicate = 0;
            mqttCtx->publish.topic_name = AWSIOT_PUBLISH_TOPIC;
            mqttCtx->publish.packet_id = mqtt_get_packetid();
            mqttCtx->publish.buffer = (byte*)mqttCtx->app_ctx;
            mqttCtx->publish.total_len = (word32)XSTRLEN((char*)mqttCtx->app_ctx);
        }
        FALL_THROUGH;

        case WMQ_PUB:
        {
            mqttCtx->stat = WMQ_PUB;

            rc = MqttClient_Publish(&mqttCtx->client, &mqttCtx->publish);
            if (rc == MQTT_CODE_CONTINUE) {
                return rc;
            }
            PRINTF("MQTT Publish: Topic %s, %s (%d)",
                mqttCtx->publish.topic_name, MqttClient_ReturnCodeToString(rc), rc);
            if (rc != MQTT_CODE_SUCCESS) {
                goto disconn;
            }

            /* Read Loop */
            PRINTF("MQTT Waiting for message...");
        }
        FALL_THROUGH;

        case WMQ_WAIT_MSG:
        {
            mqttCtx->stat = WMQ_WAIT_MSG;

            do {
                /* check for test mode or stop */
                if (mStopRead || mqttCtx->test_mode) {
                    rc = MQTT_CODE_SUCCESS;
                    PRINTF("MQTT Exiting...");
                    break;
                }

                /* Try and read packet */
                rc = MqttClient_WaitMessage(&mqttCtx->client, mqttCtx->cmd_timeout_ms);

            #ifdef WOLFMQTT_NONBLOCK
                /* Track elapsed time with no activity and trigger timeout */
                rc = mqtt_check_timeout(rc, &mqttCtx->start_sec,
                    mqttCtx->cmd_timeout_ms/1000);
            #endif

                /* check return code */
                if (rc == MQTT_CODE_CONTINUE) {
                    return rc;
                }
            #ifdef WOLFMQTT_ENABLE_STDIN_CAP
                else if (rc == MQTT_CODE_STDIN_WAKE) {
                    /* Get data from STDIO */
                    XMEMSET(mqttCtx->rx_buf, 0, MAX_BUFFER_SIZE);
                    if (XFGETS((char*)mqttCtx->rx_buf, MAX_BUFFER_SIZE - 1, stdin) != NULL) {
                        /* rc = (int)XSTRLEN((char*)mqttCtx->rx_buf); */

                        /* Publish Topic */
                        XSNPRINTF((char*)mqttCtx->app_ctx, AWSIOT_PUBLISH_MSG_SZ,
                            "{\"state\":{\"reported\":{\"msg\":\"%s\"}}}",
                            mqttCtx->rx_buf);
                        mqttCtx->stat = WMQ_PUB;
                        XMEMSET(&mqttCtx->publish, 0, sizeof(MqttPublish));
                        mqttCtx->publish.retain = 0;
                        mqttCtx->publish.qos = mqttCtx->qos;
                        mqttCtx->publish.duplicate = 0;
                        mqttCtx->publish.topic_name = AWSIOT_PUBLISH_TOPIC;
                        mqttCtx->publish.packet_id = mqtt_get_packetid();
                        mqttCtx->publish.buffer = (byte*)mqttCtx->app_ctx;
                        mqttCtx->publish.total_len = (word32)XSTRLEN((char*)mqttCtx->app_ctx);
                        rc = MqttClient_Publish(&mqttCtx->client, &mqttCtx->publish);
                        PRINTF("MQTT Publish: Topic %s, %s (%d)",
                            mqttCtx->publish.topic_name,
                            MqttClient_ReturnCodeToString(rc), rc);
                    }
                }
            #endif
                else if (rc == MQTT_CODE_ERROR_TIMEOUT) {
                    /* Keep Alive */
                    PRINTF("Keep-alive timeout, sending ping");

                    rc = MqttClient_Ping_ex(&mqttCtx->client, &mqttCtx->ping);
                    if (rc == MQTT_CODE_CONTINUE) {
                        return rc;
                    }
                    else if (rc != MQTT_CODE_SUCCESS) {
                        PRINTF("MQTT Ping Keep Alive Error: %s (%d)",
                            MqttClient_ReturnCodeToString(rc), rc);
                        break;
                    }
                }
                else if (rc != MQTT_CODE_SUCCESS) {
                    /* There was an error */
                    PRINTF("MQTT Message Wait: %s (%d)",
                        MqttClient_ReturnCodeToString(rc), rc);
                    break;
                }
            } while (1);

            /* Check for error */
            if (rc != MQTT_CODE_SUCCESS) {
                goto disconn;
            }
        }
        FALL_THROUGH;

        case WMQ_DISCONNECT:
        {
            /* Disconnect */
            rc = MqttClient_Disconnect(&mqttCtx->client);
            if (rc == MQTT_CODE_CONTINUE) {
                return rc;
            }
            PRINTF("MQTT Disconnect: %s (%d)",
                MqttClient_ReturnCodeToString(rc), rc);
            if (rc != MQTT_CODE_SUCCESS) {
                goto disconn;
            }
        }
        FALL_THROUGH;

        case WMQ_NET_DISCONNECT:
        {
            mqttCtx->stat = WMQ_NET_DISCONNECT;

            rc = MqttClient_NetDisconnect(&mqttCtx->client);
            if (rc == MQTT_CODE_CONTINUE) {
                return rc;
            }
            PRINTF("MQTT Socket Disconnect: %s (%d)",
                MqttClient_ReturnCodeToString(rc), rc);
        }
        FALL_THROUGH;

        case WMQ_DONE:
        {
            mqttCtx->stat = WMQ_DONE;
            rc = mqttCtx->return_code;
            goto exit;
        }

        case WMQ_UNSUB: /* not used */
        case WMQ_PING:
        default:
            rc = MQTT_CODE_ERROR_STAT;
            goto exit;
    } /* switch */

disconn:
    mqttCtx->stat = WMQ_NET_DISCONNECT;
    mqttCtx->return_code = rc;
    rc = MQTT_CODE_CONTINUE;

exit:

    if (rc != MQTT_CODE_CONTINUE) {
        /* Free resources */
        if (mqttCtx->tx_buf) WOLFMQTT_FREE(mqttCtx->tx_buf);
        if (mqttCtx->rx_buf) WOLFMQTT_FREE(mqttCtx->rx_buf);

        /* Cleanup network */
        MqttClientNet_DeInit(&mqttCtx->net);

        MqttClient_DeInit(&mqttCtx->client);
        
        #if defined(TARGETCHIP_VAULTIC_292)||defined(TARGETCHIP_VAULTIC_408)
        /* Close connection with VaultIC */
        if(vlt_tls_close()!=0) {
            fprintf(stderr, "ERROR: vlt_tls_close error\n");
        }
        #endif /*defined(TARGETCHIP_VAULTIC_292)||defined(TARGETCHIP_VAULTIC_408)*/
    }

    return rc;
}
#endif /* ENABLE_AWSIOT_EXAMPLE */


/* so overall tests can pull in test function */
    #ifdef USE_WINDOWS_API
        #include <windows.h> /* for ctrl handler */

        static BOOL CtrlHandler(DWORD fdwCtrlType)
        {
            if (fdwCtrlType == CTRL_C_EVENT) {
            #ifdef ENABLE_AWSIOT_EXAMPLE
                mStopRead = 1;
            #endif
                PRINTF("Received Ctrl+c");
                return TRUE;
            }
            return FALSE;
        }
    #elif HAVE_SIGNAL
        #include <signal.h>
        static void sig_handler(int signo)
        {
            if (signo == SIGINT) {
            #ifdef ENABLE_AWSIOT_EXAMPLE
                mStopRead = 1;
            #endif
                PRINTF("Received SIGINT");
            }
        }
    #endif


int launchAwsDemo(config_values_t *configByFile)
    {
        configfile = *configByFile;

        int rc;
    #ifdef ENABLE_AWSIOT_EXAMPLE
        MQTTCtx mqttCtx;
        char pubMsg[AWSIOT_PUBLISH_MSG_SZ] = {0};

        /* init defaults */
        mqtt_init_ctx(&mqttCtx);
        mqttCtx.app_name = "awsiot";
        mqttCtx.host = configfile.AWS_IOT_ENDPOINT;
        mqttCtx.qos = AWSIOT_QOS;
        mqttCtx.keep_alive_sec = AWSIOT_KEEP_ALIVE_SEC;
        mqttCtx.client_id = AWSIOT_DEVICE_ID;
        mqttCtx.topic_name = AWSIOT_SUBSCRIBE_TOPIC;
        mqttCtx.cmd_timeout_ms = AWSIOT_CMD_TIMEOUT_MS;
        mqttCtx.use_tls = 1;
        mqttCtx.app_ctx = pubMsg;

        /* parse arguments */
        /*rc = mqtt_parse_args(&mqttCtx, NULL, NULL);
        if (rc != 0) {
            return rc;
        }*/
    #endif

    #ifdef USE_WINDOWS_API
        if (SetConsoleCtrlHandler((PHANDLER_ROUTINE)CtrlHandler, TRUE) == FALSE) {
            PRINTF("Error setting Ctrl Handler! Error %d", (int)GetLastError());
        }
    #elif HAVE_SIGNAL
        if (signal(SIGINT, sig_handler) == SIG_ERR) {
            PRINTF("Can't catch SIGINT");
        }
    #endif

    #ifdef ENABLE_AWSIOT_EXAMPLE
        do {
            rc = awsiot_test(&mqttCtx);
        } while (rc == MQTT_CODE_CONTINUE);

        mqtt_free_ctx(&mqttCtx);
    #else
        (void)argc;
        (void)argv;

        /* This example requires wolfSSL 3.9.1 or later with base64encode enabled */
        PRINTF("Example not compiled in!");
        rc = 0; /* return success, so make check passes with TLS disabled */
    #endif
        
        return (rc == 0)||(rc ==  MQTT_CODE_STDIN_WAKE) ? 0 : EXIT_FAILURE;
    }
