/*
 * SPDX-FileCopyrightText: 2010-2022 Espressif Systems (Shanghai) CO LTD
 *
 * SPDX-License-Identifier: CC0-1.0
 */

#include <stdio.h>
#include "sdkconfig.h"
#include "freertos/FreeRTOS.h"
#include "freertos/task.h"
#include "freertos/event_groups.h"
#include "esp_chip_info.h"
#include "esp_flash.h"
#include <string.h>
#include "esp_system.h"
#include "esp_wifi.h"
#include "esp_mac.h"
#include "esp_event.h"
#include "esp_log.h"
#include "nvs_flash.h"
#include "esp_crc.h"
#include "esp_random.h"
#include "lwip/err.h"
#include "lwip/sys.h"
#include "esp_timer.h"


#define DEFAULT_SCAN_LIST_SIZE (10)
#define SSID "PAKAPORN_2.4G"
#define PASSWD "0873930740"

#define ESP_MAXIMUM_RETRY  (5)
#define WIFI_CONNECTED_BIT BIT0
#define WIFI_FAIL_BIT      BIT1

#define ESP_WIFI_SSID      "ESP32CAM_1"
#define ESP_WIFI_PASS      "123456789"
#define ESP_WIFI_CHANNEL   (1)
#define MAX_STA_CONN       (10)

#define max_child_node  (10)
#define fib_entry_max   (10)
#define icache_entry_max   (10)

#define ESP_WIFI_SCAN_AUTH_MODE_THRESHOLD WIFI_AUTH_WPA_PSK
//#define ESP_WIFI_SCAN_AUTH_MODE_THRESHOLD WIFI_AUTH_WPA2_PSK

typedef struct {
    char ATTR[100];
    char REGION[100];
    uint8_t DS[max_child_node][6];
    int number_ds;
} ccn_fib_entries;

typedef struct {
    ccn_fib_entries entry[fib_entry_max];
    int number_entry;
} ccn_fib_tables;

typedef struct {
    int ID;
    int TS[5];  //hr min sec millisec microsec
    char ATTR[100];
    char REGION[100];
    int ET[5];  //hr min sec millisec microsec
    int SR;     //packet per hr
} ccn_icache_entries;

typedef struct {
    ccn_icache_entries entry[icache_entry_max];
    int number_entry;
} ccn_icache_tables;

static const char *TAG = "CCN_root";
static esp_netif_t *netif_sta = NULL;
//static bool is_root;

static EventGroupHandle_t s_wifi_event_group;
static int s_retry_num = 0;

static wifi_country_t wifi_country = {.cc="CN", .schan = 1, .nchan = 13};

static uint8_t forward_interest_buf[1500];

static uint8_t my_mac_sta[6];
static uint8_t my_mac_ap[6];
static uint8_t broadcast_mac[6] = {0xff, 0xff, 0xff, 0xff, 0xff, 0xff};
static uint8_t test_mac[6] = {0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff};
static wifi_sta_list_t my_child;
static int my_layer[2] = {0,1};
static bool sniffer_running = false;

static int frame_sequence = 0;

static char number[10] = "0123456789";

static ccn_fib_tables my_fib;
static ccn_icache_tables my_icache;

static uint8_t data_hdr[] = {
    0x00,   //0: Type
    0x00,   //1: ATTR length
            //2-257: ATTR (1-256)
    0x00,   //258: Region length
            //259-514: Region (1-256)
    0x00,   //515-516: payload length
            //517-1943: payload (1-1427)
};

static uint8_t interest_hdr[] = {
    0x00,   //0: Type 0x11
    0x00,   //1: ATTR length
            //2-257: ATTR (1-256)
    0x00,   //258: Region length
            //259-514: Region (1-256)
    0x00, 0x00,     //515-516: ET millisec
    0x00, 0x00,     //517-518: SR
};

static uint8_t wifi_hdr[] = {
    0x00, 0x00,							    // 0-1: Frame Control
	0x00, 0x00,							    // 2-3: Duration
	0xff, 0xff, 0xff, 0xff, 0xff, 0xff,		// 4-9: Destination address (broadcast)
	0xba, 0xde, 0xaf, 0xfe, 0x00, 0x06,		// 10-15: Source address
	0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff,		// 16-21: BSSID
	0x00, 0x00,					            // 22-23: Sequence / fragment number
    0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, //reserve
    0x00,                                   // content length
};

typedef struct {
  unsigned frame_ctrl:16;
  unsigned duration_id:16;
  uint8_t addr1[6]; /* receiver address */
  uint8_t addr2[6]; /* sender address */
  uint8_t addr3[6]; /* filtering address */
  unsigned sequence_ctrl:16;
  uint8_t addr4[6]; /* optional */
} wifi_ieee80211_mac_hdr_t;

typedef struct {
  wifi_ieee80211_mac_hdr_t hdr;
  uint8_t payload[0]; /* network data ended with 4 bytes csum (CRC32) */
} wifi_ieee80211_packet_t;

wifi_promiscuous_filter_t filter_pkt = {
    .filter_mask = WIFI_PROMIS_FILTER_MASK_DATA,
};

/*############# define function ################*/
void sendlayer(int mylayer, uint8_t child_mac[6]);
void fib_table(char attr_node[], int attr_len, char region_node[], int region_len, uint8_t next_hop[6]);
void reset_FIB_table();
void show_FIB_table();
void sniffer_task(void *pvParameter);
void test_task(void *pvParameter);
/*############# --------------- ################*/

const char * wifi_sniffer_packet_type2str(wifi_promiscuous_pkt_type_t type)
{
  switch(type) {
  case WIFI_PKT_MGMT: return "MGMT";
  case WIFI_PKT_DATA: return "DATA";
  default:  
  case WIFI_PKT_MISC: return "MISC";
  }
}

void wifi_sniffer_packet_handler(void* buff, wifi_promiscuous_pkt_type_t type)
{
    ESP_ERROR_CHECK(esp_wifi_get_mac(WIFI_IF_STA, my_mac_sta));
    ESP_ERROR_CHECK(esp_wifi_get_mac(WIFI_IF_AP, my_mac_ap));
    ESP_ERROR_CHECK(esp_wifi_ap_get_sta_list(&my_child));

    const wifi_promiscuous_pkt_t *ppkt = (wifi_promiscuous_pkt_t *)buff;
    const wifi_ieee80211_packet_t *ipkt = (wifi_ieee80211_packet_t *)ppkt->payload;
    const wifi_ieee80211_mac_hdr_t *hdr = &ipkt->hdr;

    int check[3] = {0,0,0};
    bool match = false;

    if ((hdr->addr3[0] != test_mac[0]) || (hdr->addr3[1] != test_mac[1])
        || (hdr->addr3[2] != test_mac[2]) || (hdr->addr3[3] != test_mac[3])
        || (hdr->addr3[4] != test_mac[4]) || (hdr->addr3[5] != test_mac[5])){
        return;
    }

    for (int i=0; i<my_child.num; i++){
        check[0] = 0;
        check[1] = 0;
        check[2] = 0;
        for (int j=0; j<6; j++){
            if ( hdr->addr1[j] == my_mac_ap[j])
                check[0]++;
            if ( hdr->addr2[j] == my_child.sta[i].mac[j])
                check[1]++;
            if ( hdr->addr3[j] == test_mac[j])
                check[2]++;
        }
        if (check[0] == 6 && check[1] == 6 && check[2] == 6)
            match = true;
    }

    if (ipkt->payload[1] == 0x21 && match){
        // Introduction Packet //
        //char attr_n[ipkt->payload[2]];
        //char region_n[ipkt->payload[3+(ipkt->payload[2])]];
        char attr_n[100];
        char region_n[100];
        uint8_t node_addr[6];
        
        memcpy(attr_n, &ipkt->payload[3], ipkt->payload[2]);
        memcpy(region_n, &ipkt->payload[3+(ipkt->payload[2])+1], ipkt->payload[3+(ipkt->payload[2])]);
        
        for(int k=0; k<6; k++)
            node_addr[k] = hdr->addr2[k];
        ESP_LOGW(TAG, "PACKET TYPE= Intro Packet, RSSI=%02d ATTR: %s REGION: %s", ppkt->rx_ctrl.rssi, attr_n, region_n);
        
        fib_table(attr_n, ipkt->payload[2], region_n, ipkt->payload[3+(ipkt->payload[2])], node_addr);
        show_FIB_table();
        return;
    }
    if (ipkt->payload[1] == 0x01 && match){
        ESP_LOGW(TAG, "PACKET TYPE= Data Packet, RSSI=%02d", ppkt->rx_ctrl.rssi);
    }

/*
    printf("PACKET TYPE=%s, CHAN=%02d, RSSI=%02d,"
        " ADDR1=%02x:%02x:%02x:%02x:%02x:%02x,"
        " ADDR2=%02x:%02x:%02x:%02x:%02x:%02x,"
        " ADDR3=%02x:%02x:%02x:%02x:%02x:%02x\n",

        wifi_sniffer_packet_type2str(type),
        ppkt->rx_ctrl.channel,
        ppkt->rx_ctrl.rssi,
        // ADDR1 //
        hdr->addr1[0],hdr->addr1[1],hdr->addr1[2],
        hdr->addr1[3],hdr->addr1[4],hdr->addr1[5],
        // ADDR2 //
        hdr->addr2[0],hdr->addr2[1],hdr->addr2[2],
        hdr->addr2[3],hdr->addr2[4],hdr->addr2[5],
        // ADDR3 //
        hdr->addr3[0],hdr->addr3[1],hdr->addr3[2],
        hdr->addr3[3],hdr->addr3[4],hdr->addr3[5]
    );
*/
}

static void ip_event_handler(void *arg, esp_event_base_t event_base, int32_t event_id, void *event_data){
    
    ip_event_got_ip_t *event = (ip_event_got_ip_t *) event_data;
    ESP_LOGI(TAG, "<IP_EVENT_STA_GOT_IP>IP:" IPSTR, IP2STR(&event->ip_info.ip));

}

static void wifi_event_handler(void* arg, esp_event_base_t event_base, int32_t event_id, void* event_data)
{
    if (event_id == WIFI_EVENT_AP_STACONNECTED) {
        wifi_event_ap_staconnected_t* event = (wifi_event_ap_staconnected_t*) event_data;
        ESP_LOGI(TAG, "station "MACSTR" join, AID=%d", MAC2STR(event->mac), event->aid);
        //sendlayer(my_layer, event->mac);
    }
    else if (event_id == WIFI_EVENT_AP_STADISCONNECTED) {
        wifi_event_ap_stadisconnected_t* event = (wifi_event_ap_stadisconnected_t*) event_data;
        ESP_LOGI(TAG, "station "MACSTR" leave, AID=%d", MAC2STR(event->mac), event->aid);
    }
}

static void event_handler(void* arg, esp_event_base_t event_base, int32_t event_id, void* event_data)
{
    if (event_base == WIFI_EVENT && event_id == WIFI_EVENT_STA_START) {
        esp_wifi_connect();
    }
    else if (event_base == WIFI_EVENT && event_id == WIFI_EVENT_STA_DISCONNECTED) {
        my_layer[0] = 0;
        my_layer[1] = 1;
        if (s_retry_num < ESP_MAXIMUM_RETRY) {
            esp_wifi_connect();
            s_retry_num++;
            ESP_LOGI(TAG, "retry to connect to the AP");
        }
        else {
            xEventGroupSetBits(s_wifi_event_group, WIFI_FAIL_BIT);
        }
        ESP_LOGI(TAG,"connect to the AP fail");
    }
    else if (event_base == IP_EVENT && event_id == IP_EVENT_STA_GOT_IP) {
        ip_event_got_ip_t* event = (ip_event_got_ip_t*) event_data;
        ESP_LOGI(TAG, "got ip:" IPSTR, IP2STR(&event->ip_info.ip));
        s_retry_num = 0;
        xEventGroupSetBits(s_wifi_event_group, WIFI_CONNECTED_BIT);
    }
}

esp_err_t esp_comm_p2p_start(void)
{
    static bool is_comm_p2p_started = false;
    if (!is_comm_p2p_started) {
        is_comm_p2p_started = true;
        xTaskCreate(&test_task, "test_task", 3072, NULL, 5, NULL);
        xTaskCreate(&sniffer_task, "sniffer_task", 3072, NULL, 5, NULL);
    }
    return ESP_OK;
}

void reset_FIB_table(){
    my_fib.number_entry = 0;
    for(int i=0; i<max_child_node; i++){
        my_fib.entry[i].number_ds = 0;
    }
    ESP_LOGI(TAG,"Reset FIB Table");
}

void fib_table(char attr_node[], int attr_len, char region_node[], int region_len, uint8_t next_hop[6]){

    int check[3];
    int index[3] = {0, 0, 0};
    bool match[3] = {false, false, false};

    //printf("%d\n", my_fib.number_entry);

    for (int i = 0; i<my_fib.number_entry; i++){
        check[0] = 0;
        check[1] = 0;
        for (int j=0; j<attr_len; j++){
            if (attr_node[j] == my_fib.entry[i].ATTR[j] ){
                check[0]++;
            }
        }
        for (int k=0; k<region_len; k++){
            if (region_node[k] == my_fib.entry[i].REGION[k] ){
                check[1]++;
            }
        }
        if( check[0] == attr_len ){
            match[0] = true;
            index[0] = i;
        }
        if (check[1] == region_len){
            match[1] = true;
            index[1] = i;
        }
        //printf("%d %d\n", match[0], match[1]);
        if (match[0] && match[1]){
            for (int l=0; l<my_fib.entry[i].number_ds; l++){
                check[2] = 0;
                for (int m=0; m<6; m++){
                    if (next_hop[m] == my_fib.entry[i].DS[l][m]){
                        check[2]++;
                    }
                }
                if (check[2] == 6){
                    match[2] = true;
                    return;
                }
            }
            if (!match[2]){
                for (int n=0; n<6; n++)
                    my_fib.entry[i].DS[my_fib.entry[i].number_ds][n] = next_hop[n];
                my_fib.entry[i].number_ds++;
                return;
            }
        }
    }
    memcpy( my_fib.entry[my_fib.number_entry].ATTR, attr_node, attr_len);
    memcpy( my_fib.entry[my_fib.number_entry].REGION, region_node, region_len);
    for (int i=0; i<6; i++){
        my_fib.entry[my_fib.number_entry].DS[my_fib.entry[my_fib.number_entry].number_ds][i] = next_hop[i];
    }
    my_fib.entry[my_fib.number_entry].number_ds++;
    my_fib.number_entry++;
}

void show_FIB_table(){
    
    printf("############################## FIB Table ###############################\n");
    printf("|\tATTR\t\t|\tREGION\t|\t\tDS\t\t|\n");
    printf("------------------------------------------------------------------------\n");
    for (int i=0; i<my_fib.number_entry; i++){
        printf("|\t%s\t",my_fib.entry[i].ATTR);
        printf("|\t%s\t",my_fib.entry[i].REGION);
        for (int j=0; j<my_fib.entry[i].number_ds; j++){
            if (j > 0){
                printf("\n\t\t\t\t\t|\t"MACSTR"\t|", MAC2STR(my_fib.entry[i].DS[j]));
            }
            else{
                printf("|\t"MACSTR"\t|", MAC2STR(my_fib.entry[i].DS[j]));
            }
        }
        printf("\n");
    }
    printf("------------------------------------------------------------------------\n");
}

void showTable(wifi_ap_record_t AP_info[], uint16_t AP_count)
{
    printf("|\tSSID\t\t|      RSSI\t|    Channel\t|\n");
    printf("---------------------------------------------------------\n");
    for (int i = 0; (i < DEFAULT_SCAN_LIST_SIZE) && (i < AP_count); i++) {
        printf("|     %s    \t|\t%d\t|\t%d\t|\n", AP_info[i].ssid, AP_info[i].rssi, AP_info[i].primary);
    }
}

void sendlayer(int mylayer, uint8_t child_mac[6]){

    /*
    Send Beacon
        AP to STA 
        set ToDS bit: 0, FromDS bit:1
            Power Management, More Data, Re-Transmission bit :0
            0000 0010
    */

    vTaskDelay(2000 / portTICK_PERIOD_MS);

    char message[] = "layer:";
    uint8_t beacon_layer[200];

    ESP_ERROR_CHECK(esp_wifi_get_mac(WIFI_IF_STA, my_mac_sta));
    ESP_ERROR_CHECK(esp_wifi_get_mac(WIFI_IF_AP, my_mac_ap));
        
    memcpy(beacon_layer, wifi_hdr, 32);
    beacon_layer[32] = strlen(message);
    memcpy(&beacon_layer[33], message, strlen(message));
    beacon_layer[39] = mylayer+1;
    beacon_layer[0] = 0x80;
    beacon_layer[1] = 0x02;

    for(int i = 0; i<6; i++){
        beacon_layer[i+4] = child_mac[i];
        beacon_layer[i+10] = my_mac_ap[i];
    }
    esp_wifi_80211_tx(WIFI_IF_AP, beacon_layer, sizeof(wifi_hdr) + strlen(message), true);
}

void sniffer_task(void *pvParameter){
    ESP_ERROR_CHECK(esp_wifi_set_promiscuous(true));
    while (true){
        if(sniffer_running)
            esp_wifi_set_promiscuous_rx_cb(&wifi_sniffer_packet_handler);
    }
    vTaskDelete(NULL);
}

void test_task(void *pvParameter){
    
    char *attr_interest_message = NULL;
    char *region_interest_message = NULL;
    int line1 = 0;
    int line2 = 0;
    int ET_interval = 30000;
    int sr_pkt = 3600;

    vTaskDelay(60000 / portTICK_PERIOD_MS);

    while (true){

        ESP_ERROR_CHECK(esp_wifi_get_mac(WIFI_IF_STA, my_mac_sta));
        ESP_ERROR_CHECK(esp_wifi_get_mac(WIFI_IF_AP, my_mac_ap));
        ESP_ERROR_CHECK(esp_wifi_ap_get_sta_list(&my_child));

        if (line1 == 0)
            attr_interest_message = "video";
        if (line1 == 1)
            attr_interest_message = "sensor";
        if (line2 == 0)
            region_interest_message = "home/living";
        if (line2 == 1)
            region_interest_message = "home/kitchen";
        if (line2 == 2)
            region_interest_message = "home/bedroom";

        //int64_t t1 = esp_timer_get_time();
        //ESP_LOGW(TAG, "%lld",t1);
        
        for(int i=0;i<my_child.num;i++){

            memcpy( forward_interest_buf, wifi_hdr, 32);
            forward_interest_buf[0] = 0x08;
            forward_interest_buf[1] = 0x02; //AP->STA
            forward_interest_buf[22] = ((line1*10)+line2) >> 8;
            forward_interest_buf[23] = ((line1*10)+line2) & 0x00FF;
            forward_interest_buf[32] = sizeof(interest_hdr) + strlen(attr_interest_message) + strlen(region_interest_message);
            forward_interest_buf[1+32] = 0x11;
            forward_interest_buf[2+32] = strlen(attr_interest_message);
            memcpy( &forward_interest_buf[3+32], attr_interest_message, strlen(attr_interest_message));
            forward_interest_buf[32+3+strlen(attr_interest_message)] = strlen(region_interest_message);
            memcpy( &forward_interest_buf[32+3+strlen(attr_interest_message)+1], region_interest_message, strlen(region_interest_message));
            forward_interest_buf[32+3+strlen(attr_interest_message)+1+strlen(region_interest_message)] = ET_interval >> 8;
            forward_interest_buf[32+3+strlen(attr_interest_message)+1+strlen(region_interest_message)+1] = ET_interval & 0x00FF;
            forward_interest_buf[32+3+strlen(attr_interest_message)+1+strlen(region_interest_message)+2] = sr_pkt >> 8;
            forward_interest_buf[32+3+strlen(attr_interest_message)+1+strlen(region_interest_message)+3] = sr_pkt & 0x00FF;
            for(int j = 0; j<6; j++){
                forward_interest_buf[j+4] = my_child.sta[i].mac[j];
                forward_interest_buf[j+10] = my_mac_ap[j];
            }
            esp_wifi_80211_tx(WIFI_IF_AP, forward_interest_buf, sizeof(wifi_hdr) + sizeof(interest_hdr) + strlen(attr_interest_message) + strlen(region_interest_message), true);
            ESP_LOGI(TAG, "Interest Packet: ATTR:%s REGION:%s", attr_interest_message, region_interest_message);
            vTaskDelay(10000 / portTICK_PERIOD_MS);
        }
        
        line1++;
        if (line1 == 2){
            line2++;
            line1 = 0;
        }
        if (line2 == 3){
            line2 = 0;
        }

        vTaskDelay(10 / portTICK_PERIOD_MS);
        continue;
    }
    vTaskDelete(NULL);
}

int wifi_scan_router_rssi(void)
{
    uint16_t number = DEFAULT_SCAN_LIST_SIZE;
    wifi_ap_record_t ap_info[DEFAULT_SCAN_LIST_SIZE];
    uint16_t ap_count = 0;
    memset(ap_info, 0, sizeof(ap_info));
    int wifi_rssi = 0;
    int i,j,k=0;
    int check[2];

    ESP_ERROR_CHECK(esp_wifi_set_storage(WIFI_STORAGE_FLASH));
    ESP_ERROR_CHECK(esp_wifi_set_mode(WIFI_MODE_STA));
    ESP_ERROR_CHECK(esp_wifi_start());

    esp_wifi_scan_start(NULL, true);
    ESP_ERROR_CHECK(esp_wifi_scan_get_ap_records(&number, ap_info));
    ESP_ERROR_CHECK(esp_wifi_scan_get_ap_num(&ap_count));
    ESP_LOGI(TAG, "Total APs scanned = %u", ap_count);
    ESP_ERROR_CHECK(esp_wifi_scan_stop());
    ESP_ERROR_CHECK(esp_wifi_stop());

    for(i=0;i<ap_count;i++){
        for(j=0;j<strlen(SSID);j++){
            check[0] = SSID[j];
            check[1] = ap_info[i].ssid[j];
            if(check[0] == check[1]){
                k++;
            }
        }
        if(k == strlen(SSID)){
            wifi_rssi = ap_info[i].rssi;
            break;
        }
        else{
            k = 0;
        }
    }
    showTable(ap_info, ap_count);
    return wifi_rssi;
}

void chip_information(void){
    /* Print chip information */
    esp_chip_info_t chip_info;
    uint32_t flash_size;
    esp_chip_info(&chip_info);
    printf("This is %s chip with %d CPU core(s), WiFi%s%s, ",
           CONFIG_IDF_TARGET,
           chip_info.cores,
           (chip_info.features & CHIP_FEATURE_BT) ? "/BT" : "",
           (chip_info.features & CHIP_FEATURE_BLE) ? "/BLE" : "");

    printf("silicon revision %d, ", chip_info.revision);
    if(esp_flash_get_size(NULL, &flash_size) != ESP_OK) {
        printf("Get flash size failed");
        return;
    }

    printf("%uMB %s flash\n", flash_size / (1024 * 1024),
           (chip_info.features & CHIP_FEATURE_EMB_FLASH) ? "embedded" : "external");

    printf("Minimum free heap size: %d bytes\n", esp_get_minimum_free_heap_size());

    for (int i = 10; i >= 0; i--) {
        printf("Restarting in %d seconds...\n", i);
        vTaskDelay(1000 / portTICK_PERIOD_MS);
    }
    printf("Restarting now.\n");
    fflush(stdout);
    esp_restart();
}

void wifi_init_softap(void)
{
    ESP_ERROR_CHECK(esp_event_handler_instance_register(WIFI_EVENT,
                        ESP_EVENT_ANY_ID, &wifi_event_handler, NULL, NULL));

    wifi_config_t wifi_config = {
        .ap = {
            .ssid = ESP_WIFI_SSID,
            .ssid_len = strlen(ESP_WIFI_SSID),
            .channel = ESP_WIFI_CHANNEL,
            .password = ESP_WIFI_PASS,
            .max_connection = MAX_STA_CONN,
            .authmode = WIFI_AUTH_WPA_WPA2_PSK,
            .pmf_cfg = {
                    .required = false,
            },
        },
    };
    if (strlen(ESP_WIFI_PASS) == 0) {
        wifi_config.ap.authmode = WIFI_AUTH_OPEN;
    }

    ESP_ERROR_CHECK(esp_wifi_set_config(WIFI_IF_AP, &wifi_config));
    //ESP_ERROR_CHECK(esp_wifi_start());

}

void wifi_init_sta(void){

    s_wifi_event_group = xEventGroupCreate();

    esp_event_handler_instance_t instance_any_id;
    esp_event_handler_instance_t instance_got_ip;
    ESP_ERROR_CHECK(esp_event_handler_instance_register(WIFI_EVENT,
                                                        ESP_EVENT_ANY_ID,
                                                        &event_handler,
                                                        NULL,
                                                        &instance_any_id));
    ESP_ERROR_CHECK(esp_event_handler_instance_register(IP_EVENT,
                                                        IP_EVENT_STA_GOT_IP,
                                                        &event_handler,
                                                        NULL,
                                                        &instance_got_ip));

    wifi_config_t wifi_config = {
        .sta = {
            .ssid = SSID,
            .password = PASSWD,
            /* Authmode threshold resets to WPA2 as default if password matches WPA2 standards (pasword len => 8).
             * If you want to connect the device to deprecated WEP/WPA networks, Please set the threshold value
             * to WIFI_AUTH_WEP/WIFI_AUTH_WPA_PSK and set the password with length and format matching to
	     * WIFI_AUTH_WEP/WIFI_AUTH_WPA_PSK standards.
             */
            .threshold.authmode = ESP_WIFI_SCAN_AUTH_MODE_THRESHOLD,
            .sae_pwe_h2e = WPA3_SAE_PWE_BOTH,
        },
    };
    ESP_ERROR_CHECK(esp_wifi_set_config(WIFI_IF_STA, &wifi_config) );
    ESP_ERROR_CHECK(esp_wifi_start() );

    ESP_LOGI(TAG, "wifi_init_sta finished.");

    /* Waiting until either the connection is established (WIFI_CONNECTED_BIT) or connection failed for the maximum
     * number of re-tries (WIFI_FAIL_BIT). The bits are set by event_handler() (see above) */
    EventBits_t bits = xEventGroupWaitBits(s_wifi_event_group,
            WIFI_CONNECTED_BIT | WIFI_FAIL_BIT,
            pdFALSE,
            pdFALSE,
            portMAX_DELAY);

    /* xEventGroupWaitBits() returns the bits before the call returned, hence we can test which event actually
     * happened. */
    if (bits & WIFI_CONNECTED_BIT) {
        ESP_LOGI(TAG, "connected to AP");
        sniffer_running = true;
        ESP_ERROR_CHECK(esp_comm_p2p_start());
    }
    else if (bits & WIFI_FAIL_BIT) {
        ESP_LOGI(TAG, "Failed to connect to AP");
    }
    else {
        ESP_LOGE(TAG, "UNEXPECTED EVENT");
    }
}

void info_test(void){

    while (true){

        ESP_ERROR_CHECK(esp_wifi_get_mac(WIFI_IF_STA, my_mac_sta));
        ESP_ERROR_CHECK(esp_wifi_get_mac(WIFI_IF_AP, my_mac_ap));
        printf(" STA: "MACSTR"\n", MAC2STR(my_mac_sta));
        printf(" AP: "MACSTR"\n", MAC2STR(my_mac_ap));
        ESP_ERROR_CHECK(esp_wifi_ap_get_sta_list(&my_child));
        for(int i=0;i<my_child.num;i++){
            printf("MAC of Child %d: "MACSTR"\n", i+1, MAC2STR(my_child.sta[i].mac));
        }
        vTaskDelay(1000/portTICK_PERIOD_MS);
    }
}

void app_main(void)
{
    ESP_ERROR_CHECK(nvs_flash_init());
    /*  tcpip initialization */
    ESP_ERROR_CHECK(esp_netif_init());
    /*  event initialization */
    ESP_ERROR_CHECK(esp_event_loop_create_default());
    /*  create network interfaces for mesh (only station instance saved for further manipulation, soft AP instance ignored */
    netif_sta = esp_netif_create_default_wifi_sta();
    //assert(netif_sta);
    esp_netif_create_default_wifi_ap();
    /*  wifi initialization */
    wifi_init_config_t config = WIFI_INIT_CONFIG_DEFAULT();
    ESP_ERROR_CHECK(esp_wifi_init(&config));
    //ESP_ERROR_CHECK(esp_event_handler_register(IP_EVENT, IP_EVENT_STA_GOT_IP, &ip_event_handler, NULL));
    ESP_ERROR_CHECK(esp_wifi_set_mode(WIFI_MODE_APSTA));
    ESP_ERROR_CHECK( esp_wifi_set_country(&wifi_country) );
    reset_FIB_table();
    wifi_init_softap();
    wifi_init_sta();
    //info_test();
}