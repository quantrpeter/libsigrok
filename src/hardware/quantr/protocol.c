#include "protocol.h"
#include <config.h>
#include <stdlib.h>
#include <string.h>
#include <libsigrok/libsigrok.h>
#include "libsigrok-internal.h"
 
#define LOG_PREFIX "quantr"
 
static const uint32_t scanopts[] = {
    SR_CONF_CONN,
    SR_CONF_SERIALCOMM,
};
 
static const uint32_t devopts[] = {
    SR_CONF_LOGIC_ANALYZER,
    SR_CONF_SAMPLERATE | SR_CONF_GET | SR_CONF_SET | SR_CONF_LIST,
};
 
static const uint64_t samplerates[] = {
    SR_KHZ(1),
    SR_KHZ(10),
    SR_KHZ(100),
    SR_MHZ(1),
    SR_MHZ(10),
};
 
/* Initialize the driver */
SR_PRIV int quantr_init(struct sr_dev_driver *di, struct sr_context *sr_ctx)
{
    return std_init(di, sr_ctx);
}
 
/* Cleanup resources */
SR_PRIV int quantr_cleanup(const struct sr_dev_driver *di)
{
    return std_cleanup(di);
}
 
/* Scan for devices */
SR_PRIV GSList *quantr_scan(struct sr_dev_driver *di, GSList *options)
{
	printf("quantr_scan 2\n");
    /* Allocate memory for the device list */
    GSList *devices = NULL;
    struct sr_dev_inst *sdi;
    struct dev_context *devc;
    struct sr_serial_dev_inst *serial;
    const char *conn;
    const char *serialcomm;
 
    (void)di;
 
    /* Parse options */
    conn = NULL;
    serialcomm = "115200/8n1"; /* Default serial settings */
     
    if (sr_serial_extract_options(options, &conn, &serialcomm) != SR_OK)
        return NULL;
 
    if (!conn)
        return NULL;
 
    /* Try to open the serial port */
    serial = sr_serial_dev_inst_new(conn, serialcomm);
    if (!serial)
        return NULL;
 
    if (serial_open(serial, SERIAL_RDWR) != SR_OK) {
        sr_serial_dev_inst_free(serial);
        return NULL;
    }
 
    /* Try to communicate with the device to verify it's there */
    /* Send ping and expect pong */
    printf("c\n");
    const char *ping_cmd = "ping\n";
    char pong_reply[16] = {0};
    int write_ret = serial_write_blocking(serial, ping_cmd, strlen(ping_cmd), 1000);
    if (write_ret < 0) {
        printf("Failed to send ping to device.\n");
        serial_close(serial);
        sr_serial_dev_inst_free(serial);
        return NULL;
    }
    int read_ret = serial_read_blocking(serial, pong_reply, sizeof(pong_reply)-1, 1000);
    if (read_ret < 0) {
        printf("Failed to read pong from device.\n");
        serial_close(serial);
        sr_serial_dev_inst_free(serial);
        return NULL;
    }
    pong_reply[read_ret] = '\0';
    if (strncmp(pong_reply, "pong", 4) != 0) {
        printf("Device did not reply pong, got: '%s'\n", pong_reply);
        serial_close(serial);
        sr_serial_dev_inst_free(serial);
        return NULL;
    }
    /* Create device instance */
    sdi = g_malloc0(sizeof(struct sr_dev_inst));
    sdi->status = SR_ST_INACTIVE;
    sdi->vendor = g_strdup("Quantr");
    sdi->model = g_strdup("Device");
    sdi->inst_type = SR_INST_SERIAL;
    sdi->conn = serial;
     printf("a\n");
    if (!sdi) {
        serial_close(serial);
        sr_serial_dev_inst_free(serial);
        return NULL;
    }
 
    printf("3\n");
    devc = g_malloc0(sizeof(struct dev_context));
    devc->serial = serial;
    devc->samplerate = 1000000; /* Default 1MHz */
    devc->num_channels = 8; /* Default 8 channels */
    devc->buffer_size = 4096;
    devc->buffer = g_malloc(devc->buffer_size);
    sdi->priv = devc;
     
    serial_close(serial);
    devices = g_slist_append(devices, sdi);
    printf("devices=%p\n", devices);
    return devices;
}
 
/* List devices */
SR_PRIV GSList *quantr_dev_list(const struct sr_dev_driver *di)
{
    return ((struct sr_dev_driver *)di)->context;
}
 
/* Clear device instances */
SR_PRIV int quantr_dev_clear(const struct sr_dev_driver *di)
{
    return std_dev_clear(di);
}
 
/* Get configuration */
SR_PRIV int quantr_config_get(uint32_t key, GVariant **data, const struct sr_dev_inst *sdi, const struct sr_channel_group *cg)
{
    struct dev_context *devc = sdi->priv;
 
    (void)cg;
 
    switch (key) {
    case SR_CONF_SAMPLERATE:
        *data = g_variant_new_uint64(devc->samplerate);
        return SR_OK;
    default:
        return SR_ERR_NA;
    }
}
 
/* Set configuration */
SR_PRIV int quantr_config_set(uint32_t key, GVariant *data, const struct sr_dev_inst *sdi, const struct sr_channel_group *cg)
{
    struct dev_context *devc = sdi->priv;
 
    (void)cg;
 
    if (sdi->status != SR_ST_ACTIVE)
        return SR_ERR_DEV_CLOSED;
 
    switch (key) {
    case SR_CONF_SAMPLERATE:
        devc->samplerate = g_variant_get_uint64(data);
        return SR_OK;
    default:
        return SR_ERR_NA;
    }
}
 
/* List configuration options */
SR_PRIV int quantr_config_list(uint32_t key, GVariant **data, const struct sr_dev_inst *sdi, const struct sr_channel_group *cg)
{
    (void)sdi;
    (void)cg;
 
    switch (key) {
    case SR_CONF_SCAN_OPTIONS:
        *data = g_variant_new_fixed_array(G_VARIANT_TYPE_UINT32,
                scanopts, ARRAY_SIZE(scanopts), sizeof(uint32_t));
        return SR_OK;
    case SR_CONF_DEVICE_OPTIONS:
        *data = g_variant_new_fixed_array(G_VARIANT_TYPE_UINT32,
                devopts, ARRAY_SIZE(devopts), sizeof(uint32_t));
        return SR_OK;
    case SR_CONF_SAMPLERATE:
        *data = g_variant_new_fixed_array(G_VARIANT_TYPE_UINT64,
                samplerates, ARRAY_SIZE(samplerates), sizeof(uint64_t));
        return SR_OK;
    default:
        return SR_ERR_NA;
    }
}
 
/* Open device */
SR_PRIV int quantr_dev_open(struct sr_dev_inst *sdi)
{
    struct dev_context *devc = sdi->priv;
    int ret;
 
    ret = serial_open(devc->serial, SERIAL_RDWR);
    if (ret != SR_OK)
        return ret;
 
    sdi->status = SR_ST_ACTIVE;
    return SR_OK;
}
 
/* Close device */
SR_PRIV int quantr_dev_close(struct sr_dev_inst *sdi)
{
    struct dev_context *devc = sdi->priv;
 
    if (devc->serial) {
        serial_close(devc->serial);
    }
    sdi->status = SR_ST_INACTIVE;
    return SR_OK;
}
 
/* Start acquisition */
SR_PRIV int quantr_dev_acquisition_start(const struct sr_dev_inst *sdi)
{
    struct dev_context *devc = sdi->priv;
    int ret;
 
    if (!devc->serial)
        return SR_ERR;
 
    /* Send start command to device via serial port */
    ret = serial_write_blocking(devc->serial, "START\n", 6, 1000);
    if (ret < 0)
        return SR_ERR;
 
    devc->acquisition_running = 1;
     
    /* Set up polling or event-driven data reading here */
    /* For now, this is just a skeleton */
     
    return SR_OK;
}
 
/* Stop acquisition */
SR_PRIV int quantr_dev_acquisition_stop(struct sr_dev_inst *sdi)
{
    struct dev_context *devc = sdi->priv;
    int ret;
 
    if (!devc->serial || !devc->acquisition_running)
        return SR_OK;
 
    /* Send stop command to device via serial port */
    ret = serial_write_blocking(devc->serial, "STOP\n", 5, 1000);
    if (ret < 0)
        return SR_ERR;
 
    devc->acquisition_running = 0;
    return SR_OK;
}