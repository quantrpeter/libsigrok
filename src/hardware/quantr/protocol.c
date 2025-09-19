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
    SR_CONF_CONTINUOUS | SR_CONF_GET | SR_CONF_SET,
};
 
static const uint64_t samplerates[] = {
    SR_KHZ(1),
    SR_KHZ(10),
    SR_KHZ(100),
    SR_MHZ(1),
    SR_MHZ(10),
    SR_MHZ(20),
    SR_MHZ(25),
    SR_MHZ(50),
};
 
/* Initialize the driver */
SR_PRIV int quantr_init(struct sr_dev_driver *di, struct sr_context *sr_ctx)
{
    return std_init(di, sr_ctx);
}
 
/* Cleanup resources */
SR_PRIV int quantr_cleanup(const struct sr_dev_driver *di)
{
	printf("quantr_cleanup\n");
    return std_cleanup(di);
}
 
/* Scan for devices */
SR_PRIV GSList *quantr_scan(struct sr_dev_driver *di, GSList *options)
{
	printf("Scanning quantr device\n");
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
    serialcomm = "115200/8n1/dtr=1/rts=1"; /* Default serial settings with DTR/RTS asserted */
     
    if (sr_serial_extract_options(options, &conn, &serialcomm) != SR_OK)
        return NULL;
 
    if (!conn)
        return NULL;

	printf(" - connecting to %s, %s\n", conn, serialcomm);
 
    /* Try to open the serial port */
    serial = sr_serial_dev_inst_new(conn, serialcomm);
    if (!serial){
		printf(" - failed to open device %s by sr_serial_dev_inst_new\n", conn);
        return NULL;
	}
 
    int open_ret = serial_open(serial, SERIAL_RDWR);
    if (open_ret != SR_OK) {
        sr_serial_dev_inst_free(serial);
        printf(" - failed to open device %s (serial_open returned %d)\n", conn, open_ret);
        // Optionally, print strerror if open_ret is errno
        printf(" - strerror: %s\n", strerror(errno));
        return NULL;
    }
 
    /* Try to communicate with the device to verify it's there */
    /* Drain any initial bytes (banner/garbage) that might be pending. */
    {
        char drain_buf[128];
        int drained_total = 0;
        while (1) {
            int r = serial_read_blocking(serial, drain_buf, sizeof(drain_buf), 50);
            if (r > 0) {
                drained_total += r;
                continue;
            }
            /* Stop on timeout or error; it's fine if nothing was there. */
            break;
        }
        if (drained_total > 0)
            printf(" - flushed %d stale byte(s) before ping.\n", drained_total);
    }
    /* Send ping and expect pong (device may echo input or include CR/LF) */
    const char *ping_cmd = "ping\r";
    char accum[256] = {0};
    size_t accum_len = 0;
    printf(" - strlen(ping_cmd)=%d\n", (int)strlen(ping_cmd));
    int write_ret = serial_write_blocking(serial, ping_cmd, strlen(ping_cmd), 1000);
    if (write_ret < 0) {
        printf(" - failed to send ping to device.\n");
        serial_close(serial);
        sr_serial_dev_inst_free(serial);
        return NULL;
    }

    /* Read in chunks up to an overall timeout, and search for substring "pong". */
    int overall_timeout_ms = 2000;
    int chunk_timeout_ms = 200; /* smaller per-read timeout to accumulate */
    int waited_ms = 0;
    int found = 0;
    while (waited_ms < overall_timeout_ms && accum_len < sizeof(accum) - 1) {
        int to_read = (int)(sizeof(accum) - 1 - accum_len);
        int read_ret = serial_read_blocking(serial, accum + accum_len, to_read, chunk_timeout_ms);
        if (read_ret > 0) {
            accum_len += (size_t)read_ret;
            accum[accum_len] = '\0';
            if (strstr(accum, "pong") != NULL) {
                found = 1;
                break;
            }
            /* Continue reading until timeout or found. */
            continue;
        } else if (read_ret == 0 || read_ret == SR_ERR_TIMEOUT) {
            waited_ms += chunk_timeout_ms;
            continue;
        } else { /* read error */
            printf(" - failed to read pong from device (err=%d).\n", read_ret);
            serial_close(serial);
            sr_serial_dev_inst_free(serial);
            return NULL;
        }
    }

    if (!found) {
        /* Print a short hex dump of what we actually received for debugging. */
        printf(" - device did not reply pong. Received %zu bytes:\n  ", accum_len);
        for (size_t i = 0; i < accum_len && i < 64; i++) {
            printf("%02X ", (unsigned char)accum[i]);
        }
        if (accum_len > 64)
            printf("... ");
        printf("\n  as text: '%.*s'\n", (int)accum_len, accum);
        serial_close(serial);
        sr_serial_dev_inst_free(serial);
        return NULL;
    }

	printf("found device on %s\n", conn);
    /* Create device instance */
    sdi = g_malloc0(sizeof(struct sr_dev_inst));
    sdi->driver = di;
    sdi->status = SR_ST_INACTIVE; /* scanned devices are inactive */
    sdi->vendor = g_strdup("Quantr");
    sdi->model = g_strdup("Device");
    sdi->inst_type = SR_INST_SERIAL;
    sdi->conn = serial;
    sdi->connection_id = g_strdup(conn);
    if (!sdi) {
        serial_close(serial);
        sr_serial_dev_inst_free(serial);
        return NULL;
    }
 
    devc = g_malloc0(sizeof(struct dev_context));
    devc->serial = serial;
    devc->samplerate = 1000000; /* Default 1MHz */
    devc->num_channels = 16; /* STM32 logic analyzer with 16 channels */
    devc->buffer_size = 4096;
    devc->buffer = g_malloc(devc->buffer_size);
    devc->continuous = FALSE;
    sdi->priv = devc;
    /* Create logic channels CH0..CH15 enabled by default. */
    for (int i = 0; i < devc->num_channels; i++) {
        char name[8];
        g_snprintf(name, sizeof(name), "CH%d", i);
        sr_channel_new(sdi, i, SR_CHANNEL_LOGIC, TRUE, name);
    }
     
    serial_close(serial);
    devices = g_slist_append(devices, sdi);
    printf("devices=%p\n", devices);
    return devices;
}
 
/* List devices */
SR_PRIV GSList *quantr_dev_list(const struct sr_dev_driver *di)
{
	printf("quantr_dev_list\n");
    return ((struct sr_dev_driver *)di)->context;
}
 
/* Clear device instances */
SR_PRIV int quantr_dev_clear(const struct sr_dev_driver *di)
{
	printf("quantr_dev_clear\n");
    return std_dev_clear(di);
}
 
/* Get configuration */
SR_PRIV int quantr_config_get(uint32_t key, GVariant **data, const struct sr_dev_inst *sdi, const struct sr_channel_group *cg)
{
	printf("quantr_config_get\n");
    struct dev_context *devc = sdi->priv;
 
    (void)cg;
 
    switch (key) {
    case SR_CONF_SAMPLERATE:
        *data = g_variant_new_uint64(devc->samplerate);
        return SR_OK;
    case SR_CONF_CONTINUOUS:
        *data = g_variant_new_boolean(devc->continuous);
        return SR_OK;
    default:
        return SR_ERR_NA;
    }
}
 
/* Set configuration */
SR_PRIV int quantr_config_set(uint32_t key, GVariant *data, const struct sr_dev_inst *sdi, const struct sr_channel_group *cg)
{
	printf("quantr_config_set\n");
    struct dev_context *devc = sdi->priv;
 
    (void)cg;
 
    if (sdi->status != SR_ST_ACTIVE)
        return SR_ERR_DEV_CLOSED;
 
    switch (key) {
    case SR_CONF_SAMPLERATE:
        devc->samplerate = g_variant_get_uint64(data);
        return SR_OK;
    case SR_CONF_CONTINUOUS:
        devc->continuous = g_variant_get_boolean(data);
        return SR_OK;
    default:
        return SR_ERR_NA;
    }
}
 
/* List configuration options */
SR_PRIV int quantr_config_list(uint32_t key, GVariant **data, const struct sr_dev_inst *sdi, const struct sr_channel_group *cg)
{
	printf("quantr_config_list\n");
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
	printf("quantr_dev_open\n");
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
	printf("quantr_dev_close\n");
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
	printf("quantr_dev_acquisition_start\n");
    struct dev_context *devc = sdi->priv;
    int ret;
 
    if (!devc->serial)
        return SR_ERR;
 
    /* Send start command to device via serial port */
    ret = serial_write_blocking(devc->serial, "START\r", 6, 1000);
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
	printf("quantr_dev_acquisition_stop\n");
    struct dev_context *devc = sdi->priv;
    int ret;
 
    if (!devc->serial || !devc->acquisition_running)
        return SR_OK;
 
    /* Send stop command to device via serial port */
    ret = serial_write_blocking(devc->serial, "STOP\r", 5, 1000);
    if (ret < 0)
        return SR_ERR;
 
    devc->acquisition_running = 0;
    return SR_OK;
}