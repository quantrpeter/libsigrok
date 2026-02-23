#include "protocol.h"
#include <config.h>
#include <stdlib.h>
#include <string.h>
#include <inttypes.h>
#include <libsigrok/libsigrok.h>
#include "libsigrok-internal.h"
 
#define LOG_PREFIX "quantr"
//#define DEBUG
 
static const uint32_t scanopts[] = {
    SR_CONF_CONN,
    SR_CONF_SERIALCOMM,
};
 
static const uint32_t devopts[] = {
    SR_CONF_LOGIC_ANALYZER,
    SR_CONF_SAMPLERATE | SR_CONF_GET | SR_CONF_SET | SR_CONF_LIST,
    SR_CONF_LIMIT_SAMPLES | SR_CONF_GET | SR_CONF_SET | SR_CONF_LIST,
    SR_CONF_CONTINUOUS | SR_CONF_GET | SR_CONF_SET,
};
 
static const uint64_t samplerates[] = {
	SR_HZ(1),
	SR_HZ(100),
	SR_HZ(200),
	SR_HZ(250),
	SR_HZ(500),
    SR_KHZ(1),
    SR_KHZ(10),
    SR_KHZ(20),
    SR_KHZ(25),
    SR_KHZ(50),
    SR_KHZ(100),
    SR_KHZ(200),
    SR_KHZ(250),
    SR_KHZ(500),
};
 
/* Initialize the driver */
SR_PRIV int quantr_init(struct sr_dev_driver *di, struct sr_context *sr_ctx)
{
    return std_init(di, sr_ctx);
}
 
/* Cleanup resources */
SR_PRIV int quantr_cleanup(const struct sr_dev_driver *di)
{
    #ifdef DEBUG
	    printf("quantr_cleanup\n");
    #endif
    return std_cleanup(di);
}
 
/* Scan for devices */
SR_PRIV GSList *quantr_scan(struct sr_dev_driver *di, GSList *options)
{
	#ifdef DEBUG
	printf("Scanning quantr device\n");
	#endif
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
    serialcomm = "921600/8n1/dtr=1/rts=1"; /* Default serial settings with DTR/RTS asserted */
     
    if (sr_serial_extract_options(options, &conn, &serialcomm) != SR_OK){
		#ifdef DEBUG
		printf(" - sr_serial_extract_options is failed\n");
		#endif
        return NULL;
	}
 
    if (!conn){
        return NULL;
	}

	#ifdef DEBUG
	printf(" - connecting to %s, %s\n", conn, serialcomm);
	#endif
 
    /* Try to open the serial port */
    serial = sr_serial_dev_inst_new(conn, serialcomm);
    if (!serial){
		#ifdef DEBUG
		printf(" - failed to open device %s by sr_serial_dev_inst_new\n", conn);
		#endif
        return NULL;
	}
 
    int open_ret = serial_open(serial, SERIAL_RDWR);
    if (open_ret != SR_OK) {
        sr_serial_dev_inst_free(serial);
        #ifdef DEBUG
        printf(" - failed to open device %s (serial_open returned %d)\n", conn, open_ret);
        // Optionally, print strerror if open_ret is errno
        printf(" - strerror: %s\n", strerror(errno));
        #endif
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
        if (drained_total > 0) {
            #ifdef DEBUG
            printf(" - flushed %d stale byte(s) before ping.\n", drained_total);
            #endif
        }
    }
    /* Send ping and expect pong (device may echo input or include CR/LF) */
    const char *ping_cmd = "ping\r";
    char accum[256] = {0};
    size_t accum_len = 0;
    #ifdef DEBUG
    printf(" - strlen(ping_cmd)=%d\n", (int)strlen(ping_cmd));
    #endif
    int write_ret = serial_write_blocking(serial, ping_cmd, strlen(ping_cmd), 1000);
    if (write_ret < 0) {
        #ifdef DEBUG
        printf(" - failed to send ping to device.\n");
        #endif
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
            #ifdef DEBUG
            printf(" - failed to read pong from device (err=%d).\n", read_ret);
            #endif
            serial_close(serial);
            sr_serial_dev_inst_free(serial);
            return NULL;
        }
    }

    if (!found) {
        /* Print a short hex dump of what we actually received for debugging. */
        #ifdef DEBUG
        printf(" - device did not reply pong. Received %zu bytes:\n  ", accum_len);
        for (size_t i = 0; i < accum_len && i < 64; i++) {
            printf("%02X ", (unsigned char)accum[i]);
        }
        if (accum_len > 64)
            printf("... ");
        printf("\n  as text: '%.*s'\n", (int)accum_len, accum);
        #endif
        serial_close(serial);
        sr_serial_dev_inst_free(serial);
        return NULL;
    }

	#ifdef DEBUG
	printf("found device on %s\n", conn);
	#endif
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
    devc->limit_samples = 10000; /* Default 10k samples */
    devc->samples_collected = 0;
    devc->num_channels = 64; /* 64 channels: PA0-15, PB0-15, PC0-15, PD0-15 */
    devc->buffer_size = 4096;
    devc->buffer = g_malloc(devc->buffer_size);
    devc->continuous = FALSE;
    devc->acquisition_running = 0;
    devc->line_pos = 0;
    devc->acquisition_started = FALSE;
    sdi->priv = devc;
    /* Create logic channels CH0..CH15 enabled by default. */
    for (int i = 0; i < devc->num_channels; i++) {
        char name[8];
        g_snprintf(name, sizeof(name), "CH%d", i);
        sr_channel_new(sdi, i, SR_CHANNEL_LOGIC, TRUE, name);
    }
     
    serial_close(serial);
    devices = g_slist_append(devices, sdi);
    #ifdef DEBUG
    printf("devices=%p\n", devices);
    #endif
    return devices;
}
 
/* List devices */
SR_PRIV GSList *quantr_dev_list(const struct sr_dev_driver *di)
{
	#ifdef DEBUG
	printf("quantr_dev_list\n");
	#endif
    return ((struct sr_dev_driver *)di)->context;
}
 
/* Clear device instances */
SR_PRIV int quantr_dev_clear(const struct sr_dev_driver *di)
{
	#ifdef DEBUG
	printf("quantr_dev_clear\n");
	#endif
    return std_dev_clear(di);
}
 
/* Get configuration */
SR_PRIV int quantr_config_get(uint32_t key, GVariant **data, const struct sr_dev_inst *sdi, const struct sr_channel_group *cg)
{
    struct dev_context *devc = sdi->priv;
    #ifdef DEBUG
    printf("quantr_config_get: key=0x%08x\n", key);
    #endif
 
    (void)cg;
 
    switch (key) {
    case SR_CONF_SAMPLERATE:
        #ifdef DEBUG
        printf("  -> SR_CONF_SAMPLERATE: returning %"PRIu64" Hz\n", devc->samplerate);
        #endif
        *data = g_variant_new_uint64(devc->samplerate);
        return SR_OK;
    case SR_CONF_LIMIT_SAMPLES:
        #ifdef DEBUG
        printf("  -> SR_CONF_LIMIT_SAMPLES: returning %"PRIu64" samples\n", devc->limit_samples);
        #endif
        *data = g_variant_new_uint64(devc->limit_samples);
        return SR_OK;
    case SR_CONF_CONTINUOUS:
        #ifdef DEBUG
        printf("  -> SR_CONF_CONTINUOUS: returning %s\n", devc->continuous ? "true" : "false");
        #endif
        *data = g_variant_new_boolean(devc->continuous);
        return SR_OK;
    default:
        #ifdef DEBUG
        printf("  -> Unknown key 0x%08x, returning SR_ERR_NA\n", key);
        #endif
        return SR_ERR_NA;
    }
}
 
/* Set configuration */
SR_PRIV int quantr_config_set(uint32_t key, GVariant *data, const struct sr_dev_inst *sdi, const struct sr_channel_group *cg)
{
    struct dev_context *devc = sdi->priv;
    int ret;
    #ifdef DEBUG
    printf("quantr_config_set: key=0x%08x, device status=%d\n", key, sdi->status);
    #endif
 
    (void)cg;

    switch (key) {
    case SR_CONF_SAMPLERATE:
        devc->samplerate = g_variant_get_uint64(data);
        #ifdef DEBUG
        printf("  -> SR_CONF_SAMPLERATE: setting to %"PRIu64" Hz\n", devc->samplerate);
        #endif
        /* Send new sampling rate to device */
        if (sdi->status == SR_ST_ACTIVE) {
            char rate_cmd[64];
            snprintf(rate_cmd, sizeof(rate_cmd), "rate %"PRIu64"\r", devc->samplerate);
            #ifdef DEBUG
            printf("  -> Sending command: '%s'\n", rate_cmd);
            #endif
            ret = serial_write_blocking(devc->serial, rate_cmd, strlen(rate_cmd), 1000);
            if (ret < 0) {
                #ifdef DEBUG
                printf("  -> Failed to send sampling rate configuration to device (ret=%d)\n", ret);
                #endif
                return SR_ERR;
            }
            #ifdef DEBUG
            printf("  -> Successfully updated sampling rate to: %"PRIu64" Hz\n", devc->samplerate);
            #endif
        }
        return SR_OK;
        
    case SR_CONF_LIMIT_SAMPLES:
        devc->limit_samples = g_variant_get_uint64(data);
        #ifdef DEBUG
        printf("  -> SR_CONF_LIMIT_SAMPLES: setting to %"PRIu64" samples\n", devc->limit_samples);
        #endif
        /* Send new sample limit to device */
        if (sdi->status == SR_ST_ACTIVE) {
            char samples_cmd[64];
            snprintf(samples_cmd, sizeof(samples_cmd), "samples %"PRIu64"\r", devc->limit_samples);
            #ifdef DEBUG
            printf("  -> Sending command: '%s'\n", samples_cmd);
            #endif
            ret = serial_write_blocking(devc->serial, samples_cmd, strlen(samples_cmd), 1000);
            if (ret < 0) {
                #ifdef DEBUG
                printf("  -> Failed to send sample limit configuration to device (ret=%d)\n", ret);
                #endif
                return SR_ERR;
            }
            #ifdef DEBUG
            printf("  -> Successfully updated sample limit to: %"PRIu64" samples\n", devc->limit_samples);
            #endif
        }
        return SR_OK;
        
    case SR_CONF_CONTINUOUS:
        devc->continuous = g_variant_get_boolean(data);
        #ifdef DEBUG
        printf("  -> SR_CONF_CONTINUOUS: setting to %s\n", devc->continuous ? "true" : "false");
        #endif
        return SR_OK;
    default:
        #ifdef DEBUG
        printf("  -> Unknown key 0x%08x, returning SR_ERR_NA\n", key);
        #endif
        return SR_ERR_NA;
    }
}
 
/* List configuration options */
SR_PRIV int quantr_config_list(uint32_t key, GVariant **data, const struct sr_dev_inst *sdi, const struct sr_channel_group *cg)
{
    #ifdef DEBUG
    printf("quantr_config_list: key=0x%08x\n", key);
    #endif
    (void)sdi;
    (void)cg;
 
    switch (key) {
    case SR_CONF_SCAN_OPTIONS:
        #ifdef DEBUG
        printf("  -> SR_CONF_SCAN_OPTIONS: returning scan options array\n");
        #endif
        *data = g_variant_new_fixed_array(G_VARIANT_TYPE_UINT32,
                scanopts, ARRAY_SIZE(scanopts), sizeof(uint32_t));
        return SR_OK;
    case SR_CONF_DEVICE_OPTIONS:
        #ifdef DEBUG
        printf("  -> SR_CONF_DEVICE_OPTIONS: returning device options array\n");
        #endif
        *data = g_variant_new_fixed_array(G_VARIANT_TYPE_UINT32,
                devopts, ARRAY_SIZE(devopts), sizeof(uint32_t));
        return SR_OK;
    case SR_CONF_SAMPLERATE:
        #ifdef DEBUG
        printf("  -> SR_CONF_SAMPLERATE: returning samplerates array\n");
        #endif
        *data = std_gvar_samplerates(samplerates, ARRAY_SIZE(samplerates));
        return SR_OK;
    case SR_CONF_LIMIT_SAMPLES:
        #ifdef DEBUG
        printf("  -> SR_CONF_LIMIT_SAMPLES: returning range 1 to 1,000,000\n");
        #endif
        /* Allow from 1 sample to 1 million samples */
        *data = std_gvar_tuple_u64(1, 1000000);
        return SR_OK;
    default:
        #ifdef DEBUG
        printf("  -> Unknown key 0x%08x, returning SR_ERR_NA\n", key);
        #endif
        return SR_ERR_NA;
    }
}
 
/* Open device */
SR_PRIV int quantr_dev_open(struct sr_dev_inst *sdi)
{
	#ifdef DEBUG
	printf("quantr_dev_open\n");
	#endif
    struct dev_context *devc = sdi->priv;
    int ret;
 
    ret = serial_open(devc->serial, SERIAL_RDWR);
    if (ret != SR_OK){
		#ifdef DEBUG
		printf(" - serial_open failed\n");
		#endif
        return ret;
	}
    
    /* Send initial sampling rate configuration */
    char rate_cmd[64];
    snprintf(rate_cmd, sizeof(rate_cmd), "rate %"PRIu64"\r", devc->samplerate);
    ret = serial_write_blocking(devc->serial, rate_cmd, strlen(rate_cmd), 1000);
    if (ret < 0) {
        #ifdef DEBUG
        printf("Failed to send initial sampling rate configuration\n");
        #endif
        /* Don't fail device open for this, just log it */
    } else {
        #ifdef DEBUG
        printf("Configured sampling rate: %"PRIu64" Hz\n", devc->samplerate);
        #endif
    }
 
    sdi->status = SR_ST_ACTIVE;
    return SR_OK;
}
 
/* Close device */
SR_PRIV int quantr_dev_close(struct sr_dev_inst *sdi)
{
	#ifdef DEBUG
	printf("quantr_dev_close\n");
	#endif
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
	#ifdef DEBUG
	printf("quantr_dev_acquisition_start\n");
	#endif
    struct dev_context *devc = sdi->priv;
    int ret;
 
    if (!devc->serial)
        return SR_ERR;
 
    /* Initialize parsing state */
    devc->line_pos = 0;
    devc->acquisition_started = FALSE;
    devc->samples_collected = 0;
    
    /* Send sampling rate configuration to device */
    char rate_cmd[64];
    snprintf(rate_cmd, sizeof(rate_cmd), "rate %"PRIu64"\r", devc->samplerate);
    ret = serial_write_blocking(devc->serial, rate_cmd, strlen(rate_cmd), 1000);
    if (ret < 0) {
        #ifdef DEBUG
        printf("Failed to send sampling rate configuration\n");
        #endif
        return SR_ERR;
    }
    
    /* Wait for acknowledgment */
    char ack_buffer[128];
    ret = serial_read_blocking(devc->serial, ack_buffer, sizeof(ack_buffer) - 1, 1000);
    if (ret > 0) {
        ack_buffer[ret] = '\0';
        #ifdef DEBUG
        printf("Rate config response: '%s'\n", ack_buffer);
        #endif
    }
    
    /* Send sample limit configuration to device */
    char samples_cmd[64];
    snprintf(samples_cmd, sizeof(samples_cmd), "samples %"PRIu64"\r", devc->limit_samples);
    ret = serial_write_blocking(devc->serial, samples_cmd, strlen(samples_cmd), 1000);
    if (ret < 0) {
        #ifdef DEBUG
        printf("Failed to send sample limit configuration\n");
        #endif
        return SR_ERR;
    }
    
    /* Wait for acknowledgment */
    ret = serial_read_blocking(devc->serial, ack_buffer, sizeof(ack_buffer) - 1, 1000);
    if (ret > 0) {
        ack_buffer[ret] = '\0';
        #ifdef DEBUG
        printf("Sample limit config response: '%s'\n", ack_buffer);
        #endif
    }
    
    /* Send start command to device via serial port */
    ret = serial_write_blocking(devc->serial, "start\r", 6, 1000);
    if (ret < 0)
        return SR_ERR;
 
    devc->acquisition_running = 1;
     
    /* Set up polling mechanism to check for incoming data */
    /* This will call quantr_receive_data whenever data is available */
    return serial_source_add(sdi->session, devc->serial, G_IO_IN, 100,
                            quantr_receive_data, (void *)sdi);
}
 
/* Stop acquisition */
SR_PRIV int quantr_dev_acquisition_stop(struct sr_dev_inst *sdi)
{
	#ifdef DEBUG
	printf("quantr_dev_acquisition_stop\n");
	#endif
    struct dev_context *devc = sdi->priv;
    int ret;
 
    if (!devc->serial || !devc->acquisition_running)
        return SR_OK;
 
    /* Remove the serial source from polling */
    serial_source_remove(sdi->session, devc->serial);
    
    /* Send stop command to device via serial port */
    ret = serial_write_blocking(devc->serial, "stop\r", 5, 1000);
    if (ret < 0)
        return SR_ERR;
 
    /* Send end packet if acquisition was running and started */
    if (devc->acquisition_started) {
        std_session_send_df_end(sdi);
    }
    
    devc->acquisition_running = 0;
    devc->acquisition_started = FALSE;
    devc->line_pos = 0;
    
    return SR_OK;
}

/* Process a complete line from the STM32 */
static int process_line(struct sr_dev_inst *sdi, const char *line)
{
    struct dev_context *devc = sdi->priv;
    struct sr_datafeed_packet packet;
    struct sr_datafeed_logic logic;
    uint32_t timestamp;
    uint32_t data_bytes[8];
    uint8_t sample_data[8];
    int i;
    
    #ifdef DEBUG
    printf("Processing line: '%s'\n", line);
    #endif
    
    /* Check for control messages */
    if (strcmp(line, "started") == 0) {
        #ifdef DEBUG
        printf("Device started acquisition\n");
        #endif
        devc->acquisition_started = TRUE;
        std_session_send_df_header(sdi);
        return SR_OK;
    }
    
    if (strcmp(line, "end") == 0) {
        #ifdef DEBUG
        printf("Device finished acquisition\n");
        #endif
        std_session_send_df_end(sdi);
        devc->acquisition_running = 0;
        devc->acquisition_started = FALSE;
        return SR_OK;
    }
    
    /* Skip processing data lines if acquisition hasn't officially started */
    if (!devc->acquisition_started) {
        return SR_OK;
    }
    
    /* Parse data line: "0 > 0xAA 0xBB 0xCC 0xDD 0xEE 0xFF 0x11 0x22"
     * bytes 0-1: GPIOA (PA0-PA15)
     * bytes 2-3: GPIOB (PB0-PB15)
     * bytes 4-5: GPIOC (PC0-PC15)
     * bytes 6-7: GPIOD (PD0-PD15)
     */
    if (sscanf(line, "%u > 0x%02x 0x%02x 0x%02x 0x%02x 0x%02x 0x%02x 0x%02x 0x%02x",
               &timestamp,
               &data_bytes[0], &data_bytes[1], &data_bytes[2], &data_bytes[3],
               &data_bytes[4], &data_bytes[5], &data_bytes[6], &data_bytes[7]) == 9) {
        
        /* Convert to byte array */
        for (i = 0; i < 8; i++) {
            sample_data[i] = (uint8_t)data_bytes[i];
        }
        
        #ifdef DEBUG
        printf("Parsed sample %"PRIu64": timestamp=%u, "
               "A=0x%02x%02x B=0x%02x%02x C=0x%02x%02x D=0x%02x%02x\n",
               devc->samples_collected + 1, timestamp,
               sample_data[1], sample_data[0],
               sample_data[3], sample_data[2],
               sample_data[5], sample_data[4],
               sample_data[7], sample_data[6]);
        #endif
        
        /* Send logic data packet:
         * unitsize = 8 bytes (64 channels: PA0-15, PB0-15, PC0-15, PD0-15)
         * length   = 8 bytes (one sample)
         */
        packet.type = SR_DF_LOGIC;
        packet.payload = &logic;
        logic.length = 8;
        logic.unitsize = 8;
        logic.data = sample_data;
        
        sr_session_send(sdi, &packet);
        
        /* Increment sample counter and check limit */
        devc->samples_collected++;
        #ifdef DEBUG
        printf("Sample counter: %"PRIu64" / %"PRIu64" (limit), continuous=%s\n", 
               devc->samples_collected, devc->limit_samples, devc->continuous ? "true" : "false");
        #endif
               
        if (!devc->continuous && devc->samples_collected >= devc->limit_samples) {
            #ifdef DEBUG
            printf("*** Reached sample limit (%"PRIu64" samples), stopping acquisition ***\n", devc->limit_samples);
            #endif
            quantr_dev_acquisition_stop(sdi);
        }
        
        return SR_OK;
    }
    
    /* If we get here, the line format wasn't recognized */
    #ifdef DEBUG
    printf("Unrecognized line format: '%s'\n", line);
    #endif
    return SR_OK;
}

/* Receive data callback - called when data is available on serial port */
SR_PRIV int quantr_receive_data(int fd, int revents, void *cb_data)
{
    struct sr_dev_inst *sdi;
    struct dev_context *devc;
    uint8_t buffer[256];
    int len, i;
    
    (void)fd;
    (void)revents;
    
    if (!(sdi = cb_data))
        return TRUE;
        
    if (!(devc = sdi->priv))
        return TRUE;
        
    if (!devc->acquisition_running)
        return FALSE;  /* Stop polling */
    
    /* Read available data from serial port */
    len = serial_read_nonblocking(devc->serial, buffer, sizeof(buffer) - 1);
    if (len <= 0)
        return TRUE;  /* Continue polling, no data available */
    
    buffer[len] = '\0';  /* Null terminate for safety */
    #ifdef DEBUG
    printf("Received %d bytes: '%.*s'\n", len, len, buffer);
    #endif
    
    /* Process each character to build complete lines */
    for (i = 0; i < len; i++) {
        char c = buffer[i];
        
        /* Handle line endings */
        if (c == '\r' || c == '\n') {
            if (devc->line_pos > 0) {
                /* We have a complete line */
                devc->line_buffer[devc->line_pos] = '\0';
                process_line(sdi, devc->line_buffer);
                devc->line_pos = 0;  /* Reset for next line */
            }
            /* Skip empty lines (handles CRLF) */
        } else {
            /* Accumulate line characters */
            if (devc->line_pos < sizeof(devc->line_buffer) - 1) {
                devc->line_buffer[devc->line_pos++] = c;
            } else {
                /* Line too long, reset */
                #ifdef DEBUG
                printf("Line too long, resetting buffer\n");
                #endif
                devc->line_pos = 0;
            }
        }
    }
    
    return TRUE;  /* Continue polling */
}