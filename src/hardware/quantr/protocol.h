#ifndef LIBSIGROK_HARDWARE_QUANTR_PROTOCOL_H
#define LIBSIGROK_HARDWARE_QUANTR_PROTOCOL_H
 
#include <stdint.h>
#include <libsigrok/libsigrok.h>
#include "libsigrok-internal.h"
 
/* Device-specific context */
struct dev_context {
    struct sr_serial_dev_inst *serial;
    uint64_t samplerate;
    int num_channels;
    uint8_t *buffer;
    size_t buffer_size;
    int acquisition_running;
    gboolean continuous;
    
    /* Line parsing state */
    char line_buffer[256];
    size_t line_pos;
    gboolean acquisition_started;
};
 
/* Function prototypes */
SR_PRIV int quantr_init(struct sr_dev_driver *di, struct sr_context *sr_ctx);
SR_PRIV int quantr_cleanup(const struct sr_dev_driver *di);
SR_PRIV GSList *quantr_scan(struct sr_dev_driver *di, GSList *options);
SR_PRIV GSList *quantr_dev_list(const struct sr_dev_driver *di);
SR_PRIV int quantr_dev_clear(const struct sr_dev_driver *di);
SR_PRIV int quantr_config_get(uint32_t key, GVariant **data, const struct sr_dev_inst *sdi, const struct sr_channel_group *cg);
SR_PRIV int quantr_config_set(uint32_t key, GVariant *data, const struct sr_dev_inst *sdi, const struct sr_channel_group *cg);
SR_PRIV int quantr_config_list(uint32_t key, GVariant **data, const struct sr_dev_inst *sdi, const struct sr_channel_group *cg);
SR_PRIV int quantr_dev_open(struct sr_dev_inst *sdi);
SR_PRIV int quantr_dev_close(struct sr_dev_inst *sdi);
SR_PRIV int quantr_dev_acquisition_start(const struct sr_dev_inst *sdi);
SR_PRIV int quantr_dev_acquisition_stop(struct sr_dev_inst *sdi);
SR_PRIV int quantr_receive_data(int fd, int revents, void *cb_data);
 
#endif