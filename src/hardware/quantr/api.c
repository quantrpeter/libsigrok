#include <config.h>
#include <libsigrok/libsigrok.h>
#include "libsigrok-internal.h"
#include "protocol.h"
 
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
 
SR_PRIV struct sr_dev_driver quantr_driver_info = {
    .name = "quantr",
    .longname = "Quantr Device",
    .api_version = 1,
    .init = quantr_init,
    .cleanup = quantr_cleanup,
    .scan = quantr_scan,
    .dev_list = quantr_dev_list,
    .dev_clear = quantr_dev_clear,
    .config_get = quantr_config_get,
    .config_set = quantr_config_set,
    .config_list = quantr_config_list,
    .dev_open = quantr_dev_open,
    .dev_close = quantr_dev_close,
    .dev_acquisition_start = quantr_dev_acquisition_start,
    .dev_acquisition_stop = quantr_dev_acquisition_stop,
    .context = NULL,
};
 
SR_REGISTER_DEV_DRIVER(quantr_driver_info);