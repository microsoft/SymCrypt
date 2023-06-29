#pragma once
#include "kat_IEEE802_11SaeCustom.dat.h"
#include "kat_authenc.dat.h"
#include "kat_blockcipher.dat.h"
#include "kat_cxof.dat.h"
#include "kat_dh.dat.h"
#include "kat_dsa.dat.h"
#include "kat_ecdsa.dat.h"
#include "kat_hash.dat.h"
#include "kat_hash_long.dat.h"
#include "kat_kdf.dat.h"
#include "kat_kmac.dat.h"
#include "kat_mac.dat.h"
#include "kat_rng.dat.h"
#include "kat_rsaenc.dat.h"
#include "kat_rsasign.dat.h"
#include "kat_streamcipher.dat.h"
#include "kat_xof.dat.h"
#include "kat_xts.dat.h"

static inline
size_t GetResourceBytes(const char *resourceName, const char **bytes)
{
    if (strcasecmp(resourceName, "kat_IEEE802_11SaeCustom.dat") == 0) {
        *bytes = kat_IEEE802_11SaeCustom_dat;
        return sizeof(kat_IEEE802_11SaeCustom_dat);
    }
    if (strcasecmp(resourceName, "kat_authenc.dat") == 0) {
        *bytes = kat_authenc_dat;
        return sizeof(kat_authenc_dat);
    }
    if (strcasecmp(resourceName, "kat_blockcipher.dat") == 0) {
        *bytes = kat_blockcipher_dat;
        return sizeof(kat_blockcipher_dat);
    }
    if (strcasecmp(resourceName, "kat_cxof.dat") == 0) {
        *bytes = kat_cxof_dat;
        return sizeof(kat_cxof_dat);
    }
    if (strcasecmp(resourceName, "kat_dh.dat") == 0) {
        *bytes = kat_dh_dat;
        return sizeof(kat_dh_dat);
    }
    if (strcasecmp(resourceName, "kat_dsa.dat") == 0) {
        *bytes = kat_dsa_dat;
        return sizeof(kat_dsa_dat);
    }
    if (strcasecmp(resourceName, "kat_ecdsa.dat") == 0) {
        *bytes = kat_ecdsa_dat;
        return sizeof(kat_ecdsa_dat);
    }
    if (strcasecmp(resourceName, "kat_hash.dat") == 0) {
        *bytes = kat_hash_dat;
        return sizeof(kat_hash_dat);
    }
    if (strcasecmp(resourceName, "kat_hash_long.dat") == 0) {
        *bytes = kat_hash_long_dat;
        return sizeof(kat_hash_long_dat);
    }
    if (strcasecmp(resourceName, "kat_kdf.dat") == 0) {
        *bytes = kat_kdf_dat;
        return sizeof(kat_kdf_dat);
    }
    if (strcasecmp(resourceName, "kat_kmac.dat") == 0) {
        *bytes = kat_kmac_dat;
        return sizeof(kat_kmac_dat);
    }
    if (strcasecmp(resourceName, "kat_mac.dat") == 0) {
        *bytes = kat_mac_dat;
        return sizeof(kat_mac_dat);
    }
    if (strcasecmp(resourceName, "kat_rng.dat") == 0) {
        *bytes = kat_rng_dat;
        return sizeof(kat_rng_dat);
    }
    if (strcasecmp(resourceName, "kat_rsaenc.dat") == 0) {
        *bytes = kat_rsaenc_dat;
        return sizeof(kat_rsaenc_dat);
    }
    if (strcasecmp(resourceName, "kat_rsasign.dat") == 0) {
        *bytes = kat_rsasign_dat;
        return sizeof(kat_rsasign_dat);
    }
    if (strcasecmp(resourceName, "kat_streamcipher.dat") == 0) {
        *bytes = kat_streamcipher_dat;
        return sizeof(kat_streamcipher_dat);
    }
    if (strcasecmp(resourceName, "kat_xof.dat") == 0) {
        *bytes = kat_xof_dat;
        return sizeof(kat_xof_dat);
    }
    if (strcasecmp(resourceName, "kat_xts.dat") == 0) {
        *bytes = kat_xts_dat;
        return sizeof(kat_xts_dat);
    }
    return 0;
}
