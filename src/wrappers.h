#include "hydrogen.h"

void hydro_kx_keygen_wrap(uint8_t pk[hydro_kx_PUBLICKEYBYTES], uint8_t sk[hydro_kx_SECRETKEYBYTES]);

int hydro_kx_kk_1_wrap(
    uint8_t pk_ephemeral[hydro_kx_PUBLICKEYBYTES],
    uint8_t sk_ephemeral[hydro_kx_SECRETKEYBYTES],
    uint32_t hash_state_state[12],
    uint8_t* hash_state_buf_off,
    uint8_t hash_state_align[3],
    uint8_t packet1[hydro_kx_KK_PACKET1BYTES],
    const uint8_t peer_static_pk[hydro_kx_PUBLICKEYBYTES],
    uint8_t pk_static[hydro_kx_PUBLICKEYBYTES],
    uint8_t sk_static[hydro_kx_SECRETKEYBYTES]);
