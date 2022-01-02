#include "wrappers.h"

void hydro_kx_keygen_wrap(
    uint8_t pk[hydro_kx_PUBLICKEYBYTES],
    uint8_t sk[hydro_kx_SECRETKEYBYTES]) {

    hydro_kx_keypair kp = { .pk = pk , .sk = sk };
    hydro_kx_keygen(&kp);
}
