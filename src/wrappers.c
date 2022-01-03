#include "wrappers.h"
#include <string.h>

void hydro_kx_keygen_wrap(
    uint8_t pk[hydro_kx_PUBLICKEYBYTES],
    uint8_t sk[hydro_kx_SECRETKEYBYTES]) {

    hydro_kx_keypair kp;
    hydro_kx_keygen(&kp);

    memcpy(pk, kp.pk, hydro_kx_PUBLICKEYBYTES);
    memcpy(sk, kp.sk, hydro_kx_SECRETKEYBYTES);
}


int hydro_kx_kk_2_wrap(
    uint8_t rx_session[hydro_kx_SESSIONKEYBYTES],
    uint8_t tx_session[hydro_kx_SESSIONKEYBYTES],
    uint8_t packet2[hydro_kx_KK_PACKET2BYTES],
    const uint8_t packet1[hydro_kx_KK_PACKET1BYTES],
    const uint8_t peer_static_pk[hydro_kx_PUBLICKEYBYTES],
    uint8_t pk_static[hydro_kx_PUBLICKEYBYTES],
    uint8_t sk_static[hydro_kx_SECRETKEYBYTES]) {

    hydro_kx_session_keypair session_kp;

    hydro_kx_keypair static_kp;
    memcpy(static_kp.pk, pk_static, hydro_kx_PUBLICKEYBYTES);
    memcpy(static_kp.sk, sk_static, hydro_kx_SECRETKEYBYTES);

    int ret = hydro_kx_kk_2(
        &session_kp,
        packet2,
        packet1,
        peer_static_pk,
        &static_kp);

    if (ret != 0) {
        return ret;
    }

    memcpy(rx_session, session_kp.rx, hydro_kx_SESSIONKEYBYTES);
    memcpy(tx_session, session_kp.tx, hydro_kx_SESSIONKEYBYTES);

    return 0;
}


int hydro_kx_kk_3_wrap(
    uint8_t pk_ephemeral[hydro_kx_PUBLICKEYBYTES],
    uint8_t sk_ephemeral[hydro_kx_SECRETKEYBYTES],
    uint32_t hash_state_state[12],
    uint8_t hash_state_buf_off,
    uint8_t hash_state_align[3],
    uint8_t rx_session[hydro_kx_SESSIONKEYBYTES],
    uint8_t tx_session[hydro_kx_SESSIONKEYBYTES],
    const uint8_t packet2[hydro_kx_KK_PACKET2BYTES],
    uint8_t pk_static[hydro_kx_PUBLICKEYBYTES],
    uint8_t sk_static[hydro_kx_SECRETKEYBYTES]) {

    hydro_kx_state state;
    memcpy(state.eph_kp.pk, pk_ephemeral, hydro_kx_PUBLICKEYBYTES);
    memcpy(state.eph_kp.sk, sk_ephemeral, hydro_kx_SECRETKEYBYTES);
    memcpy(state.h_st.state, hash_state_state, 12*4);
    state.h_st.buf_off = hash_state_buf_off;
    memcpy(state.h_st.align, hash_state_align, 3);

    hydro_kx_session_keypair session_kp;

    hydro_kx_keypair static_kp;
    memcpy(static_kp.pk, pk_static, hydro_kx_PUBLICKEYBYTES);
    memcpy(static_kp.sk, sk_static, hydro_kx_SECRETKEYBYTES);

    int ret = hydro_kx_kk_3(&state, &session_kp, packet2, &static_kp);
    if (ret != 0) {
        return ret;
    }

    memcpy(rx_session, session_kp.rx, hydro_kx_SESSIONKEYBYTES);
    memcpy(tx_session, session_kp.tx, hydro_kx_SESSIONKEYBYTES);
}


int hydro_kx_kk_1_wrap(
    uint8_t pk_ephemeral[hydro_kx_PUBLICKEYBYTES],
    uint8_t sk_ephemeral[hydro_kx_SECRETKEYBYTES],
    uint32_t hash_state_state[12],
    uint8_t* hash_state_buf_off,
    uint8_t hash_state_align[3],
    uint8_t packet1[hydro_kx_KK_PACKET1BYTES],
    const uint8_t peer_static_pk[hydro_kx_PUBLICKEYBYTES],
    uint8_t pk_static[hydro_kx_PUBLICKEYBYTES],
    uint8_t sk_static[hydro_kx_SECRETKEYBYTES]) {


    hydro_kx_keypair static_kp;
    memcpy(static_kp.pk, pk_static, hydro_kx_PUBLICKEYBYTES); 
    memcpy(static_kp.sk, sk_static, hydro_kx_SECRETKEYBYTES);

    hydro_kx_state state;

    int ret =
        hydro_kx_kk_1(&state, packet1, peer_static_pk, &static_kp);
    
    if (ret != 0) {
        return ret;
    }

    memcpy(pk_ephemeral, state.eph_kp.pk, hydro_kx_PUBLICKEYBYTES);
    memcpy(sk_ephemeral, state.eph_kp.sk, hydro_kx_SECRETKEYBYTES);
    memcpy(hash_state_state, state.h_st.state, 12*4);
    *hash_state_buf_off = state.h_st.buf_off;
    memcpy(hash_state_align, state.h_st.align, 3);

    return 0;
}
