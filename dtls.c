/*******************************************************************************
 *
 * Copyright (c) 2011-2022 Olaf Bergmann (TZI) and others.
 * All rights reserved. This program and the accompanying materials
 * are made available under the terms of the Eclipse Public License v1.0
 * and Eclipse Distribution License v. 1.0 which accompanies this distribution.
 *
 * The Eclipse Public License is available at http://www.eclipse.org/legal/epl-v10.html
 * and the Eclipse Distribution License is available at
 * http://www.eclipse.org/org/documents/edl-v10.php.
 *
 * Contributors:
 *    Olaf Bergmann  - initial API and implementation
 *    Hauke Mehrtens - memory optimization, ECC integration
 *    Achim Kraus    - session recovery
 *    Sachin Agrawal - rehandshake support
 *
 *******************************************************************************/

#include "tinydtls.h"
#include "dtls_time.h"

#include <stdio.h>
#include <stdlib.h>
#ifdef HAVE_ASSERT_H
#include <assert.h>
#endif
#ifndef WITH_CONTIKI
#include <stdlib.h>
#include "global.h"
#endif /* WITH_CONTIKI */
#ifdef HAVE_INTTYPES_H
#define __STDC_FORMAT_MACROS
#include <inttypes.h>
#else
#  ifndef PRIu64
#    define PRIu64 "llu"
#  endif
#  ifndef PRIx64
#    define PRIx64 "llx"
#  endif
#endif /* HAVE_INTTYPES_H */

#include "utlist.h"
#ifndef DTLS_PEERS_NOHASH
#include "uthash.h"
#endif /* DTLS_PEERS_NOHASH */

#include "dtls_debug.h"
#include "numeric.h"
#include "netq.h"
#include "dtls.h"

#include "alert.h"
#include "session.h"
#include "dtls_prng.h"
#include "dtls_mutex.h"

#ifdef WITH_SHA256
#  include "hmac.h"
#endif /* WITH_SHA256 */

#ifdef WITH_ZEPHYR
LOG_MODULE_DECLARE(TINYDTLS, CONFIG_TINYDTLS_LOG_LEVEL);
#endif /* WITH_ZEPHYR */

#define DTLS10_VERSION 0xfeff
#define DTLS12_VERSION 0xfefd
#define DTLS13_VERSION 0xfefc

/* Flags for dtls_destroy_peer()
 *
 *  DTLS_DESTROY_CLOSE indicates that the connection should be closed
 *                     when applicable
 */
#define DTLS_DESTROY_CLOSE 0x02

#ifdef RIOT_VERSION
# include <memarray.h>

dtls_context_t dtlscontext_storage_data[DTLS_CONTEXT_MAX];
memarray_t dtlscontext_storage;
#endif /* RIOT_VERSION */

#define dtls_set_version(H,V) dtls_int_to_uint16((H)->version, (V))
#define dtls_set_content_type(H,V) ((H)->content_type = (V) & 0xff)
#define dtls_set_length(H,V)  ((H)->length = (V))

#define dtls_get_content_type(H) ((H)->content_type & 0xff)
#define dtls_get_version(H) dtls_uint16_to_int((H)->version)
#define dtls_get_epoch(H) dtls_uint16_to_int((H)->epoch)
#define dtls_get_sequence_number(H) dtls_uint48_to_int((H)->sequence_number)
#define dtls_get_length(H) dtls_uint16_to_int((H)->length)
#define dtls_get_fragment_length(H) dtls_uint24_to_int((H)->fragment_length)

#ifdef DTLS_PEERS_NOHASH
#define FIND_PEER(head,sess,out)                                \
  do {                                                          \
    dtls_peer_t * tmp;                                          \
    (out) = NULL;                                               \
    LL_FOREACH((head), tmp) {                                   \
      if (dtls_session_equals(&tmp->session, (sess))) {         \
        (out) = tmp;                                            \
        break;                                                  \
      }                                                         \
    }                                                           \
  } while (0)
#define DEL_PEER(head,delptr)                   \
  if ((head) != NULL && (delptr) != NULL) {	\
    LL_DELETE(head,delptr);                     \
  }
#define ADD_PEER(head,sess,add)                 \
  LL_PREPEND(ctx->peers, peer);
#else /* DTLS_PEERS_NOHASH */
#define FIND_PEER(head,sess,out)		\
  HASH_FIND(hh,head,sess,sizeof(session_t),out)
#define ADD_PEER(head,sess,add)                 \
  HASH_ADD(hh,head,sess,sizeof(session_t),add)
#define DEL_PEER(head,delptr)                   \
  if ((head) != NULL && (delptr) != NULL) {	\
    HASH_DELETE(hh,head,delptr);		\
  }
#endif /* DTLS_PEERS_NOHASH */

#define DTLS_RH_LENGTH sizeof(dtls_record_header_t)
#define DTLS_HS_LENGTH sizeof(dtls_handshake_header_t)
/*
 * ClientHello:
 *
 * session_length         := 1 byte
 * session                := 0 bytes
 * cookie_length          := 1 byte
 * cookie                 := n bytes
 * cipher_length          := 2 bytes
 * cipher suites (max)    := 2 bytes + max * 2
 * compression_length     := 1 byte
 * compression            := 1 byte
 * extensions_length      := 2 bytes   => 10 + max * 2
 *
 * client_cert_type       := 6 bytes
 * server_cert_type       := 6 bytes
 * ec curves              := 8 bytes
 * ec point format        := 6 bytes   => 26
 * sign. and hash algos   := 8 bytes
 * cookie, empty          := 6 bytes
 * key share, empty       := 6 bytes
 * extended master secret := 4 bytes
 * connection id, empty   := 5 bytes   => 29
 * key share entry        := 65 bytes
 */
#define DTLS_CH_LENGTH sizeof(dtls_client_hello_t) /* no variable length fields! */
#define DTLS_COOKIE_LENGTH_MAX 64 // MF: was 32. what is a good value here?
#define DTLS_CH_LENGTH_MAX DTLS_CH_LENGTH + DTLS_COOKIE_LENGTH_MAX + 10 + (2 * DTLS_MAX_CIPHER_SUITES) + 26 + 29 + 65 // MF: FIXME set max extension size
#define DTLS_HV_LENGTH sizeof(dtls_hello_verify_t)
/*
 * ServerHello:
 *
 * version                := 2 bytes
 * random                 := 32 bytes
 * session_length         := 1 byte
 * session                := 0 bytes
 * cipher suite           := 2 bytes
 * compression            := 1 byte
 */
#define DTLS_SH_LENGTH (2 + DTLS_RANDOM_LENGTH + 1 + 2 + 1)
#define DTLS_SKEXEC_LENGTH (1 + 2 + 1 + 1 + DTLS_EC_KEY_SIZE + DTLS_EC_KEY_SIZE + 1 + 1 + 2 + 70)
#define DTLS_SKEXECPSK_LENGTH_MIN 2
#define DTLS_SKEXECPSK_LENGTH_MAX 2 + DTLS_PSK_MAX_CLIENT_IDENTITY_LEN
#define DTLS_CKXPSK_LENGTH_MIN 2
#define DTLS_CKXEC_LENGTH (1 + 1 + max(DTLS_EC_KEY_SIZE + DTLS_EC_KEY_SIZE, DTLS_PSK_MAX_CLIENT_IDENTITY_LEN))
#define DTLS_CV_LENGTH (1 + 1 + 2 + 1 + 1 + 1 + 1 + DTLS_EC_KEY_SIZE + 1 + 1 + DTLS_EC_KEY_SIZE)
#define DTLS_FIN_LENGTH DTLS_MAC_LENGTH // 12

/*
 * HelloRetryRequest:
 * 
 * ServerHello
 * extensions_length      := 2 bytes
 * ext supported_versions := 6 bytes
 * ext key_share          := 6 bytes
 * ext cookie             := 6 bytes + cookie length
 */
#define DTLS_HRR_LENGTH_MAX (DTLS_SH_LENGTH + 2 + 6 + 6 + 6 + DTLS_COOKIE_LENGTH)

#define DTLS_ALERT_LENGTH 2 /* length of the Alert message */

#define HS_HDR_LENGTH  DTLS_RH_LENGTH + DTLS_HS_LENGTH
#define HV_HDR_LENGTH  HS_HDR_LENGTH + DTLS_HV_LENGTH

#define DTLS_COOKIE_LENGTH sizeof(dtls_cookie_t)

#define UHDR_MAGIC_VAL          (1 << 5) /* 00100000 */
#define UHDR_MAGIC_BITS         (3 << 5) /* 11100000 */
#define UHDR_CID_BIT            (1 << 4) /* 00010000 */
#define UHDR_SEQ_LEN_BIT        (1 << 3) /* 00000100 */
#define UHDR_LENGTH_BIT         (1 << 2) /* 00000100 */
#define UHDR_EPOCH_BITS         3        /* 00000011 */
#define DTLS_RN_MASK_LENGTH     16       /* AES */

#define HIGH(V) (((V) >> 8) & 0xff)
#define LOW(V)  ((V) & 0xff)

#define DTLS_RECORD_HEADER(M) ((dtls_record_header_t *)(M))
#define DTLS_HANDSHAKE_HEADER(M) ((dtls_handshake_header_t *)(M))

#define HANDSHAKE(M) ((dtls_handshake_header_t *)((M) + DTLS_RH_LENGTH))
#define CLIENTHELLO(M) ((dtls_client_hello_t *)((M) + HS_HDR_LENGTH))

/* The length check here should work because dtls_*_to_int() works on
 * unsigned char. Otherwise, broken messages could cause severe
 * trouble. Note that this macro jumps out of the current program flow
 * when the message is too short. Beware!
 */
#define SKIP_VAR_FIELD(P,L,T) {						\
    if (L < dtls_ ## T ## _to_int(P) + sizeof(T))			\
      goto error;							\
    L -= dtls_ ## T ## _to_int(P) + sizeof(T);				\
    P += dtls_ ## T ## _to_int(P) + sizeof(T);				\
  }

/* some constants for the PRF */
#define PRF_LABEL(Label) prf_label_##Label
#define PRF_LABEL_SIZE(Label) (sizeof(PRF_LABEL(Label)) - 1)

// static const unsigned char prf_label_master[] = "master secret";
// static const unsigned char prf_label_extended_master[] = "extended master secret";
// static const unsigned char prf_label_key[] = "key expansion";
// static const unsigned char prf_label_client[] = "client";
// static const unsigned char prf_label_server[] = "server";
// static const unsigned char prf_label_finished[] = " finished";

static const uint8 hello_retry_magic[DTLS_RANDOM_LENGTH] = {
  0xCF, 0x21, 0xAD, 0x74, 0xE5, 0x9A, 0x61, 0x11,
  0xBE, 0x1D, 0x8C, 0x02, 0x1E, 0x65, 0xB8, 0x91,
  0xC2, 0xA2, 0x11, 0x16, 0x7A, 0xBB, 0x8C, 0x5E,
  0x07, 0x9E, 0x09, 0xE2, 0xC8, 0xA8, 0x33, 0x9C
};

#ifdef DTLS_ECC
/* first part of Raw public key, the is the start of the Subject Public Key */
static const unsigned char cert_asn1_header[] = {
  0x30, 0x59, /* SEQUENCE, length 89 bytes */
    0x30, 0x13, /* SEQUENCE, length 19 bytes */
      0x06, 0x07, /* OBJECT IDENTIFIER ecPublicKey (1 2 840 10045 2 1) */
        0x2A, 0x86, 0x48, 0xCE, 0x3D, 0x02, 0x01,
      0x06, 0x08, /* OBJECT IDENTIFIER prime256v1 (1 2 840 10045 3 1 7) */
        0x2A, 0x86, 0x48, 0xCE, 0x3D, 0x03, 0x01, 0x07,
      0x03, 0x42, 0x00, /* BIT STRING, length 66 bytes, 0 bits unused */
         0x04 /* uncompressed, followed by the r und s values of the public key */
};
#endif /* DTLS_ECC */

#ifdef WITH_CONTIKI

PROCESS(dtls_retransmit_process, "DTLS retransmit process");

#endif /* WITH_CONTIKI */

#if defined(WITH_CONTIKI) ||  defined(WITH_LWIP)
static dtls_context_t the_dtls_context;

static inline dtls_context_t *
malloc_context(void) {
  return &the_dtls_context;
}

static inline void
free_context(dtls_context_t *context) {
  (void)context;
}

#endif /* WITH_CONTIKI || WITH_LWIP */

#ifdef RIOT_VERSION
static inline dtls_context_t *
malloc_context(void) {
     return (dtls_context_t *) memarray_alloc(&dtlscontext_storage);
}

static inline void free_context(dtls_context_t *context) {
  memarray_free(&dtlscontext_storage, context);
}
#endif /* RIOT_VERSION */

#if defined(WITH_POSIX) || defined(IS_WINDOWS)

static inline dtls_context_t *
malloc_context(void) {
  return (dtls_context_t *)malloc(sizeof(dtls_context_t));
}

static inline void
free_context(dtls_context_t *context) {
  free(context);
}

#endif /* WITH_POSIX */

void
dtls_init(void) {
  dtls_clock_init();
  crypto_init();
  netq_init();
  peer_init();

#ifdef RIOT_VERSION
memarray_init(&dtlscontext_storage, dtlscontext_storage_data,
              sizeof(dtls_context_t), DTLS_CONTEXT_MAX);
#endif /* RIOT_VERSION */
}

/* Calls cb_alert() with given arguments if defined, otherwise an
 * error message is logged and the result is -1. This is just an
 * internal helper.
 */
#define CALL(Context, which, ...)					\
  ((Context)->h && (Context)->h->which					\
   ? (Context)->h->which((Context), __VA_ARGS__)			\
   : -1)

static int
dtls_send_multi(dtls_context_t *ctx, dtls_peer_t *peer,
		dtls_security_parameters_t *security , session_t *session,
		unsigned char type, uint8 *buf_array[],
		size_t buf_len_array[], size_t buf_array_len);

static int
handle_alert(dtls_context_t *ctx, dtls_peer_t *peer,
		uint8 *record_header, uint8 *data, size_t data_length);

/**
 * Sends the fragment of length \p buflen given in \p buf to the
 * specified \p peer. The data will be MAC-protected and encrypted
 * according to the selected cipher and split into one or more DTLS
 * records of the specified \p type. This function returns the number
 * of bytes that were sent, or \c -1 if an error occurred.
 *
 * \param ctx    The DTLS context to use.
 * \param peer   The remote peer.
 * \param type   The content type of the record.
 * \param buf    The data to send.
 * \param buflen The actual length of \p buf.
 * \return Less than zero on error, the number of bytes written otherwise.
 */
static int
dtls_send(dtls_context_t *ctx, dtls_peer_t *peer, unsigned char type,
	  uint8 *buf, size_t buflen) {
  return dtls_send_multi(ctx, peer, dtls_security_params(peer), &peer->session,
			 type, &buf, &buflen, 1);
}

/**
 * Stops ongoing retransmissions of handshake messages for @p peer.
 */
static void dtls_stop_retransmission(dtls_context_t *context, dtls_peer_t *peer);

dtls_peer_t *
dtls_get_peer(const dtls_context_t *ctx, const session_t *session) {
  dtls_peer_t *p;
  FIND_PEER(ctx->peers, session, p);
  return p;
}

/**
 * Adds @p peer to list of peers in @p ctx. This function returns @c 0
 * on success, or a negative value on error (e.g. due to insufficient
 * storage).
 */
static int
dtls_add_peer(dtls_context_t *ctx, dtls_peer_t *peer) {
  ADD_PEER(ctx->peers, session, peer);
  return 0;
}

int
dtls_writev(struct dtls_context_t *ctx,
	    session_t *dst, uint8 *buf_array[],
	    size_t buf_len_array[], size_t buf_array_len) {

  dtls_peer_t *peer = dtls_get_peer(ctx, dst);

  /* Check if peer connection already exists */
  if (!peer) { /* no ==> create one */
    int res;

    /* dtls_connect() returns a value greater than zero if a new
     * connection attempt is made, 0 for session reuse. */
    res = dtls_connect(ctx, dst);

    return (res >= 0) ? 0 : res;
  } else { /* a session exists, check if it is in state connected */

    // MF: Server can only send app data in WAIT_FINISHED, if
    // security array can hold 3 security parameters (epoch 0, 2, 3)
    // Client can send app data in WAIT_FINISHED_ACK
    if (peer->state != DTLS_STATE_CONNECTED) {
      return 0;
    } else {
      return dtls_send_multi(ctx, peer, dtls_security_params(peer),
                             &peer->session, DTLS_CT_APPLICATION_DATA,
                             buf_array, buf_len_array, buf_array_len);
    }
  }
}

int
dtls_write(struct dtls_context_t *ctx, session_t *session,
	       uint8 *buf, size_t len) {
  return dtls_writev(ctx, session, &buf, &len, 1);
}

static int
dtls_check_cookie(dtls_context_t *ctx,
                  session_t *session,
                  uint8 *ext, int extlen,
                  dtls_cookie_t **cookie) {
  unsigned char buf[DTLS_HMAC_DIGEST_SIZE];
  dtls_hmac_context_t hmac;

  /* check length of extension_data */
  if (extlen != 2 + DTLS_COOKIE_LENGTH) {
    dtls_debug("cookie extension len mismatch recv. %u != %lu!\n", extlen, 2 + DTLS_COOKIE_LENGTH);
    return 0;
  }

  /* check length of cookie inside extension_data */
  if (dtls_uint16_to_int(ext) != DTLS_COOKIE_LENGTH) {
    dtls_debug("cookie len mismatch recv. %u != %lu!\n", dtls_uint16_to_int(ext), DTLS_COOKIE_LENGTH);
    return 0;
  }

  *cookie = (dtls_cookie_t*) (ext + sizeof(uint16));

  /* check cookie MAC */
  dtls_hmac_init(&hmac, ctx->cookie_secret, DTLS_COOKIE_SECRET_LENGTH);
  dtls_hmac_update(&hmac, (unsigned char *)&session->addr, session->size);
  dtls_hmac_update(&hmac, (*cookie)->hash, DTLS_SHA256_DIGEST_LENGTH);
  dtls_hmac_update(&hmac, (*cookie)->cipher_suite, sizeof(uint16));
  dtls_hmac_update(&hmac, (*cookie)->named_group, sizeof(uint16));
  // MF: add Client-Parameters to cookie?
  dtls_hmac_finalize(&hmac, buf);

  if (memcmp(buf, (*cookie)->mac, DTLS_COOKIE_MAC_LENGTH)) {
    dtls_debug_dump("not matching cookie", (unsigned char*) cookie, DTLS_COOKIE_LENGTH);
    return 0;
  }
  return 1;
}

static int
create_cookie(dtls_context_t *ctx,
                     session_t *session,
                     uint8 *msg, size_t msglen,
                     dtls_cookie_t *cookie) {

  unsigned char buf[DTLS_HMAC_DIGEST_SIZE];
  union {
    dtls_hash_ctx hash;
    dtls_hmac_context_t hmac;
  } c;

  /* Hash the Client Hello */
  dtls_hash_init(&c.hash);
  /* Include msg_type(1) and length(3) of Handshake Header */
  dtls_hash_update(&c.hash, msg, sizeof(uint8) + sizeof(uint24));
  msg += DTLS_HS_LENGTH;
  msglen -= DTLS_HS_LENGTH;
  dtls_hash_update(&c.hash, msg, msglen);
  dtls_hash_finalize(cookie->hash, &c.hash);

  /* Create the Cookie MAC */
  dtls_hmac_init(&c.hmac, ctx->cookie_secret, DTLS_COOKIE_SECRET_LENGTH);
  dtls_hmac_update(&c.hmac, (unsigned char *)&session->addr, session->size);
  dtls_hmac_update(&c.hmac, cookie->hash, DTLS_SHA256_DIGEST_LENGTH);
  dtls_hmac_update(&c.hmac, cookie->cipher_suite, sizeof(uint16));
  dtls_hmac_update(&c.hmac, cookie->named_group, sizeof(uint16));
  // MF: add Client-Parameters to cookie?
  dtls_hmac_finalize(&c.hmac, buf);
  memcpy(cookie->mac, buf, DTLS_COOKIE_MAC_LENGTH);

  dtls_debug_dump("Hash of ClientHello1", cookie->hash, DTLS_SHA256_DIGEST_LENGTH);
  dtls_debug_dump("Cookie MAC", cookie->mac, DTLS_COOKIE_MAC_LENGTH);
  return 0;
}

typedef enum {
  DTLS_ENCRYPT,
  DTLS_DECRYPT
} dtls_seq_num_dir;

typedef enum {
  DTLS_PLAINTEXT,
  DTLS_CIPHERTEXT
} dtls_record_type;

typedef struct {
  uint64_t epoch;
  uint64_t seq_nr;
} dtls_record_number_t;

static unsigned int
is_plaintext_record(uint8 *msg, size_t msglen) {
  dtls_record_header_t *header;
  unsigned int rlen = 0;
  uint8_t type;

  if (msglen >= DTLS_RH_LENGTH) { /* FIXME allow empty records? */
    header = DTLS_RECORD_HEADER(msg);
    type = dtls_get_content_type(header);

    if (type == DTLS_CT_ALERT ||
        type == DTLS_CT_HANDSHAKE ||
        type == DTLS_CT_ACK)
    {
      rlen = DTLS_RH_LENGTH + dtls_get_length(header);
    }

    /* we do not accept wrong length field in record header */
    if (rlen > msglen)
      rlen = 0;
  }

  return rlen > 0;
}

static int
is_record(uint8 *msg, size_t msglen, dtls_record_type *type) {

  if (is_plaintext_record(msg, msglen)) {
    *type = DTLS_PLAINTEXT;
    return 1;
  }

  if (msglen > 0) {
    uint8_t flags = dtls_uint8_to_int(msg);
    if ((flags & UHDR_MAGIC_BITS) == UHDR_MAGIC_VAL) {
      *type = DTLS_CIPHERTEXT;
      return 1;
    }
  }

  return 0;
}

static int
dtls_encrypt_decrypt_seq_num(dtls_security_parameters_t *security,
                             dtls_peer_type role, uint8 *ciphertext,
                             uint8 *seq, int seq_len,
                             dtls_seq_num_dir dir) {
  int err = 0;
  uint8 mask[DTLS_RN_MASK_LENGTH];
  uint8 *sn_key;

  if (dir == DTLS_ENCRYPT) {
    sn_key = dtls_kb_local_sn_key(security, role);
  } else {
    sn_key = dtls_kb_remote_sn_key(security, role);
  }

  dtls_debug_dump("seq num key", sn_key, DTLS_KEY_LENGTH);

  err = dtls_aes_encrypt_direct(ciphertext, mask, sn_key, DTLS_KEY_LENGTH);

  if (err < 0)
    return err;

  dtls_debug_dump("seq num mask", mask, DTLS_RN_MASK_LENGTH);

  memxor(seq, mask, seq_len);
  return err;
}

static uint64_t
dtls_reconstruct_seq_num(dtls_security_parameters_t *security,
                         uint8 *seq, int seq_len) {
  assert(security);
  assert(seq_len == 1 || seq_len == 2);

  uint16_t actual_bits;
  uint16_t mask;

  if (seq_len == 1) {
    actual_bits = dtls_uint8_to_int(seq);
    mask = 0xff;
  } else {
    actual_bits = dtls_uint16_to_int(seq);
    mask = 0xffff;
  }

  /* first guess of the reconstructed seq num is the
   * expected seq num, but with lower bits from header */
  uint64_t out = (security->cseq.cseq & ~mask) | actual_bits;
  /* range of the record seq num in the header */
  uint32_t width = mask + 1;
  uint16_t expected_bits = security->cseq.cseq & mask;

  if (actual_bits >= expected_bits) {
    uint32_t diff = actual_bits - expected_bits;
    if (diff > width / 2) {
      /* subtracting one full width is closer to the expected seq num */
      out -= width;
    }
  } else {
    /* actual_bits < expected_bits */
    uint32_t diff = expected_bits - actual_bits;
    if (diff > width / 2) {
      /* adding one full width is closer to the expected seq num */
      out += width;
    }
  }

  return out;
}

static int
dtls_parse_unified_header(dtls_peer_t *peer, uint8 *msg, int msglen,
                          dtls_record_number_t *rn, int *headerlen) {
  int err = 0;
  dtls_handshake_parameters_t *handshake = NULL;
  dtls_security_parameters_t *security = NULL;
  uint8_t flags = dtls_uint8_to_int(msg);
  uint8_t epochBits = flags & UHDR_EPOCH_BITS;
  int size; /* size of header */
  uint8 *seq_num;
  int seq_len;

  handshake = peer->handshake_params;

  if (handshake) {
    /* RFC 9147 4.2.2 During the handshake phase, the epoch bits unambiguously
     * indicate the correct key to use. */
    // MF: this is effectively the same as dtls_security_params_read_epoch
    security = dtls_security_params_epoch(peer, epochBits);
  } else if ((peer->security_params[0]->epoch & UHDR_EPOCH_BITS) == epochBits) {
    /* epoch bits match those of the current epoch */
    security = peer->security_params[0];
  } else if (peer->security_params[1] &&
            (peer->security_params[1]->epoch & UHDR_EPOCH_BITS) == epochBits) {
    /* epoch bits match those of the pending epoch */
    /* 4.2.1 Implementations SHOULD discard records from earlier epochs */
    /* MF: TODO ? peer->security_params[1]->epoch > peer->security_params[0]->epoch */
    security = peer->security_params[1];
  }

  if (!security) {
    dtls_warn("No security context for epoch bits: %d\n", epochBits);
    return -1;
  }

  /* epoch 0 is always unencrypted */
  if (security->epoch == 0)
    return -1;

  seq_num = msg + sizeof(uint8);
  seq_len = sizeof(uint8);

  /* CID is not supported */
  if (flags & UHDR_CID_BIT) {
    dtls_warn("connection id was not sent by client!\n");
    return -1;
  }

  /* flags + 8 bit seq no. */
  size = sizeof(uint8) + sizeof(uint8);
  if (flags & UHDR_SEQ_LEN_BIT) {
    size += sizeof(uint8); /* seq no is 16 bit */
    seq_len += sizeof(uint8);
  }
  if (flags & UHDR_LENGTH_BIT) {
    msglen = dtls_uint16_to_int(msg + size);
    size += sizeof(uint16); /* 16 bit length present */
  } else {
    /* record consumes the entire rest of the datagram */
    msglen -= size;
  }

  /* 4.2.3 ciphertext must be at least 16 bytes for sequence number decryption */
  if (msglen < DTLS_RN_MASK_LENGTH)
    return -1;
  
  err = dtls_encrypt_decrypt_seq_num(security, peer->role, msg + size,
    seq_num, seq_len, DTLS_DECRYPT);

  if (err < 0)
    return err;

  rn->epoch = security->epoch;
  rn->seq_nr = dtls_reconstruct_seq_num(security, seq_num, seq_len);
  *headerlen = size;

  return msglen + size;
}

/**
 * Initializes \p buf as record header. The caller must ensure that \p
 * buf is capable of holding at least \c sizeof(dtls_record_header_t)
 * bytes. Increments records sequence number counter.
 * \return pointer to the next byte after the written header.
 * The length will be set to 0 and has to be changed before sending.
 */
static inline uint8 *
dtls_set_record_header(uint8 type,
		       uint16_t epoch,
		       uint64_t *rseqn,
		       uint8 *buf) {
  dtls_int_to_uint8(buf, type);
  buf += sizeof(uint8);

  dtls_int_to_uint16(buf, DTLS_VERSION);
  buf += sizeof(uint16);

  dtls_int_to_uint16(buf, epoch);
  buf += sizeof(uint16);

  dtls_int_to_uint48(buf, *rseqn);
  buf += sizeof(uint48);

  /* increment record sequence counter by 1 */
  (*rseqn)++;

  /* space for record size */
  memset(buf, 0, sizeof(uint16));
  return buf + sizeof(uint16);
}

/**
 * Initializes \p buf as handshake header. The caller must ensure that \p
 * buf is capable of holding at least \c sizeof(dtls_handshake_header_t)
 * bytes. Increments message sequence number counter.
 * \return pointer to the next byte after \p buf
 */
static inline uint8 *
dtls_set_handshake_header(uint8 type,
			  uint16_t *mseqn,
			  int length,
			  int frag_offset, int frag_length,
			  uint8 *buf) {

  dtls_int_to_uint8(buf, type);
  buf += sizeof(uint8);

  dtls_int_to_uint24(buf, length);
  buf += sizeof(uint24);

  /* and copy the result to buf */
  dtls_int_to_uint16(buf, *mseqn);
  buf += sizeof(uint16);

  /* increment handshake message sequence counter by 1 */
  (*mseqn)++;

  dtls_int_to_uint24(buf, frag_offset);
  buf += sizeof(uint24);

  dtls_int_to_uint24(buf, frag_length);
  buf += sizeof(uint24);

  return buf;
}

static const dtls_user_parameters_t default_user_parameters = {
  .cipher_suites =
#ifdef DTLS_DEFAULT_CIPHER_SUITES
    DTLS_DEFAULT_CIPHER_SUITES,
#else /* DTLS_DEFAULT_CIPHER_SUITES */
    {
#ifdef DTLS_ECC
      TLS_AES_128_CCM_SHA256,
      TLS_AES_128_CCM_8_SHA256,
#endif /* DTLS_ECC */

#ifdef DTLS_PSK
      TLS_PSK_WITH_AES_128_CCM_8,
      TLS_PSK_WITH_AES_128_CCM,
#endif /* DTLS_PSK */
    /* TLS_NULL_WITH_NULL_NULL must always be the last entry as it
     * indicates the stop marker for the traversal of this table. */
       TLS_NULL_WITH_NULL_NULL
    },
#endif /* DTLS_DEFAULT_CIPHER_SUITES */
  .key_exchange_algorithms =
    {
#ifdef DTLS_ECC
      DTLS_KEY_EXCHANGE_ECDHE_ECDSA,
#endif /* DTLS_ECC */
#ifdef DTLS_PSK
      DTLS_KEY_EXCHANGE_PSK,
#endif /* DTLS_PSK */
      DTLS_KEY_EXCHANGE_NONE
    },
  .force_extended_master_secret = 0, // MF: not necessary for 1.3
#if (DTLS_MAX_CID_LENGTH > 0)
  .support_cid = DTLS_USE_CID_DEFAULT,
#endif /* DTLS_MAX_CID_LENGTH > 0 */
};

/** only one compression method is currently defined */
static uint8 compression_methods[] = {
  TLS_COMPRESSION_NULL
};

typedef struct cipher_suite_param_t {
  dtls_cipher_t cipher_suite;
  uint8_t mac_length;
  dtls_key_exchange_algorithm_t key_exchange_algorithm;
} cipher_suite_param_t;

static const struct cipher_suite_param_t cipher_suite_params[] = {
  /* The TLS_NULL_WITH_NULL_NULL cipher suite must be the first
   * in this table (index DTLS_CIPHER_INDEX_NULL) */
  { TLS_NULL_WITH_NULL_NULL,             0, DTLS_KEY_EXCHANGE_NONE },
#ifdef DTLS_PSK
  { TLS_AES_128_CCM_8_SHA256,            8, DTLS_KEY_EXCHANGE_PSK },
  { TLS_AES_128_CCM_SHA256,             16, DTLS_KEY_EXCHANGE_PSK },
#endif /* DTLS_PSK */
#ifdef DTLS_ECC
  { TLS_AES_128_CCM_8_SHA256,            8, DTLS_KEY_EXCHANGE_ECDHE_ECDSA },
  { TLS_AES_128_CCM_SHA256,             16, DTLS_KEY_EXCHANGE_ECDHE_ECDSA },
#endif /* DTLS_ECC */
 };

static const dtls_cipher_index_t last_cipher_suite_param =
    sizeof(cipher_suite_params) / sizeof(cipher_suite_param_t);

/**
 * Check if cipher suite is contained in table.
 *
 * \param cipher_suites table with cipher suites. Terminated with
 *                      TLS_NULL_WITH_NULL_NULL.
 * \param cipher_suite cipher suite
 * \return 0 if not contained, != 0 if contained
 */
static inline uint8_t
contains_cipher_suite(const dtls_cipher_t* cipher_suites, const dtls_cipher_t cipher_suite) {
  if (cipher_suite == TLS_NULL_WITH_NULL_NULL) {
    return 0;
  }
  while ((*cipher_suites != cipher_suite) &&
         (*cipher_suites != TLS_NULL_WITH_NULL_NULL)) {
    cipher_suites++;
  }
  return *cipher_suites == cipher_suite;
}

static inline uint8_t
contains_key_exchange_algorithm(const dtls_key_exchange_algorithm_t* algorithms,
                                const dtls_key_exchange_algorithm_t algorithm) {
  if (algorithm == DTLS_KEY_EXCHANGE_NONE) {
    return 0;
  }
  while ((*algorithms != algorithm) &&
         (*algorithms != DTLS_KEY_EXCHANGE_NONE)) {
    algorithms++;
  }
  return *algorithms == algorithm;
}

/**
 * Get index to cipher suite params.
 *
 * \param user_parameters user parameters with table with user-selected cipher suites.
 *                        Terminated with TLS_NULL_WITH_NULL_NULL.
 * \param cipher cipher suite
 * \param algorithm key exchange algorithm
 * \return index to cipher suite params, DTLS_CIPHER_INDEX_NULL if not found.
 */
static inline dtls_cipher_index_t
get_cipher_index(const dtls_user_parameters_t* user_parameters, dtls_cipher_t cipher, dtls_key_exchange_algorithm_t algorithm) {
  if (contains_cipher_suite(user_parameters->cipher_suites, cipher) &&
      contains_key_exchange_algorithm(user_parameters->key_exchange_algorithms, algorithm)) {
    for (int index = 0; index < last_cipher_suite_param ; ++index) {
      if (cipher_suite_params[index].cipher_suite == cipher &&
          cipher_suite_params[index].key_exchange_algorithm == algorithm) {
        return index;
      }
    }
  }
  return DTLS_CIPHER_INDEX_NULL;
}

/**
 * Get cipher suite.
 * \param cipher_index index to cipher suite params
 * \return cipher suite.
 */
static inline dtls_cipher_t
get_cipher_suite(dtls_cipher_index_t cipher_index) {
  assert(cipher_index < last_cipher_suite_param);
  return cipher_suite_params[cipher_index].cipher_suite;
}

/**
 * Get key exchange algorithm of cipher suite.
 * \param cipher_index index to cipher suite params
 * \return key exchange algorithm.
 *         \c DTLS_KEY_EXCHANGE_NONE, if cipher is not supported.
 */
static inline dtls_key_exchange_algorithm_t
get_key_exchange_algorithm(dtls_cipher_index_t cipher_index) {
  assert(cipher_index < last_cipher_suite_param);
  return cipher_suite_params[cipher_index].key_exchange_algorithm;
}

/**
 * Get MAC length of cipher suite.
 * \param cipher_index index to cipher suite params
 * \return MAC length of cipher. \c 0, if cipher is not supported.
 */
static inline uint8_t
get_cipher_suite_mac_len(dtls_cipher_index_t cipher_index) {
  assert(cipher_index < last_cipher_suite_param);
  return cipher_suite_params[cipher_index].mac_length;
}

/** returns true if the cipher suite uses an ECDHE_ECDSA key exchange */
static inline int
is_key_exchange_ecdhe_ecdsa(dtls_cipher_index_t cipher_index) {
#ifdef DTLS_ECC
  return DTLS_KEY_EXCHANGE_ECDHE_ECDSA == get_key_exchange_algorithm(cipher_index);
#else
  (void) cipher_index;
  return 0;
#endif /* DTLS_ECC */
}

/** returns true if the cipher suite uses an PSK key exchange */
static inline int
is_key_exchange_psk(dtls_cipher_index_t cipher_index) {
#ifdef DTLS_PSK
  return DTLS_KEY_EXCHANGE_PSK == get_key_exchange_algorithm(cipher_index);
#else
  (void) cipher_index;
  return 0;
#endif /* DTLS_PSK */
}

/** returns true if the application is configured for psk */
static inline int
is_psk_supported(dtls_context_t *ctx) {
#ifdef DTLS_PSK
  return ctx && ctx->h && ctx->h->get_psk_info;
#else
  (void) ctx;
  return 0;
#endif /* DTLS_PSK */
}

/** returns true if the application is configured for ecdhe_ecdsa */
static inline int
is_ecdsa_supported(dtls_context_t *ctx, int is_client) {
#ifdef DTLS_ECC
  return ctx && ctx->h && ((!is_client && ctx->h->get_ecdsa_key) ||
                           (is_client && ctx->h->verify_ecdsa_key));
#else
  (void) ctx;
  (void) is_client;
  return 0;
#endif /* DTLS_ECC */
}

/** Returns true if the application is configured for ecdhe_ecdsa with
  * client authentication */
static inline int
is_ecdsa_client_auth_supported(dtls_context_t *ctx) {
#ifdef DTLS_ECC
  return ctx && ctx->h && ctx->h->get_ecdsa_key && ctx->h->verify_ecdsa_key;
#else
  (void) ctx;
  return 0;
#endif /* DTLS_ECC */
}

/**
 * Returns @c 1 if @p code is a cipher suite other than @c
 * TLS_NULL_WITH_NULL_NULL that we recognize.
 *
 * @param ctx   The current DTLS context
 * @param cipher_index The index to cipher suite params to check
 * @param is_client 1 for a dtls client, 0 for server
 * @return @c 1 iff @p code is recognized,
 */
static int
known_cipher_index(dtls_context_t *ctx, dtls_cipher_index_t cipher_index, int is_client) {
  const int psk = is_psk_supported(ctx);
  const int ecdsa = is_ecdsa_supported(ctx, is_client);
  const dtls_key_exchange_algorithm_t key_exchange_algorithm =
                                      get_key_exchange_algorithm(cipher_index);

  return (psk && key_exchange_algorithm == DTLS_KEY_EXCHANGE_PSK) ||
	 (ecdsa && key_exchange_algorithm == DTLS_KEY_EXCHANGE_ECDHE_ECDSA);
}

static int
known_cipher_suite(dtls_cipher_t cipher) {
  for (uint8_t i = 0; i < last_cipher_suite_param; i++) {
    if (cipher_suite_params[i].cipher_suite == cipher)
      return 1;
  }
  return 0;
}

/** Dump out the cipher keys and IVs used for the symmetric cipher. */
static void
dtls_debug_keyblock(dtls_security_parameters_t *config) {
  dtls_debug("key_block (%d bytes):\n", dtls_kb_size(config, peer->role));
  dtls_debug_dump("  client_MAC_secret",
		  dtls_kb_client_mac_secret(config, peer->role),
		  dtls_kb_mac_secret_size(config, peer->role));

  dtls_debug_dump("  server_MAC_secret",
		  dtls_kb_server_mac_secret(config, peer->role),
		  dtls_kb_mac_secret_size(config, peer->role));

  dtls_debug_dump("  client_write_key",
		  dtls_kb_client_write_key(config, peer->role),
		  dtls_kb_key_size(config, peer->role));

  dtls_debug_dump("  server_write_key",
		  dtls_kb_server_write_key(config, peer->role),
		  dtls_kb_key_size(config, peer->role));

  dtls_debug_dump("  client_IV",
		  dtls_kb_client_iv(config, peer->role),
		  dtls_kb_iv_size(config, peer->role));

  dtls_debug_dump("  server_IV",
		  dtls_kb_server_iv(config, peer->role),
		  dtls_kb_iv_size(config, peer->role));

  dtls_debug_dump("  client_sn_key",
    dtls_kb_client_sn_key(config, peer->role),
    dtls_kb_key_size(config, peer->role));

  dtls_debug_dump("  server_sn_key",
    dtls_kb_server_sn_key(config, peer->role),
    dtls_kb_key_size(config, peer->role));
}

/** returns the name of the given handshake type number.
  * see IANA for a full list of types:
  * https://www.iana.org/assignments/tls-parameters/tls-parameters.xml#tls-parameters-7
  */
static const char *
dtls_handshake_type_to_name(int type) {
  switch (type) {
  case DTLS_HT_HELLO_REQUEST:
    return "hello_request";
  case DTLS_HT_CLIENT_HELLO:
    return "client_hello";
  case DTLS_HT_SERVER_HELLO:
    return "server_hello";
  case DTLS_HT_HELLO_VERIFY_REQUEST:
    return "hello_verify_request";
  case DTLS_HT_HELLO_RETRY_REQUEST:
    return "hello_retry_request";
  case DTLS_HT_ENCRYPTED_EXTENSIONS:
    return "encrypted_extensions";
  case DTLS_HT_REQUEST_CONNECTION_ID:
    return "request_connection_id";
  case DTLS_HT_NEW_CONNECTION_ID:
    return "new_connection_id";
  case DTLS_HT_CERTIFICATE:
    return "certificate";
  case DTLS_HT_SERVER_KEY_EXCHANGE:
    return "server_key_exchange";
  case DTLS_HT_CERTIFICATE_REQUEST:
    return "certificate_request";
  case DTLS_HT_SERVER_HELLO_DONE:
    return "server_hello_done";
  case DTLS_HT_CERTIFICATE_VERIFY:
    return "certificate_verify";
  case DTLS_HT_CLIENT_KEY_EXCHANGE:
    return "client_key_exchange";
  case DTLS_HT_FINISHED:
    return "finished";
  case DTLS_HT_KEY_UPDATE:
    return "key_update";
  default:
    return "unknown";
  }
}

static const char *
dtls_message_type_to_name(int type) {
  switch (type) {
  case DTLS_CT_CHANGE_CIPHER_SPEC:
    return "change_cipher_spec";
  case DTLS_CT_ALERT:
    return "alert";
  case DTLS_CT_HANDSHAKE:
    return "handshake";
  case DTLS_CT_APPLICATION_DATA:
    return "application_data";
  case DTLS_CT_TLS12_CID:
    return "connection_id";
  default:
    return NULL;
  }
}

static int
list_contains_key(uint8 *data, size_t data_length,
                  int length_size, int key_size,
                  int key)
{
  int i;
  int value;
  assert(length_size == 1 || length_size == 2);
  assert(key_size == 1 || key_size == 2);

  if (data_length < (size_t) length_size)
    return dtls_alert_fatal_create(DTLS_ALERT_HANDSHAKE_FAILURE);

  if (length_size == 1) {
    i = dtls_uint8_to_int(data);
    data += sizeof(uint8);
    data_length -= sizeof(uint8);
  } else {
     i = dtls_uint16_to_int(data);
     data += sizeof(uint16);
     data_length -= sizeof(uint16);
  }

  if ((size_t) i != data_length) {
    dtls_warn("the list should be tls extension length - 2\n");
    return dtls_alert_fatal_create(DTLS_ALERT_HANDSHAKE_FAILURE);
  }

  for (i = data_length; i > 0; i -= key_size) {
    value = key_size == 1
      ? dtls_uint8_to_int(data)
      : dtls_uint16_to_int(data);

    if (value == key)
      return 1;
    data += key_size;
  }
  return 0;
}

static inline void
store_ecdhe_pub_key(dtls_peer_t *peer, uint8 *key) {
  dtls_handshake_parameters_t *handshake = peer->handshake_params;
  assert(is_key_exchange_ecdhe_ecdsa(handshake->cipher_index));

  memcpy(handshake->keyx.ecdsa.other_eph_pub_x, key, sizeof(handshake->keyx.ecdsa.other_eph_pub_x));
  key += sizeof(handshake->keyx.ecdsa.other_eph_pub_x);

  memcpy(handshake->keyx.ecdsa.other_eph_pub_y, key, sizeof(handshake->keyx.ecdsa.other_eph_pub_y));
  key += sizeof(handshake->keyx.ecdsa.other_eph_pub_y);
}

static int
create_ext_supported_versions(uint8 *buf, dtls_peer_type role) {
  /* length of the one ProtocolVersion */
  const uint8_t length = 2;

  buf += dtls_int_to_uint16(buf, TLS_EXT_SUPPORTED_VERSIONS);

  /* Client sends a list of all supported Protocol Versions. The server only
    * sends the selected version in server hello and hello retry request. */
  if (role == DTLS_CLIENT) {
    buf += dtls_int_to_uint16(buf, length + 1); /* length of the extension */
    buf += dtls_int_to_uint8(buf, length); /* length of the list of ProtocolVersions */
  } else {
    buf += dtls_int_to_uint16(buf, length); /* length of the extension */
  }
  buf += dtls_int_to_uint16(buf, DTLS13_VERSION);

  return 2 + 2 + 2 + (role == DTLS_CLIENT ? 1 : 0);
}

static int
create_ext_key_share_generate_key(uint8 *buf, dtls_peer_type role,
                                  dtls_handshake_parameters_t *handshake) {
  uint8 *ephemeral_pub_x;
  uint8 *ephemeral_pub_y;

  /*
   * KeyShareEntry:
   * 
   * named group              :=  2 bytes
   * Key_exchange length      :=  2 bytes
   * legacy_form              :=  1 byte
   * key_x                    := 32 bytes
   * key_y                    := 32 bytes => 69 bytes
  */
  const uint16_t length = 69;

  buf += dtls_int_to_uint16(buf, TLS_EXT_KEY_SHARE);
  if (role == DTLS_CLIENT) {
    /* The Client sends a KeyShareClientHello which contains a list
     * of KeyShareEntry (only one group is supported). The Server only
     * sends a single KeyShareEntry so no length required. */
    buf += dtls_int_to_uint16(buf, length + 2);
  }
  /* length of one KeyShareEntry. For the server, this is the length of the extension. */
  buf += dtls_int_to_uint16(buf, length); 
  buf += dtls_int_to_uint16(buf, TLS_NAMED_GROUP_SECP256R1);
  buf += dtls_int_to_uint16(buf, length - 4); /* length of key_exchange inside KeyShareEntry */
  buf += dtls_int_to_uint8(buf, 4); /* legacy_form: uncompressed point */

  ephemeral_pub_x = buf;
  buf += DTLS_EC_KEY_SIZE;
  ephemeral_pub_y = buf;
  buf += DTLS_EC_KEY_SIZE;

  dtls_ecdsa_generate_key(
        handshake->keyx.ecdsa.own_eph_priv,
        ephemeral_pub_x, ephemeral_pub_y,
        DTLS_EC_KEY_SIZE);

  return 2 + 2 + length + (role == DTLS_CLIENT ? 2 : 0);
}

static int
create_ext_client_certificate_type(uint8 *buf, dtls_peer_type role) {
  buf += dtls_int_to_uint16(buf, TLS_EXT_CLIENT_CERTIFICATE_TYPE);
  if (role == DTLS_CLIENT) {
    buf += dtls_int_to_uint16(buf, 2); /* length of this extension */
    buf += dtls_int_to_uint8(buf, 1); /* length of the list */
    buf += dtls_int_to_uint8(buf, TLS_CERT_TYPE_RAW_PUBLIC_KEY);
    return 2 + 2 + 1 + 1;
  } else {
    buf += dtls_int_to_uint16(buf, 1); /* length of this extension */
    buf += dtls_int_to_uint8(buf, TLS_CERT_TYPE_RAW_PUBLIC_KEY);
    return 2 + 2 + 1;
  }
}

static int
create_ext_server_certificate_type(uint8 *buf, dtls_peer_type role) {
  buf += dtls_int_to_uint16(buf, TLS_EXT_SERVER_CERTIFICATE_TYPE);
  if (role == DTLS_CLIENT) {
    buf += dtls_int_to_uint16(buf, 2); /* length of this extension */
    buf += dtls_int_to_uint8(buf, 1); /* length of the list */
    buf += dtls_int_to_uint8(buf, TLS_CERT_TYPE_RAW_PUBLIC_KEY);
    return 2 + 2 + 1 + 1;
  } else {
    buf += dtls_int_to_uint16(buf, 1); /* length of this extension */
    buf += dtls_int_to_uint8(buf, TLS_CERT_TYPE_RAW_PUBLIC_KEY);
    return 2 + 2 + 1;
  }
}

static inline int
create_ext_cookie(uint8 *buf, uint8 *cookie, uint16_t cookie_length) {
  
  buf += dtls_int_to_uint16(buf, TLS_EXT_COOKIE);
  buf += dtls_int_to_uint16(buf, 2 + cookie_length);
  buf += dtls_int_to_uint16(buf, cookie_length);
  memcpy(buf, cookie, cookie_length);
  return 2 + 2 + 2 + cookie_length;
}

static inline int
create_ext_key_share_empty(uint8 *buf) {
  buf += dtls_int_to_uint16(buf, TLS_EXT_KEY_SHARE);
  buf += dtls_int_to_uint16(buf, 2);
  buf += dtls_int_to_uint16(buf, 0);
  return 2 + 2 + 2;
}

static inline int
create_ext_key_share_hello_retry(uint8 *buf) {
  buf += dtls_int_to_uint16(buf, TLS_EXT_KEY_SHARE);
  buf += dtls_int_to_uint16(buf, 2);
  buf += dtls_int_to_uint16(buf, TLS_NAMED_GROUP_SECP256R1);
  return 2 + 2 + 2;
}

static inline int
create_ext_supported_groups(uint8 *buf) {
  buf += dtls_int_to_uint16(buf, TLS_EXT_ELLIPTIC_CURVES);
  buf += dtls_int_to_uint16(buf, 4); /* length of this extension */
  buf += dtls_int_to_uint16(buf, 2); /* length of the list */
  buf += dtls_int_to_uint16(buf, TLS_EXT_ELLIPTIC_CURVES_SECP256R1);
  return 2 + 2 + 2 + 2;
}

static inline int
create_ext_signature_algorithms(uint8 *buf) {
  buf += dtls_int_to_uint16(buf, TLS_EXT_SIGNATURE_ALGORITHMS);
  buf += dtls_int_to_uint16(buf, 4); /* length of this extension */
  buf += dtls_int_to_uint16(buf, 2); /* length of supported_signature_algorithms */
  buf += dtls_int_to_uint16(buf, TLS_SIGNATURE_SCHEME_ECDSA_SECP256R1_SHA256);
  return 2 + 2 + 2 + 2;
}

#if (DTLS_MAX_CID_LENGTH > 0)
static inline int
create_ext_connection_id(uint8 *buf) {
  buf += dtls_int_to_uint16(buf, TLS_EXT_CONNECTION_ID);
  buf += dtls_int_to_uint16(buf, 1); /* length of this extension */
  /* empty cid, indicating support for cid extension */
  buf += dtls_int_to_uint8(buf, 0);
  return 2 + 2 + 1;
}
#endif /* DTLS_MAX_CID_LENGTH > 0 */

static int
find_ext_by_type(uint8 *data, size_t data_length,
                 uint16_t ext_type,
                 uint8 **ext_data, int *ext_length) {
  uint16_t type;
  uint16_t size;

  if (data_length < sizeof(uint16))
    return 0; /* no extensions */

  /* get the length of the tls extension list */
  size = dtls_uint16_to_int(data);
  data += sizeof(uint16);
  data_length -= sizeof(uint16);

  if (data_length < size)
    return dtls_alert_fatal_create(DTLS_ALERT_DECODE_ERROR);

  data_length = size;

  while (data_length)
  {
    if (data_length < sizeof(uint16) * 2)
      return dtls_alert_fatal_create(DTLS_ALERT_DECODE_ERROR);

    /* get the tls extension type */
    type = dtls_uint16_to_int(data);
    data += sizeof(uint16);
    data_length -= sizeof(uint16);

    /* get the length of the tls extension */
    size = dtls_uint16_to_int(data);
    data += sizeof(uint16);
    data_length -= sizeof(uint16);

    if (data_length < size)
      return dtls_alert_fatal_create(DTLS_ALERT_DECODE_ERROR);

    if (type == ext_type) {
      *ext_data = data;
      *ext_length = size;
      return 1;
    }

    data += size;
    data_length -= size;
  }
  return 0;
}

static int
is_valid_key_share_entry(uint8 *data,
                         size_t data_length,
                         uint16_t *entry_length,
                         uint8 **key) {
    uint16_t group;
    uint16_t key_length;
    
    /*
     * ECDHE KeyShareEntry:
     *
     * NamedGroup             :=  2 bytes
     * key length             :=  2 bytes
     * legacy_form            :=  1 byte
     * key x                  := 32 bytes
     * key y                  := 32 bytes
     */
    if (data_length < 2 + 2)
      return dtls_alert_fatal_create(DTLS_ALERT_DECODE_ERROR);

    group = dtls_uint16_to_int(data);
    data += sizeof(uint16);
    data_length -= sizeof(uint16);

    key_length = dtls_uint16_to_int(data);
    data += sizeof(uint16);
    data_length -= sizeof(uint16);

    if (key_length < data_length)
      return dtls_alert_fatal_create(DTLS_ALERT_DECODE_ERROR);

    *entry_length = 2 + 2 + key_length;

    if (group != TLS_NAMED_GROUP_SECP256R1)
      return 0;

    if (key_length != 1 + 2 * DTLS_EC_KEY_SIZE) {
      dtls_alert("expected 65 bytes long public point\n");
      return dtls_alert_fatal_create(DTLS_ALERT_DECODE_ERROR);
    }

    if (dtls_uint8_to_int(data) != 4) {
      dtls_alert("expected uncompressed public point\n");
      return dtls_alert_fatal_create(DTLS_ALERT_DECODE_ERROR);
    }

    if (key)
      *key = data + sizeof(uint8);

    return 1;
}

static int
verify_ext_key_share(uint8 *data,
                     size_t ext_length,
                     int hs_type,
                     uint8 **pub_key)
{
  int res = 0;
  uint16_t list_length;
  uint16_t entry_length;

  if (hs_type == DTLS_HT_CLIENT_HELLO) {

    if (ext_length < 2)
      return dtls_alert_fatal_create(DTLS_ALERT_DECODE_ERROR);
    
    /* lenth of list of key share entries */
    list_length = dtls_uint16_to_int(data);
    data += sizeof(uint16);
    ext_length -= sizeof(uint16);

    if (ext_length < list_length)
      return dtls_alert_fatal_create(DTLS_ALERT_DECODE_ERROR);

    if (list_length == 0) {
      /* if this is the first client hello, the client is requesting a
       * hello retry request. Server has to supply the selected group. */
      return 0;
    }

    while (list_length) {
      res = is_valid_key_share_entry(data, list_length, &entry_length, pub_key);
      if (res < 0)
        return res; /* error */
      else if (res > 0) {
        return 1; /* found key */
      }
      list_length -= entry_length;
    }
    /* no valid key share found */
    return 0;

  } else if (hs_type == DTLS_HT_SERVER_HELLO) {
    /* Key Share ServerHello contains a single KeyShareEntry */
    /* RFC 8446 4.2.8
     * The named group has to be
     *  1) the same as in the key share from ClientHello
     *  2) supported by the client (part of supported_groups)
     *  3) the same as in the key share from HelloRetryRequest (if present)
     * check for secp256r1, since that's the only one supported.
     */
    res = is_valid_key_share_entry(data, ext_length, &entry_length, pub_key);
    if (res < 0) {
      return res; /* error */
    } else if (res > 0) {
      return 1; /* valid key */
    } else {
      /* invalid key */
      return dtls_alert_fatal_create(DTLS_ALERT_ILLEGAL_PARAMETER);
    }


  } else if (hs_type == DTLS_HT_HELLO_RETRY_REQUEST) {
    /*
     * Key Share HelloRetryRequest contains the mutually supported group
     * the server intends to negotiate:
     *
     * NamedGroup             :=  2 bytes
     */
    if (ext_length < 2)
      return dtls_alert_fatal_create(DTLS_ALERT_DECODE_ERROR);

    if (dtls_uint16_to_int(data) != TLS_EXT_ELLIPTIC_CURVES_SECP256R1) {
      dtls_alert("expected secp256r1\n");
      return dtls_alert_fatal_create(DTLS_ALERT_ILLEGAL_PARAMETER);
    }
    data += sizeof(uint16);
    ext_length -= sizeof(uint16);
  }
  return 0;
}

static int
verify_ext_cookie(uint8 *data,
                  size_t ext_length,
                  int hs_type,
                  uint8 **cookie,
                  uint16_t *cookie_length)
{
  /* Cookie inside Client Hello already processed in dtls_0_verify_peer */

  if (hs_type == DTLS_HT_HELLO_RETRY_REQUEST) {
    if (ext_length < sizeof(uint16))
      return dtls_alert_fatal_create(DTLS_ALERT_DECODE_ERROR);

    *cookie_length = dtls_uint16_to_int(data);
    data += sizeof(uint16);
    ext_length -= sizeof(uint16);

    if (*cookie_length > DTLS_COOKIE_LENGTH_MAX) {
      dtls_warn("the cookie is too long\n");
      return dtls_alert_fatal_create(DTLS_ALERT_HANDSHAKE_FAILURE);
    }

    if (ext_length < *cookie_length)
      return dtls_alert_fatal_create(DTLS_ALERT_DECODE_ERROR);

    *cookie = data;
  }

  return 0;
}

static int
verify_ext_supported_groups(uint8 *data,
                            size_t ext_length,
                            int hs_type)
{
  int ret = 0;

  if (hs_type == DTLS_HT_CLIENT_HELLO) {
    ret = list_contains_key(data, ext_length,
                            sizeof(uint16), sizeof(uint16),
                            TLS_NAMED_GROUP_SECP256R1);
    if (ret < 0) {
      return ret; /* error */
    } else if (ret > 0) {
      return 0; /* key found */
    } else {
      /* key not found */
      dtls_warn("no supported group found\n");
      return dtls_alert_fatal_create(DTLS_ALERT_HANDSHAKE_FAILURE);
    }
  }

  /**
   * hs_type == DTLS_HT_ENCRYPTED_EXTENSIONS
   * RFC 8446 4.2.7: Clients MUST NOT act upon any information found.
   * Clients MAY use the information [...] in subsequent connections.
   * 
   * Since only secp256r1 is supported, we just ignore the servers preferences
  */

  return ret;
}

static int
verify_ext_signature_algorithms(uint8 *data,
                                size_t ext_length,
                                int hs_type)
{
  int ret = 0;

  if (hs_type == DTLS_HT_CLIENT_HELLO || hs_type == DTLS_HT_CERTIFICATE_REQUEST) {
    ret = list_contains_key(data, ext_length,
                            sizeof(uint16), sizeof(uint16),
                            TLS_SIGNATURE_SCHEME_ECDSA_SECP256R1_SHA256);
    if (ret < 0) {
      return ret; /* error */
    } else if (ret) {
      return 0; /* key found */
    } else {
      /* key not found */
      dtls_warn("no supported signature scheme found\n");
      return dtls_alert_fatal_create(DTLS_ALERT_HANDSHAKE_FAILURE);
    }
  }
  return ret;
}

static int
verify_ext_certificate_type(uint8 *data,
                            size_t ext_length,
                            int hs_type)
{
  int ret = 0;

  if (hs_type == DTLS_HT_CLIENT_HELLO) {
    ret = list_contains_key(data, ext_length,
                            sizeof(uint8), sizeof(uint8),
                            TLS_CERT_TYPE_RAW_PUBLIC_KEY);
    if (ret < 0) {
      return ret; /* error */
    } else if (ret == 0) {
      dtls_warn("no supported cert type found\n");
      return dtls_alert_fatal_create(DTLS_ALERT_HANDSHAKE_FAILURE);
    }

  } else if (hs_type == DTLS_HT_ENCRYPTED_EXTENSIONS) {
    if (ext_length < sizeof(uint8))
      return dtls_alert_fatal_create(DTLS_ALERT_HANDSHAKE_FAILURE);

    if (dtls_uint8_to_int(data) != TLS_CERT_TYPE_RAW_PUBLIC_KEY)
      return dtls_alert_fatal_create(DTLS_ALERT_HANDSHAKE_FAILURE);
  }

  /* type found */
  return 0;
}

#if (DTLS_MAX_CID_LENGTH > 0)

static int
verify_ext_connection_id(dtls_handshake_parameters_t *handshake, uint8 *data,
                      size_t ext_length, int hs_type) {
  uint8_t i;

  if (hs_type == DTLS_HT_SERVER_HELLO && !handshake->user_parameters.support_cid) {
    dtls_warn("connection id was not sent by client!\n");
    return dtls_alert_fatal_create(DTLS_ALERT_HANDSHAKE_FAILURE);
  }

  if (sizeof(uint8) > ext_length) {
    dtls_warn("invalid length (%zu) for extension connection id\n", ext_length);
    return dtls_alert_fatal_create(DTLS_ALERT_HANDSHAKE_FAILURE);
  }

  /* length of the connection id */
  i = dtls_uint8_to_int(data);
  data += sizeof(uint8);
  if (i + sizeof(uint8) != ext_length) {
    dtls_warn("invalid connection id length (%d)\n", i);
    return dtls_alert_fatal_create(DTLS_ALERT_HANDSHAKE_FAILURE);
  }

  if (DTLS_MAX_CID_LENGTH < i) {
    dtls_warn("connection id length (%d) exceeds maximum (%d)!\n", i, DTLS_MAX_CID_LENGTH);
    return dtls_alert_fatal_create(DTLS_ALERT_HANDSHAKE_FAILURE);
  }

  handshake->write_cid_length = i;
  memcpy(handshake->write_cid, data, i);

  return 0;
}

#endif /* DTLS_MAX_CID_LENGTH > 0*/

typedef struct dtls_extension_info_t
{
    uint8 *pub_key;
    uint8 *cookie;
    uint16_t cookie_length;

    unsigned int ext_key_share:1;
    unsigned int ext_cookie:1;
    unsigned int ext_sig_algo:1;
    unsigned int ext_supported_groups:1;
    unsigned int ext_client_cert_type:1;
    unsigned int ext_server_cert_type:1;
    unsigned int ext_connection_id:1;
} dtls_extension_info_t;

static int
dtls_parse_tls_extension(dtls_peer_t *peer,
                         uint8 *data,
                         size_t data_length,
                         int hs_type,
                         dtls_extension_info_t *info) {
  (void) peer;
  int err = 0;
  uint16_t type;
  uint16_t size;
  memset(info, 0, sizeof(*info));
  
  if (data_length < sizeof(uint16)) {
    return dtls_alert_fatal_create(DTLS_ALERT_DECODE_ERROR);
  }

  /* get the length of the tls extension list */
  size = dtls_uint16_to_int(data);
  data += sizeof(uint16);
  data_length -= sizeof(uint16);

  if (data_length < size)
    return dtls_alert_fatal_create(DTLS_ALERT_DECODE_ERROR);

  while (err >= 0 && data_length) {
    if (data_length < sizeof(uint16) * 2)
      return dtls_alert_fatal_create(DTLS_ALERT_DECODE_ERROR);

    /* get the tls extension type */
    type = dtls_uint16_to_int(data);
    data += sizeof(uint16);
    data_length -= sizeof(uint16);

    /* get the length of the tls extension */
    size = dtls_uint16_to_int(data);
    data += sizeof(uint16);
    data_length -= sizeof(uint16);

    if (data_length < size)
      return dtls_alert_fatal_create(DTLS_ALERT_DECODE_ERROR);

    switch (type)
    {
    case TLS_EXT_SUPPORTED_VERSIONS:
      if (hs_type != DTLS_HT_CLIENT_HELLO &&
          hs_type != DTLS_HT_SERVER_HELLO &&
          hs_type != DTLS_HT_HELLO_RETRY_REQUEST)
        return dtls_alert_fatal_create(DTLS_ALERT_ILLEGAL_PARAMETER);

      /* supported versions already processed */
      break;

    case TLS_EXT_CLIENT_CERTIFICATE_TYPE:
      if (hs_type != DTLS_HT_CLIENT_HELLO &&
          hs_type != DTLS_HT_ENCRYPTED_EXTENSIONS)
        return dtls_alert_fatal_create(DTLS_ALERT_ILLEGAL_PARAMETER);

      if (info->ext_client_cert_type)
        return dtls_alert_fatal_create(DTLS_ALERT_ILLEGAL_PARAMETER);

      err = verify_ext_certificate_type(data, size, hs_type);
      info->ext_client_cert_type = 1;
      break;
    
    case TLS_EXT_SERVER_CERTIFICATE_TYPE:
      if (hs_type != DTLS_HT_CLIENT_HELLO &&
          hs_type != DTLS_HT_ENCRYPTED_EXTENSIONS)
        return dtls_alert_fatal_create(DTLS_ALERT_ILLEGAL_PARAMETER);

      if (info->ext_server_cert_type)
        return dtls_alert_fatal_create(DTLS_ALERT_ILLEGAL_PARAMETER);

      err = verify_ext_certificate_type(data, size, hs_type);
      info->ext_server_cert_type = 1;
      break;

    case TLS_EXT_KEY_SHARE:
      if (hs_type != DTLS_HT_CLIENT_HELLO &&
          hs_type != DTLS_HT_SERVER_HELLO &&
          hs_type != DTLS_HT_HELLO_RETRY_REQUEST)
        return dtls_alert_fatal_create(DTLS_ALERT_ILLEGAL_PARAMETER);

      if (info->ext_key_share)
        return dtls_alert_fatal_create(DTLS_ALERT_ILLEGAL_PARAMETER);

      err = verify_ext_key_share(data, size, hs_type, &info->pub_key);
      info->ext_key_share = 1;
      break;

    case TLS_EXT_COOKIE:
      if (hs_type != DTLS_HT_CLIENT_HELLO &&
          hs_type != DTLS_HT_HELLO_RETRY_REQUEST)
        return dtls_alert_fatal_create(DTLS_ALERT_ILLEGAL_PARAMETER);

      if (info->ext_cookie)
        return dtls_alert_fatal_create(DTLS_ALERT_ILLEGAL_PARAMETER);

      err = verify_ext_cookie(data, size, hs_type,
                &info->cookie, &info->cookie_length);
      info->ext_cookie = 1;
      break;

    case TLS_EXT_SUPPORTED_GROUPS:
      if (hs_type != DTLS_HT_CLIENT_HELLO &&
          hs_type != DTLS_HT_ENCRYPTED_EXTENSIONS)
        return dtls_alert_fatal_create(DTLS_ALERT_ILLEGAL_PARAMETER);

      if (info->ext_supported_groups)
        return dtls_alert_fatal_create(DTLS_ALERT_ILLEGAL_PARAMETER);

      err = verify_ext_supported_groups(data, size, hs_type);
      info->ext_supported_groups = 1;
      break;

    case TLS_EXT_SIGNATURE_ALGORITHMS:
      if (hs_type != DTLS_HT_CLIENT_HELLO &&
          hs_type != DTLS_HT_CERTIFICATE_REQUEST)
        return dtls_alert_fatal_create(DTLS_ALERT_ILLEGAL_PARAMETER);

      if (info->ext_sig_algo)
        return dtls_alert_fatal_create(DTLS_ALERT_ILLEGAL_PARAMETER);

      err = verify_ext_signature_algorithms(data, size, hs_type);
      info->ext_sig_algo = 1;
      break;

#if (DTLS_MAX_CID_LENGTH > 0)
    case TLS_EXT_CONNECTION_ID:
      if (hs_type != DTLS_HT_CLIENT_HELLO &&
          hs_type != DTLS_HT_SERVER_HELLO)
        return dtls_alert_fatal_create(DTLS_ALERT_ILLEGAL_PARAMETER);

      if (info->ext_connection_id)
        return dtls_alert_fatal_create(DTLS_ALERT_ILLEGAL_PARAMETER);

      err = verify_ext_connection_id(peer->handshake_params, data, size, hs_type);
      info->ext_connection_id = 1;
      break;
#endif /* DTLS_MAX_CID_LENGTH */

    default:
      dtls_notice("unsupported tls extension: %i\n", type);
      break;
    }

    data += size;
    data_length -= size;
  }
  
  return err;
}

static int
dtls_check_supported_versions(uint8 *data,
                              size_t data_length,
                              uint16_t hs_type) {
  int ret;
  uint8* ext;
  int extlen;

  ret = find_ext_by_type(data, data_length, TLS_EXT_SUPPORTED_VERSIONS, &ext, &extlen);
  if (ret < 0)
    return ret;

  if (ret == 0) {
    dtls_warn("no supported_versions extension\n");
    return dtls_alert_fatal_create(DTLS_ALERT_HANDSHAKE_FAILURE);
  }
  /* extension present */

  if (hs_type == DTLS_HT_CLIENT_HELLO) {
    /* CH must have DTLS 1.3 inside version list */
    ret = list_contains_key(ext, extlen,
                            sizeof(uint8), sizeof(uint16),
                            DTLS13_VERSION);
    if (ret < 0) {
      return ret; /* error */
    } else if (ret == 0) {
      dtls_warn("no DTLS 1.3 version found in extension\n");
      return dtls_alert_fatal_create(DTLS_ALERT_PROTOCOL_VERSION);
    }

  } else if (hs_type == DTLS_HT_HELLO_RETRY_REQUEST || hs_type == DTLS_HT_SERVER_HELLO) {
    /* HRR and SH must have DTLS 1.3 as content inside extension */
    if (extlen != 2)
      return dtls_alert_fatal_create(DTLS_ALERT_HANDSHAKE_FAILURE);

    if (dtls_uint16_to_int(ext) != DTLS13_VERSION) {
      dtls_warn("wrong DTLS version in extension\n");
      return dtls_alert_fatal_create(DTLS_ALERT_PROTOCOL_VERSION);
    }
  }

  /* DTLS 1.3 version found */
  return 0;
}

/**
 * Parses the ClientHello from the client and updates the internal handshake
 * parameters with the new data for the given \p peer. When the ClientHello
 * handshake message in \p data does not contain a cipher suite or
 * compression method, it is copied from the the current security parameters.
 *
 * \param ctx   The current DTLS context.
 * \param peer  The remote peer whose security parameters are about to change.
 * \param data  The handshake message with a ClientHello.
 * \param data_length The actual size of \p data.
 * \param cookie The cookie from the ClientHello.
 * \return \c -Something if an error occurred, \c 0 on success.
 */
static int
dtls_update_parameters(dtls_context_t *ctx,
		       dtls_peer_t *peer,
		       uint8 *data, size_t data_length,
           dtls_cookie_t *cookie) {
  int i;
  unsigned int j;
  int ok;
  dtls_cipher_t cipher = TLS_NULL_WITH_NULL_NULL;
  dtls_handshake_parameters_t *config = peer->handshake_params;
  dtls_extension_info_t ext_info;

  assert(config);
  assert(data_length > DTLS_HS_LENGTH + DTLS_CH_LENGTH);

  /* skip the handshake header and client version information */
  data += DTLS_HS_LENGTH + sizeof(uint16);
  data_length -= DTLS_HS_LENGTH + sizeof(uint16);

  /* store client random in config */
  memcpy(config->tmp.random.client, data, DTLS_RANDOM_LENGTH);
  data += DTLS_RANDOM_LENGTH;
  data_length -= DTLS_RANDOM_LENGTH;

  /* Caution: SKIP_VAR_FIELD may jump to error: */
  SKIP_VAR_FIELD(data, data_length, uint8);	/* skip session id */
  SKIP_VAR_FIELD(data, data_length, uint8);	/* skip cookie */

  if (data_length < sizeof(uint16)) {
    dtls_debug("cipher suites length exceeds record\n");
    goto error;
  }

  i = dtls_uint16_to_int(data);

  if (i == 0) {
    dtls_debug("cipher suites missing\n");
    goto error;
  }

  if (data_length < i + sizeof(uint16)) {
    dtls_debug("length for cipher suites exceeds record\n");
    goto error;
  }

  if ((i % sizeof(uint16)) != 0) {
    dtls_debug("odd length for cipher suites\n");
    goto error;
  }

  data += sizeof(uint16);
  data_length -= sizeof(uint16) + i;

  config->user_parameters = default_user_parameters;
  if (ctx->h->get_user_parameters != NULL) {
    ctx->h->get_user_parameters(ctx, &peer->session, &config->user_parameters);
  }

  ok = 0;
  while ((i >= (int)sizeof(uint16)) && !ok) {
    // MF: determine key exchange algorithm from extensions
    cipher = dtls_uint16_to_int(data);
    config->cipher_index = get_cipher_index(&config->user_parameters, cipher, DTLS_KEY_EXCHANGE_ECDHE_ECDSA);
    ok = known_cipher_index(ctx, config->cipher_index, 0);
    i -= sizeof(uint16);
    data += sizeof(uint16);
  }

  /* skip remaining ciphers */
  data += i;

  if (!ok) {
    /* reset config cipher to a well-defined value */
    config->cipher_index = DTLS_CIPHER_INDEX_NULL;
    dtls_warn("No matching cipher suite found\n");
    goto error;
  }

  if (cipher != dtls_uint16_to_int(cookie->cipher_suite)) {
    dtls_warn("cipher suite differs from first client hello\n");
    goto error;
  }

  if (data_length < sizeof(uint8)) {
    dtls_debug("compression methods length exceeds record\n");
    goto error;
  }

  i = dtls_uint8_to_int(data);

  if (i == 0) {
    dtls_debug("compression methods missing\n");
    goto error;
  }

  if (data_length < i + sizeof(uint8)) {
    dtls_debug("length of compression methods exceeds record\n");
    goto error;
  }

  data += sizeof(uint8);
  data_length -= sizeof(uint8) + i;

  ok = 0;
  while (i && !ok) {
    for (j = 0; j < sizeof(compression_methods) / sizeof(uint8); ++j) {
      if (dtls_uint8_to_int(data) == compression_methods[j]) {
        config->compression = compression_methods[j];
        ok = 1;
      }
    }
    i -= sizeof(uint8);
    data += sizeof(uint8);
  }

  /* skip remaining compression methods */
  data += i;

  if (!ok) {
    /* reset config cipher to a well-defined value */
    goto error;
  }

  int res = dtls_parse_tls_extension(peer, data, data_length, DTLS_HT_CLIENT_HELLO, &ext_info);

  if (res < 0) {
    dtls_warn("error in dtls_parse_tls_extension err: %i\n", res);
    return res;
  }

  assert(ext_info.ext_cookie);

  if (!ext_info.ext_supported_groups || !ext_info.ext_sig_algo || !ext_info.ext_key_share) {
    dtls_warn("mandatory extensions missing in client hello\n");
    return dtls_alert_fatal_create(DTLS_ALERT_HANDSHAKE_FAILURE);
  }

  if (!ext_info.ext_client_cert_type || !ext_info.ext_server_cert_type) {
    dtls_warn("certificate type extensions missing in client hello\n");
    return dtls_alert_fatal_create(DTLS_ALERT_MISSING_EXTENSION);
  }

  if (!ext_info.pub_key) {
    dtls_warn("no valid KeyShareEntry in client hello\n");
    return dtls_alert_fatal_create(DTLS_ALERT_ILLEGAL_PARAMETER);
  }

  store_ecdhe_pub_key(peer, ext_info.pub_key);
  return 0;

error:
  if (peer->state == DTLS_STATE_CONNECTED) {
    return dtls_alert_create(DTLS_ALERT_LEVEL_WARNING, DTLS_ALERT_NO_RENEGOTIATION);
  } else {
    return dtls_alert_fatal_create(DTLS_ALERT_HANDSHAKE_FAILURE);
  }
}

static void copy_hs_hash(dtls_peer_t *peer, dtls_hash_ctx *hs_hash);

static void
update_hs_hash(dtls_peer_t *peer, uint8 *data, size_t length) {
  dtls_debug_hexdump("add MAC data", data, length);
  dtls_hash_update(&peer->handshake_params->hs_state.hs_hash, data, length);

  // dtls_hash_ctx hash;
  // unsigned char buf[DTLS_HMAC_DIGEST_SIZE];
  // copy_hs_hash(peer, &hash);
  // dtls_hash_finalize(buf, &hash);
  // dtls_debug_dump("  Hash: ", buf, sizeof(buf));
}

static void
copy_hs_hash(dtls_peer_t *peer, dtls_hash_ctx *hs_hash) {
  memcpy(hs_hash, &peer->handshake_params->hs_state.hs_hash,
	 sizeof(peer->handshake_params->hs_state.hs_hash));
}

static inline size_t
finalize_hs_hash(dtls_peer_t *peer, uint8 *buf) {
  return dtls_hash_finalize(buf, &peer->handshake_params->hs_state.hs_hash);
}

static inline void
clear_hs_hash(dtls_peer_t *peer) {
  assert(peer);
  dtls_debug("clear MAC\n");
  dtls_hash_init(&peer->handshake_params->hs_state.hs_hash);
}

static inline void
hash_handshake_header(dtls_peer_t *peer, uint8 *data) {

  /* exclude DTLS only fields in Transcript Hash. Included fields are:
   *    msg_type      := 1 byte
   *    length        := 3 bytes
   */
  update_hs_hash(peer, data, sizeof(uint32));
}

static inline void
hash_handshake(dtls_peer_t *peer, uint8 *data, size_t length) {
  if (length >= DTLS_HS_LENGTH) {
    hash_handshake_header(peer, data);
    data += DTLS_HS_LENGTH;
    length -= DTLS_HS_LENGTH;
    update_hs_hash(peer, data, length);
  }
}

static void
hash_message_hash(dtls_peer_t *peer, unsigned char ch_hash[]) {
  uint8 buf[4];
  unsigned char sha256hash[DTLS_SHA256_DIGEST_LENGTH];

  /* The hash of the first client hello is either inside the current
   * transcript hash (ch_hash == NULL) or inside ch_hash */

  if (!ch_hash) {
    finalize_hs_hash(peer, sha256hash);
  }

  /* create Header for Handshake Message of type message_hash.
   * This Message is never transmitted and only used for the Transcript Hash.
   * The only fields needed are msg_type(1) and length(3).
   * The content of a Message of type message_hash is the Hash of
   * the first Client Hello.
   */
  dtls_int_to_uint8(buf, DTLS_HT_MESSAGE_HASH);
  dtls_int_to_uint24(buf + 1, DTLS_HMAC_DIGEST_SIZE);

  clear_hs_hash(peer);
  /* Header */
  update_hs_hash(peer, buf, sizeof(buf));
  /* Content */
  if (ch_hash) {
    update_hs_hash(peer, ch_hash, DTLS_SHA256_DIGEST_LENGTH);
  } else {
    update_hs_hash(peer, sha256hash, DTLS_SHA256_DIGEST_LENGTH);
  }
}

static int
build_hello_retry_request(uint8 *buf, dtls_cookie_t *cookie) {

  /* buf must have a size of at least DTLS_HRR_LENGTH_MAX */
  uint8 *p = buf;
  int msg_length = DTLS_HRR_LENGTH_MAX;
  uint16_t extensions_length = DTLS_HRR_LENGTH_MAX - DTLS_SH_LENGTH - 2;
  int with_key_share = dtls_uint16_to_int(cookie->named_group) != 0;

  if (!with_key_share) {
    /* no key_share extension */
    msg_length -= 6;
    extensions_length -= 6;
  }

  /* Begin of Hello Retry Request */
  p += dtls_int_to_uint16(p, DTLS12_VERSION);

  /* RFC 8446 4.1.3 HelloRetryRequest uses the same structure as ServerHello,
   * but with Random set to SHA-256 of "HelloRetryRequest" */
  memcpy(p, hello_retry_magic, DTLS_RANDOM_LENGTH);
  p += DTLS_RANDOM_LENGTH;

  *p++ = 0; /* no session id */

  /* selected cipher suite */
  memcpy(p, cookie->cipher_suite, sizeof(uint16));
  p += sizeof(uint16);

  p += dtls_int_to_uint8(p, TLS_COMPRESSION_NULL);
  p += dtls_int_to_uint16(p, extensions_length);

  /* ext supported_versions */
  p += create_ext_supported_versions(p, DTLS_SERVER);
  /* ext cookie */
  p += create_ext_cookie(p, (uint8*) cookie, DTLS_COOKIE_LENGTH);

  if (with_key_share) {
    /* ext key_share */
    p += create_ext_key_share_hello_retry(p);
  }

  assert((p - buf) == (int) msg_length);
  return msg_length;
}

static void
hash_hello_retry_request(dtls_peer_t *peer, dtls_cookie_t *cookie) {

  uint8 header[4];
  uint8 message[DTLS_HRR_LENGTH_MAX];

  /* Hello Retry Request */
  int length = build_hello_retry_request(message, cookie);

  /* Handshake header */
  dtls_int_to_uint8(header, DTLS_HT_SERVER_HELLO);
  dtls_int_to_uint24(header + 1, length);
  hash_handshake_header(peer, header);

  update_hs_hash(peer, message, length);
}

typedef enum {
  ENCRYPT_SIDE_ONLY = 0,
  DECRYPT_SIDE_ONLY,
  ENCRYPT_AND_DECRYPT_SIDE
} dtls_key_side;

typedef enum {
  TRANSCRIPT_HASH,
  EMPTY_STRING_HASH,
  EMPTY_CONTEXT
} dtls_context_type;

static int dtls_derive_secret(dtls_peer_t *peer,
                         dtls_context_type context, const uint8 *prk,
                         const char *label, uint8 labellen,
                         uint8 *okm, size_t okmlen)
{
  dtls_hash_ctx msg_hash;
  unsigned char sha256hash[DTLS_SHA256_DIGEST_LENGTH];
  uint8_t hashlen = 0;

  switch (context)
  {
  case TRANSCRIPT_HASH:
    /* Use the current transcript hash of all hs messages so far. */
    copy_hs_hash(peer, &msg_hash);
    dtls_hash_finalize(sha256hash, &msg_hash);
    hashlen = DTLS_SHA256_DIGEST_LENGTH;
    dtls_debug_hexdump("transcript hash", sha256hash, sizeof(sha256hash));
    break;

  case EMPTY_STRING_HASH:
    /* Use hash of empty string. */
    dtls_hash_init(&msg_hash);
    dtls_hash_update(&msg_hash, NULL, 0);
    dtls_hash_finalize(sha256hash, &msg_hash);
    hashlen = DTLS_SHA256_DIGEST_LENGTH;
    break;

  case EMPTY_CONTEXT:
    // MF: remove EMPTY_CONTEXT and directly call dtls_hkdf_expand_label
    /* Use a zero-length Context */
    hashlen = 0;
    break;

  default:
    break;
  }

  return dtls_hkdf_expand_label(HASH_SHA256, prk, DTLS_SECRET_LENGTH, label, labellen,
                                sha256hash, hashlen, okm, okmlen);
}

static int dtls_derive_early_secret(dtls_peer_t *peer, dtls_security_parameters_t *security)
{
  uint8 *prk = peer->handshake_params->tmp.early_secret;

  /* Temporarily use the key_block storage space for the pre master secret. */
  uint8 *ikm = security->key_block;

  return dtls_hkdf_extract(HASH_SHA256, NULL, 0, ikm, DTLS_SECRET_LENGTH, prk);
}

static int dtls_derive_handshake_secret(dtls_peer_t *peer, dtls_security_parameters_t *security)
{
  uint8 *ikm; /* pre master secret */
  size_t ikmlen = 32; // MF: Macro for ecdhe key length?
  uint8 salt[DTLS_SHA256_DIGEST_LENGTH];

  if (!security) {
    return dtls_alert_fatal_create(DTLS_ALERT_INTERNAL_ERROR);
  }

  /* Temporarily use the key_block storage space for the pre master secret. */
  ikm = security->key_block;

  /* derive secret from early secret. Used as salt for hkdf extract
   * to calculate handshake secret from pre master secret (ikm). */
  dtls_derive_secret(peer, EMPTY_STRING_HASH, peer->handshake_params->tmp.early_secret, "derived", 7, salt, sizeof(salt));
  dtls_hkdf_extract(HASH_SHA256, salt, sizeof(salt), ikm, ikmlen, peer->handshake_params->tmp.handshake_secret);

  return 0; /* TODO: check */
}

static int dtls_derive_master_secret(dtls_peer_t *peer)
{
  uint8 salt[DTLS_SHA256_DIGEST_LENGTH];
  /* ikm consists of zero string */
  uint8 ikm[DTLS_SECRET_LENGTH];
  memset(ikm, 0, DTLS_SECRET_LENGTH);

  /* derive secret from handshake secret. Used as salt for hkdf extract */
  dtls_derive_secret(peer, EMPTY_STRING_HASH, peer->handshake_params->tmp.handshake_secret, "derived", 7, salt, sizeof(salt));
  dtls_hkdf_extract(HASH_SHA256, salt, sizeof(salt), ikm, sizeof(ikm), peer->handshake_params->tmp.master_secret);

  return 0; /* TODO: check */
}

static int dtls_derive_finished_secret(dtls_peer_t *peer, dtls_peer_type key_side, uint8 *out)
{
  uint8 *secret;
  dtls_security_parameters_t *security = peer->security_params[0];

  if (!security) {
    return dtls_alert_fatal_create(DTLS_ALERT_INTERNAL_ERROR);
  }

  /* MAC write key of which side to derive */
  if (key_side == DTLS_SERVER) {
    secret = security->server_traffic_secret;
  } else {
    secret = security->client_traffic_secret;
  }

  return dtls_derive_secret(peer, EMPTY_CONTEXT, secret, "finished", 8, out, DTLS_HMAC_DIGEST_SIZE);
}

// MF: maybe create enum for key side client / server
#define PROVISION_CLIENT 1
#define PROVISION_SERVER 2
#define PROVISION_CLIENT_SERVER 3

static int dtls_derive_keys(dtls_peer_t *peer, dtls_security_parameters_t *security, dtls_key_type type, dtls_key_side side)
{
  // input: Early / Handshake / Master Secret
  uint8 *prk;
  uint8 *secret;
  uint8_t provision;

  if (side == ENCRYPT_AND_DECRYPT_SIDE) {
    provision = PROVISION_CLIENT_SERVER;
  } else {
    provision = peer->role == (uint8_t) side ? PROVISION_CLIENT : PROVISION_SERVER;
  }

  if (!security) {
    return dtls_alert_fatal_create(DTLS_ALERT_INTERNAL_ERROR);
  }

  switch (type)
  {
  case EARLY_DATA_KEY:
    return -1;

  case HANDSHAKE_KEY:
    prk = peer->handshake_params->tmp.handshake_secret;
    if (provision & PROVISION_CLIENT) {
      dtls_derive_secret(peer, TRANSCRIPT_HASH, prk, "c hs traffic", 12, security->client_traffic_secret, DTLS_SECRET_LENGTH);
    }
    if (provision & PROVISION_SERVER) {
      dtls_derive_secret(peer, TRANSCRIPT_HASH, prk, "s hs traffic", 12, security->server_traffic_secret, DTLS_SECRET_LENGTH);
    }
    break;

  case TRAFFIC_KEY:
    prk = peer->handshake_params->tmp.master_secret;
    if (provision & PROVISION_CLIENT) {
      dtls_derive_secret(peer, TRANSCRIPT_HASH, prk, "c ap traffic", 12, security->client_traffic_secret, DTLS_SECRET_LENGTH);
    }
    if (provision & PROVISION_SERVER) {
      dtls_derive_secret(peer, TRANSCRIPT_HASH, prk, "s ap traffic", 12, security->server_traffic_secret, DTLS_SECRET_LENGTH);
    }
    break;

  case UPDATE_TRAFFIC_KEY:
    if (provision & PROVISION_CLIENT) {
      prk = security->client_traffic_secret;
      dtls_derive_secret(peer, EMPTY_CONTEXT, prk, "traffic upd", 11, security->client_traffic_secret, DTLS_SECRET_LENGTH);
    }
    if (provision & PROVISION_SERVER) {
      prk = security->server_traffic_secret;
      dtls_derive_secret(peer, EMPTY_CONTEXT, prk, "traffic upd", 11, security->server_traffic_secret, DTLS_SECRET_LENGTH);
    }
    break;
    
  default:
    /* Invalid */
    dtls_crit("invalid key type %d\n", type);
    return -1;
  }

  if (provision & PROVISION_CLIENT) {
    /* derive client traffic secret from previous secret */
    secret = security->client_traffic_secret;
    /* generate client write key, write iv and sn key from traffic secret */
    dtls_derive_secret(peer, EMPTY_CONTEXT, secret, "key", 3, dtls_kb_client_write_key(security, peer->role), DTLS_KEY_LENGTH);
    dtls_derive_secret(peer, EMPTY_CONTEXT, secret, "iv", 2, dtls_kb_client_iv(security, peer->role), DTLS_IV_LENGTH);
    dtls_derive_secret(peer, EMPTY_CONTEXT, secret, "sn", 2, dtls_kb_client_sn_key(security, peer->role), DTLS_KEY_LENGTH);
  }

  if (provision & PROVISION_SERVER) {
    /* derive server traffic secret from previous secret */
    secret = security->server_traffic_secret;
    /* generate server write key, write iv and sn key from traffic secret */
    dtls_derive_secret(peer, EMPTY_CONTEXT, secret, "key", 3, dtls_kb_server_write_key(security, peer->role), DTLS_KEY_LENGTH);
    dtls_derive_secret(peer, EMPTY_CONTEXT, secret, "iv", 2, dtls_kb_server_iv(security, peer->role), DTLS_IV_LENGTH);
    dtls_derive_secret(peer, EMPTY_CONTEXT, secret, "sn", 2, dtls_kb_server_sn_key(security, peer->role), DTLS_KEY_LENGTH);
  }

  return 0; /* TODO: check */
}

static int
calculate_key_block(dtls_peer_t *peer, dtls_key_type type) {
  dtls_handshake_parameters_t *handshake = peer->handshake_params;
  dtls_security_parameters_t *security;
  unsigned char *pre_master_secret;
  int pre_master_len = 0;
  int err = 0;

//  assert(is_key_exchange_ecdhe_ecdsa(handshake->cipher_index));

  security = dtls_security_params_next(peer, (uint8_t) type);
  if (!security) {
    return dtls_alert_fatal_create(DTLS_ALERT_INTERNAL_ERROR);
  }
  
  /* Temporarily use the key_block storage space for the pre master secret. */
  pre_master_secret = security->key_block;

  switch (type)
  {
  case EARLY_DATA_KEY:
    // MF: store psk in pre_master_secret, if using PSKs
    // dtls_psk_pre_master_secret()

    // else set it to zero
    pre_master_len = DTLS_SECRET_LENGTH;
    memset(pre_master_secret, 0, DTLS_SECRET_LENGTH);

    dtls_debug_dump("  pre_master_secret PSK", pre_master_secret, pre_master_len);

    err = dtls_derive_early_secret(peer, security);
    if (err < 0) {
      dtls_warn("error in derive early secret err: %i\n", err);
      return err;
    }
    dtls_debug_dump("  early_secret", handshake->tmp.early_secret, DTLS_SECRET_LENGTH);

    // MF: derive early data key here if client wants to send early data
    // dtls_derive_keys(peer, EARLY_DATA_KEY, ...);
    break;

  case HANDSHAKE_KEY:
    // MF: check if ecdsa keys are present (maybe PSK only)
    pre_master_len = dtls_ecdh_pre_master_secret(
                          handshake->keyx.ecdsa.own_eph_priv,
                          handshake->keyx.ecdsa.other_eph_pub_x,
                          handshake->keyx.ecdsa.other_eph_pub_y,
                          sizeof(handshake->keyx.ecdsa.own_eph_priv),
                          pre_master_secret,
                          sizeof(handshake->keyx.ecdsa.own_eph_priv));
    if (pre_master_len < 0) {
      dtls_crit("the curve was too long, for the pre master secret\n");
      return dtls_alert_fatal_create(DTLS_ALERT_INTERNAL_ERROR);
    }

    dtls_debug_dump("  pre_master_secret DHE", pre_master_secret, pre_master_len);

    err = dtls_derive_handshake_secret(peer, security);
    if (err < 0) {
      dtls_warn("error in derive handshake secret err: %i\n", err);
      return err;
    }
    dtls_debug_dump("  handshake_secret", handshake->tmp.handshake_secret, DTLS_SECRET_LENGTH);

    err = dtls_derive_keys(peer, security, HANDSHAKE_KEY, ENCRYPT_AND_DECRYPT_SIDE);
    if (err < 0) {
      dtls_warn("error in derive keys err: %i\n", err);
      return err;
    }
    dtls_debug_dump("  client_handshake_traffic_secret",
      security->client_traffic_secret, DTLS_SECRET_LENGTH);
    dtls_debug_dump("  server_handshake_traffic_secret",
      security->server_traffic_secret, DTLS_SECRET_LENGTH);
    dtls_debug_keyblock(security);
    break;

  case TRAFFIC_KEY:
    err = dtls_derive_master_secret(peer);
    if (err < 0) {
      dtls_warn("error in derive master secret err: %i\n", err);
      return err;
    }

    dtls_debug_dump("  master_secret", peer->handshake_params->tmp.master_secret, DTLS_SECRET_LENGTH);

    err = dtls_derive_keys(peer, security, TRAFFIC_KEY, ENCRYPT_AND_DECRYPT_SIDE);
    if (err < 0) {
      dtls_warn("error in derive keys err: %i\n", err);
      return err;
    }

    dtls_debug_dump("  client_application_traffic_secret_0",
      security->client_traffic_secret, DTLS_SECRET_LENGTH);
    dtls_debug_dump("  server_application_traffic_secret_0",
      security->server_traffic_secret, DTLS_SECRET_LENGTH);
    dtls_debug_keyblock(security);
    break;

  case UPDATE_TRAFFIC_KEY:
    return -1;
 
  default:
    return -1;
  }

  security->cipher_index = handshake->cipher_index;
  security->compression = TLS_COMPRESSION_NULL;
  security->rseq = 0;
#if (DTLS_MAX_CID_LENGTH > 0)
  security->write_cid_length = handshake->write_cid_length;
  memcpy(security->write_cid, handshake->write_cid, handshake->write_cid_length);
#endif /* DTLS_MAX_CID_LENGTH > 0 */

  return 0;
}

// MF: TODO fix ordering of functions
static int dtls_send_certificate_ecdsa(dtls_context_t*, dtls_peer_t*, const dtls_ecdsa_key_t*);
static int dtls_send_certificate_verify_ecdh(dtls_context_t*, dtls_peer_t*, const dtls_ecdsa_key_t*);
static int dtls_send_finished(dtls_context_t*, dtls_peer_t*);

static int
dtls_send_handshake_msg(dtls_context_t *, dtls_peer_t *, uint8,uint8 *,size_t);

static int
dtls_send_ack(dtls_context_t *ctx, dtls_peer_t *peer, dtls_record_number_t *rn) {
  uint8 buf[2 + sizeof(*rn)];
  uint8 *p = buf;

  p += dtls_int_to_uint16(p, sizeof(*rn));
  p += dtls_int_to_uint64(p, rn->epoch);
  p += dtls_int_to_uint64(p, rn->seq_nr);

  return dtls_send(ctx, peer, DTLS_CT_ACK, buf, sizeof(buf));
}

/**
 * Checks if \p record + \p data contain a Finished message with valid
 * verify_data.
 *
 * \param ctx    The current DTLS context.
 * \param peer   The remote peer of the security association.
 * \param data   The cleartext payload of the message.
 * \param data_length Actual length of \p data.
 * \return \c 0 if the Finished message is valid, \c negative number otherwise.
 */
static int
check_finished(dtls_context_t *ctx, dtls_peer_t *peer,
           uint8 *data, size_t data_length) {
  (void) ctx;
  int res = 0;
  dtls_hmac_context_t hmac_ctx;
  uint8 hmac_key[DTLS_HMAC_DIGEST_SIZE];
  dtls_peer_type key_side;
  // size_t digest_length, label_size;
  // const unsigned char *label;
  unsigned char buf[DTLS_SHA256_DIGEST_LENGTH];
  dtls_handshake_parameters_t *handshake = peer->handshake_params;
  // dtls_security_parameters_t *security;
#ifdef DTLS_ECC
  const dtls_ecdsa_key_t *ecdsa_key;
#endif /* DTLS_ECC */

  if (data_length < DTLS_HS_LENGTH + DTLS_FIN_LENGTH)
    return dtls_alert_fatal_create(DTLS_ALERT_HANDSHAKE_FAILURE);

  /* Use a union here to ensure that sufficient stack space is
   * reserved. As statebuf and verify_data are not used at the same
   * time, we can re-use the storage safely.
   */
  union {
    unsigned char statebuf[DTLS_HASH_CTX_SIZE];
    unsigned char verify_data[DTLS_FIN_LENGTH];
  } b;

  /* temporarily store hash status for roll-back after finalize */
  memcpy(b.statebuf, &handshake->hs_state.hs_hash, DTLS_HASH_CTX_SIZE);

  finalize_hs_hash(peer, buf);
  /* clear_hash(); */

  /* restore hash status */
  memcpy(&handshake->hs_state.hs_hash, b.statebuf, DTLS_HASH_CTX_SIZE);

  if (peer->role == DTLS_CLIENT) {
    key_side = DTLS_SERVER; /* server write MAC key */
  } else { /* server */
    key_side = DTLS_CLIENT; /* client write MAC key */
  }

  res = dtls_derive_finished_secret(peer, key_side, hmac_key);

  if (res < 0)
    return res;

  dtls_debug_dump("finished_key", hmac_key, sizeof(hmac_key));

  dtls_hmac_init(&hmac_ctx, hmac_key, sizeof(hmac_key));
  dtls_hmac_update(&hmac_ctx, buf, sizeof(buf));
  dtls_hmac_finalize(&hmac_ctx, b.verify_data);

  dtls_debug_dump("d:", data + DTLS_HS_LENGTH, sizeof(b.verify_data));
  dtls_debug_dump("v:", b.verify_data, sizeof(b.verify_data));

  /* compare verify data and create DTLS alert code when they differ */
  if (!equals(data + DTLS_HS_LENGTH, b.verify_data, sizeof(b.verify_data)))
    return dtls_alert_fatal_create(DTLS_ALERT_DECRYPT_ERROR);

  // MF: this might not be the best check
  // If the client does not send a certificate, the finished message
  // is the first message the server receives after sending its
  // finished message. Need to calculate traffic keys then.
  if (peer->role == DTLS_SERVER && !peer->security_params[1]) {
    res = calculate_key_block(peer, TRAFFIC_KEY);

    if (res < 0) {
      dtls_alert("dtls_finished: error in calculate_key_block\n");
      return res;
    }
  }

  hash_handshake(peer, data, data_length);

  if (peer->role == DTLS_CLIENT) {

    res = calculate_key_block(peer, TRAFFIC_KEY);
    if (res < 0) {
      dtls_alert("dtls_finished: error in calculate_key_block\n");
      return res;
    }

#ifdef DTLS_ECC
    if (handshake->do_client_auth) {

      res = CALL(ctx, get_ecdsa_key, &peer->session, &ecdsa_key);
      if (res < 0) {
        dtls_crit("no ecdsa certificate to send in certificate\n");
        return res;
      }

      res = dtls_send_certificate_ecdsa(ctx, peer, ecdsa_key);

      if (res < 0) {
        dtls_debug("dtls_finished: cannot prepare Certificate record\n");
        return res;
      }

      res = dtls_send_certificate_verify_ecdh(ctx, peer, ecdsa_key);

      if (res < 0) {
        dtls_debug("dtls_finished: cannot prepare Certificate record\n");
        return res;
      }
    }
#endif /* DTLS_ECC */

    res = dtls_send_finished(ctx, peer);

    if (res < 0) {
      dtls_alert("dtls_finished: error in send_finished\n");
      return res;
    }
  }

  /* switch cipher suite. We are now in epoch DTLS_EPOCH_APPLICATION_0 (3) */
  dtls_security_params_switch(peer);
  handshake->hs_state.read_epoch = dtls_security_params(peer)->epoch;

  if (peer->role == DTLS_SERVER) {
    /* acknowledge the client's finished message */
    dtls_record_number_t rn;
    rn.epoch = HANDSHAKE_KEY;
    rn.seq_nr = peer->security_params[1]->cseq.cseq;
    res = dtls_send_ack(ctx, peer, &rn);
  }

  return res;
}

static int
decrypt_verify(dtls_peer_t *peer, dtls_record_number_t *rn,
               uint8 *packet, size_t length,
               int header_length, uint8 **cleartext);

/**
 * Prepares the payload given in \p data for sending with
 * dtls_send(). The \p data is encrypted and compressed according to
 * the current security parameters of \p peer. The result of this
 * operation is put into \p sendbuf with a prepended record header of
 * type \p type ready for sending. As some cipher suites add a MAC
 * before encryption, \p data must be large enough to hold this data
 * as well (usually \c dtls_kb_digest_size(CURRENT_CONFIG(peer)).
 *
 * \param peer            The remote peer the packet will be sent to.
 * \param security        The encryption paramater used to encrypt
 * \param type            The content type of this record.
 * \param data_array      Array with payloads in correct order.
 * \param data_len_array  Sizes of the payloads in correct order.
 * \param data_array_len  The number of payloads given.
 * \param sendbuf         The output buffer where the encrypted record
 *                        will be placed.
 * \param rlen            This parameter must be initialized with the
 *                        maximum size of \p sendbuf and will be updated
 *                        to hold the actual size of the stored packet
 *                        on success. On error, the value of \p rlen is
 *                        undefined.
 * \return Less than zero on error, or greater than zero success.
 */
static int
dtls_prepare_record(dtls_peer_t *peer, dtls_security_parameters_t *security,
		    unsigned char type,
		    uint8 *data_array[], size_t data_len_array[],
		    size_t data_array_len,
		    uint8 *sendbuf, size_t *rlen) {
  uint8 *p;
  int res;
  unsigned int i;

  if (!peer || !security) {
    dtls_alert("peer or security parameter missing\n");
    return dtls_alert_fatal_create(DTLS_ALERT_INTERNAL_ERROR);
  }

  if (security->cipher_index == DTLS_CIPHER_INDEX_NULL) {
    /* no cipher suite */

    if (*rlen < DTLS_RH_LENGTH) {
      dtls_alert("The sendbuf (%zu bytes) is too small\n", *rlen);
      return dtls_alert_fatal_create(DTLS_ALERT_INTERNAL_ERROR);
    }

    p = dtls_set_record_header(type, security->epoch, &(security->rseq), sendbuf);

    res = 0;
    for (i = 0; i < data_array_len; i++) {
      /* check the minimum that we need for packets that are not encrypted */
      if (*rlen < res + DTLS_RH_LENGTH + data_len_array[i]) {
        dtls_debug("dtls_prepare_record: send buffer too small\n");
        return dtls_alert_fatal_create(DTLS_ALERT_INTERNAL_ERROR);
      }

      memcpy(p, data_array[i], data_len_array[i]);
      p += data_len_array[i];
      res += data_len_array[i];
    }

    /* fix length of fragment in sendbuf */
    dtls_int_to_uint16(sendbuf + 11, res);

    *rlen = DTLS_RH_LENGTH + res;

  } else { /* TLS_PSK_WITH_AES_128_CCM_8, TLS_PSK_WITH_AES_128_CCM,
              TLS_ECDHE_ECDSA_WITH_AES_128_CCM_8 or
              TLS_ECDHE_ECDSA_WITH_AES_128_CCM */

    if (*rlen < 5) {
      dtls_alert("The sendbuf (%zu bytes) is too small\n", *rlen);
      return dtls_alert_fatal_create(DTLS_ALERT_INTERNAL_ERROR);
    }

    /* create unified header */
    uint8 *start;
    uint8 *pseq; /* points to seq num in header */
    uint8_t flags = UHDR_MAGIC_VAL;
    flags |= UHDR_SEQ_LEN_BIT;
    flags |= UHDR_LENGTH_BIT;
    flags |= (uint8_t) (security->epoch & UHDR_EPOCH_BITS);
    p = sendbuf;

#if (DTLS_MAX_CID_LENGTH > 0)
    if (security->write_cid_length > 0)
      flags |= UHDR_CID_BIT;
#endif /* DTLS_MAX_CID_LENGTH > 0 */

    dtls_int_to_uint8(p, flags);
    p += sizeof(uint8);

#if (DTLS_MAX_CID_LENGTH > 0)
    if (security->write_cid_length > 0) {
      memcpy(p, security->write_cid, security->write_cid_length);
      p += security->write_cid_length;
    }
#endif /* DTLS_MAX_CID_LENGTH > 0 */

    pseq = p;

    dtls_int_to_uint16(p, (uint16_t) (security->rseq & 0xffff));
    p += sizeof(uint16);

    /* space for record size */
    p += sizeof(uint16);
    start = p;

    unsigned char nonce[DTLS_CCM_BLOCKSIZE];
    // unsigned char A_DATA[A_DATA_LEN];
    const uint8_t mac_len = get_cipher_suite_mac_len(security->cipher_index);
    const dtls_key_exchange_algorithm_t key_exchange_algorithm =
            get_key_exchange_algorithm(security->cipher_index);
    /* For backwards-compatibility, dtls_encrypt_params is called with
     * M=<macLen> and L=3. */
    const dtls_ccm_params_t params = { nonce, mac_len, 3 };
    const size_t rh_length = p - sendbuf;

    if (mac_len == 0) {
        dtls_debug("dtls_prepare_record(): encrypt using unknown cipher\n");
    } else {
      if (key_exchange_algorithm == DTLS_KEY_EXCHANGE_PSK) {
        dtls_debug("dtls_prepare_record(): encrypt using "
                   "TLS_PSK_WITH_AES_128_CCM_%d\n", mac_len);
      } else if (key_exchange_algorithm == DTLS_KEY_EXCHANGE_ECDHE_ECDSA) {
        dtls_debug("dtls_prepare_record(): encrypt using "
                   "TLS_ECDHE_ECDSA_WITH_AES_128_CCM_%d\n", mac_len);
      }
    }

    res = 0;

    for (i = 0; i < data_array_len; i++) {
      /* check the minimum that we need for packets that are not encrypted */
      if (*rlen < res + rh_length + data_len_array[i]) {
        dtls_debug("dtls_prepare_record: send buffer too small\n");
        return dtls_alert_fatal_create(DTLS_ALERT_INTERNAL_ERROR);
      }

      memcpy(p, data_array[i], data_len_array[i]);
      p += data_len_array[i];
      res += data_len_array[i];
    }

    if (*rlen < res + rh_length + 1) {
      dtls_debug("dtls_prepare_record: send buffer too small\n");
      return dtls_alert_fatal_create(DTLS_ALERT_INTERNAL_ERROR);
    }

    /* content type is at the end of plaintext */
    dtls_int_to_uint8(p, type);
    p += sizeof(uint8);
    res += sizeof(uint8);
    /* no zero padding */ // MF: TODO add padding when using CCM_8

    /* fix length of fragment in sendbuf */
    dtls_int_to_uint16(sendbuf + rh_length - sizeof(uint16), res + mac_len);

    /* nonce is iv xored with seq num padded to the left with zeros to iv length */
    memset(nonce, 0, DTLS_CCM_BLOCKSIZE);
    dtls_int_to_uint64(nonce + DTLS_IV_LENGTH - sizeof(uint64_t), security->rseq);
    memxor(nonce, dtls_kb_local_iv(security, peer->role), dtls_kb_iv_size(security, peer->role));

    dtls_debug_dump("nonce:", nonce, DTLS_CCM_BLOCKSIZE);
    dtls_debug_dump("key:", dtls_kb_local_write_key(security, peer->role), dtls_kb_key_size(security, peer->role));

    res = dtls_encrypt_params(&params, start, res, start,
              dtls_kb_local_write_key(security, peer->role),
              dtls_kb_key_size(security, peer->role),
              sendbuf, rh_length);

    if (res < 0)
      return res;

    int err = dtls_encrypt_decrypt_seq_num(security, peer->role, start, pseq, 2, DTLS_ENCRYPT);

    if (err < 0)
      return err;

    /* increment record sequence counter by 1 */
    security->rseq++;
    *rlen = rh_length + res;
  }

  return 0;
}

/**
 * Send Alert in stateless fashion.
 * An Alert is sent to the peer (using the write callback function
 * registered with \p ctx). The return value is the number of bytes sent,
 * or less than 0 on error.
 *
 * \param ctx              The DTLS context.
 * \param ephemeral_peer   The ephemeral remote party we are talking to.
 * \param level            Alert level.
 * \param description      Alert description.
 * \return number of bytes sent, or less than 0 on error.
 */
static int
dtls_0_send_alert(dtls_context_t *ctx,
			     dtls_ephemeral_peer_t *ephemeral_peer,
			     dtls_alert_level_t level,
			     dtls_alert_t description)
{
  uint8 buf[DTLS_RH_LENGTH + DTLS_ALERT_LENGTH];
  uint8 *p = dtls_set_record_header(DTLS_CT_ALERT, 0, &(ephemeral_peer->rseq), buf);

  /* fix length of fragment in sendbuf */
  dtls_int_to_uint16(buf + 11, DTLS_ALERT_LENGTH);

  /* Alert */
  dtls_int_to_uint8(p, level);
  dtls_int_to_uint8(p + 1, description);

  dtls_debug("send alert - protocol version  packet\n");

  dtls_debug_hexdump("send header", buf, DTLS_RH_LENGTH);
  dtls_debug_hexdump("send unencrypted alert", p, DTLS_ALERT_LENGTH);

  return CALL(ctx, write, ephemeral_peer->session, buf, sizeof(buf));
}

static int
dtls_0_send_alert_from_err(dtls_context_t *ctx,
                           dtls_ephemeral_peer_t *ephemeral_peer,
                           int err) {

  assert(ephemeral_peer);

  if (dtls_is_alert(err)) {
    dtls_alert_level_t level = ((-err) & 0xff00) >> 8;
    dtls_alert_t desc = (-err) & 0xff;
    return dtls_0_send_alert(ctx, ephemeral_peer, level, desc);
  } else if (err == -1) {
    return dtls_0_send_alert(ctx, ephemeral_peer, DTLS_ALERT_LEVEL_FATAL,
                             DTLS_ALERT_INTERNAL_ERROR);
  }
  return -1;
}

static int
dtls_0_send_hello_retry_request(dtls_context_t *ctx,
                                dtls_ephemeral_peer_t *ephemeral_peer,
                                dtls_cookie_t *cookie)
{
  uint8 buf[DTLS_RH_LENGTH + DTLS_HS_LENGTH + DTLS_HRR_LENGTH_MAX];
  size_t data_length;
  /* build record from bottom up to get the length for the headers. */
  uint8 *p = buf + DTLS_RH_LENGTH + DTLS_HS_LENGTH;
  
  data_length = build_hello_retry_request(p, cookie);
  dtls_set_handshake_header(DTLS_HT_SERVER_HELLO,
                      &(ephemeral_peer->mseq), data_length, 0, data_length,
                      buf + DTLS_RH_LENGTH);

  p = dtls_set_record_header(DTLS_CT_HANDSHAKE, 0, &(ephemeral_peer->rseq), buf);
  /* fix length of fragment in sendbuf */
  dtls_int_to_uint16(p - sizeof(uint16), DTLS_HS_LENGTH + data_length);

  dtls_debug("send hello_retry_request packet\n");

  dtls_debug_hexdump("send header", buf, DTLS_RH_LENGTH);
  dtls_debug_hexdump("send unencrypted handshake header", buf + DTLS_RH_LENGTH,
                     DTLS_HS_LENGTH);

  // assert((buf <= p) && ((unsigned int)(p - buf) <= sizeof(buf)));

  return CALL(ctx, write, ephemeral_peer->session, buf, DTLS_RH_LENGTH + DTLS_HS_LENGTH + data_length);
}

static int
dtls_send_handshake_msg_hash(dtls_context_t *ctx,
			     dtls_peer_t *peer,
			     session_t *session,
			     uint8 header_type,
			     uint8 *data, size_t data_length,
			     int add_hash)
{
  uint8 buf[DTLS_HS_LENGTH];
  uint8 *data_array[2];
  size_t data_len_array[2];
  int i = 0;
  dtls_security_parameters_t *security = dtls_security_params(peer);

  dtls_set_handshake_header(header_type,
                            &(peer->handshake_params->hs_state.mseq_s),
                            data_length, 0, data_length, buf);

  if (add_hash) {
    hash_handshake_header(peer, buf);
  }
  data_array[i] = buf;
  data_len_array[i] = sizeof(buf);
  i++;

  if (data != NULL) {
    if (add_hash) {
      update_hs_hash(peer, data, data_length);
    }
    data_array[i] = data;
    data_len_array[i] = data_length;
    i++;
  }
  dtls_debug("send handshake packet of type: %s (%i)\n",
	     dtls_handshake_type_to_name(header_type), header_type);
  return dtls_send_multi(ctx, peer, security, session, DTLS_CT_HANDSHAKE,
			 data_array, data_len_array, i);
}

static int
dtls_send_handshake_msg(dtls_context_t *ctx,
			dtls_peer_t *peer,
			uint8 header_type,
			uint8 *data, size_t data_length)
{
  return dtls_send_handshake_msg_hash(ctx, peer, &peer->session,
				      header_type, data, data_length, 1);
}

/**
 * Returns true if the message @p Data is a handshake message that
 * must be included in the calculation of verify_data in the Finished
 * message.
 *
 * @param Type The message type. Only handshake messages but the initial
 * Client Hello and Hello Verify Request are included in the hash,
 * @param Data The PDU to examine.
 * @param Length The length of @p Data.
 *
 * @return @c 1 if @p Data must be included in hash, @c 0 otherwise.
 *
 * @hideinitializer
 */
#define MUST_HASH(Type, Data, Length)					\
  ((Type) == DTLS_CT_HANDSHAKE &&					\
   ((Data) != NULL) && ((Length) > 0)  &&				\
   ((Data)[0] != DTLS_HT_HELLO_VERIFY_REQUEST) &&			\
   ((Data)[0] != DTLS_HT_CLIENT_HELLO ||				\
    ((Length) >= HS_HDR_LENGTH &&					\
     (dtls_uint16_to_int(DTLS_RECORD_HEADER(Data)->epoch > 0) ||	\
      (dtls_uint16_to_int(HANDSHAKE(Data)->message_seq) > 0)))))


#ifdef DTLS_CONSTRAINED_STACK
static dtls_mutex_t static_mutex = DTLS_MUTEX_INITIALIZER;
static unsigned char sendbuf[DTLS_MAX_BUF];
#endif /* DTLS_CONSTRAINED_STACK */

/**
 * Sends the data passed in @p buf as a DTLS record of type @p type to
 * the given peer. The data will be encrypted and compressed according
 * to the security parameters for @p peer.
 *
 * @param ctx             The DTLS context in effect.
 * @param peer            The remote party where the packet is sent.
 * @param security        The encryption paramater used to encrypt.
 * @param session         The transport address of the remote peer.
 * @param type            The content type of this record.
 * @param buf_array       The array of data to send.
 * @param buf_len_array   The number of bytes in each array element.
 * @param buf_array_len   The number of array elements.
 * @return Less than zero in case of an error or the number of
 *   bytes that have been sent otherwise.
 */
static int
dtls_send_multi(dtls_context_t *ctx, dtls_peer_t *peer,
		dtls_security_parameters_t *security , session_t *session,
		unsigned char type, uint8 *buf_array[],
		size_t buf_len_array[], size_t buf_array_len)
{
  /* We cannot use ctx->sendbuf here as it is reserved for collecting
   * the input for this function, i.e. buf == ctx->sendbuf.
   *
   * TODO: check if we can use the receive buf here. This would mean
   * that we might not be able to handle multiple records stuffed in
   * one UDP datagram */
#ifndef DTLS_CONSTRAINED_STACK
  unsigned char sendbuf[DTLS_MAX_BUF];
#endif /* ! DTLS_CONSTRAINED_STACK */
  size_t len = sizeof(sendbuf);
  int res;
  unsigned int i;
  size_t overall_len = 0;

#ifdef DTLS_CONSTRAINED_STACK
  dtls_mutex_lock(&static_mutex);
#endif /* DTLS_CONSTRAINED_STACK */

  res = dtls_prepare_record(peer, security, type, buf_array, buf_len_array,
                            buf_array_len, sendbuf, &len);

  if (res < 0)
    goto return_unlock;

  /* if (peer && MUST_HASH(peer, type, buf, buflen)) */
  /*   update_hs_hash(peer, buf, buflen); */


  /* Signal DTLS version 1.0 in the record layer of ClientHello and
   * HelloVerifyRequest handshake messages according to Section 4.2.1
   * of RFC 6347.
   *
   * This does not apply to a renegotation ClientHello
   */
  if (security->epoch == 0) {
    if (type == DTLS_CT_HANDSHAKE) {
      if (buf_array[0][0] == DTLS_HT_CLIENT_HELLO) {
        dtls_int_to_uint16(sendbuf + 1, DTLS10_VERSION);
      }
    }
  }

  // dtls_debug_hexdump("send header", sendbuf, sizeof(dtls_record_header_t));
  for (i = 0; i < buf_array_len; i++) {
    // dtls_debug_hexdump("send unencrypted", buf_array[i], buf_len_array[i]);
    overall_len += buf_len_array[i];
  }

  if (type == DTLS_CT_HANDSHAKE || type == DTLS_CT_CHANGE_CIPHER_SPEC) {
    /* copy messages of handshake into retransmit buffer */
    netq_t *n = netq_node_new(overall_len);
    if (n) {
      dtls_tick_t now;
      dtls_ticks(&now);
      n->t = now + 2 * CLOCK_SECOND;
      n->retransmit_cnt = 0;
      n->timeout = 2 * CLOCK_SECOND;
      n->peer = peer;
      n->epoch = (security) ? security->epoch : 0;
      n->type = type;
      n->job = RESEND;
      n->length = 0;
      for (i = 0; i < buf_array_len; i++) {
        memcpy(n->data + n->length, buf_array[i], buf_len_array[i]);
        n->length += buf_len_array[i];
      }

      if (!netq_insert_node(&ctx->sendqueue, n)) {
        dtls_warn("cannot add packet to retransmit buffer\n");
        netq_node_free(n);
#ifdef WITH_CONTIKI
      } else {
        /* must set timer within the context of the retransmit process */
        PROCESS_CONTEXT_BEGIN(&dtls_retransmit_process);
        etimer_set(&ctx->retransmit_timer, n->timeout);
        PROCESS_CONTEXT_END(&dtls_retransmit_process);
#else /* WITH_CONTIKI */
        dtls_debug("copied to sendqueue\n");
#endif /* WITH_CONTIKI */
      }
    } else {
      dtls_warn("retransmit buffer full\n");
    }
  }

  /* FIXME: copy to peer's sendqueue (after fragmentation if
   * necessary) and initialize retransmit timer */
  res = CALL(ctx, write, session, sendbuf, len);

return_unlock:
#ifdef DTLS_CONSTRAINED_STACK
  dtls_mutex_unlock(&static_mutex);
#endif /* DTLS_CONSTRAINED_STACK */

  /* Guess number of bytes application data actually sent:
   * dtls_prepare_record() tells us in len the number of bytes to
   * send, res will contain the bytes actually sent. */
  return res <= 0 ? res : (int)(overall_len - (len - (unsigned int)res));
}

static inline int
dtls_send_alert(dtls_context_t *ctx, dtls_peer_t *peer, dtls_alert_level_t level,
		dtls_alert_t description) {
  uint8_t msg[] = { level, description };

  dtls_send(ctx, peer, DTLS_CT_ALERT, msg, sizeof(msg));

  /* copy close alert in retransmit buffer to emulate timeout */
  /* not resent, therefore don't copy the complete record */
  netq_t *n = netq_node_new(2);
  if (n) {
    dtls_tick_t now;
    dtls_ticks(&now);
    n->t = now + 2 * CLOCK_SECOND;
    n->retransmit_cnt = 0;
    n->timeout = 2 * CLOCK_SECOND;
    n->peer = peer;
    n->epoch = peer->security_params[0]->epoch;
    n->type = DTLS_CT_ALERT;
    n->length = 2;
    n->data[0] = level;
    n->data[1] = description;
    n->job = TIMEOUT;

    if (!netq_insert_node(&ctx->sendqueue, n)) {
      dtls_warn("cannot add alert to retransmit buffer\n");
      netq_node_free(n);
      n = NULL;
#ifdef WITH_CONTIKI
    } else {
      /* must set timer within the context of the retransmit process */
      PROCESS_CONTEXT_BEGIN(&dtls_retransmit_process);
      etimer_set(&ctx->retransmit_timer, n->timeout);
      PROCESS_CONTEXT_END(&dtls_retransmit_process);
#else /* WITH_CONTIKI */
      dtls_debug("alert copied to retransmit buffer\n");
#endif /* WITH_CONTIKI */
    }
  } else {
    dtls_warn("cannot add alert, retransmit buffer full\n");
  }
  if (!n) {
    /* timeout not registered */
    handle_alert(ctx, peer, NULL, msg, sizeof(msg));
  }

  return 0;
}

int
dtls_close(dtls_context_t *ctx, const session_t *remote) {
  int res = -1;
  dtls_peer_t *peer;

  peer = dtls_get_peer(ctx, remote);

  if (peer) {
    /* indicate tear down */
    peer->state = DTLS_STATE_CLOSING;
    res = dtls_send_alert(ctx, peer, DTLS_ALERT_LEVEL_WARNING,
                          DTLS_ALERT_CLOSE_NOTIFY);
  }
  return res;
}

static void
dtls_destroy_peer(dtls_context_t *ctx, dtls_peer_t *peer, int flags) {
  if ((flags & DTLS_DESTROY_CLOSE) &&
      (peer->state != DTLS_STATE_CLOSED) &&
      (peer->state != DTLS_STATE_CLOSING)) {
    dtls_close(ctx, &peer->session);
  }
  dtls_stop_retransmission(ctx, peer);
  DEL_PEER(ctx->peers, peer);
  dtls_dsrv_log_addr(DTLS_LOG_DEBUG, "removed peer", &peer->session);
  dtls_free_peer(peer);
}

/**
 * Checks a received ClientHello message for a valid cookie. When the
 * ClientHello contains no cookie, the function fails and a HelloVerifyRequest
 * is sent to the peer (using the write callback function registered
 * with \p ctx). The return value is \c -1 on error, \c 1 when
 * undecided, and \c 0 if the ClientHello was good.
 *
 * \param ctx              The DTLS context.
 * \param ephemeral_peer   The remote party we are talking to, if any.
 * \param data             The received datagram.
 * \param data_length      Length of \p msg.
 * \param cookie           The cookie from the ClientHello.
 *
 * \return \c 0 if msg is a ClientHello with a valid cookie, \c 1 or
 * \c -1 otherwise.
 */
static int
dtls_0_verify_peer(dtls_context_t *ctx,
		 dtls_ephemeral_peer_t *ephemeral_peer,
		 uint8 *data, size_t data_length,
     dtls_cookie_t **cookie)
{
  int res;
  int len;
  /* keep original data and length for the hash */
  uint8 *const hs_data = data;
  const size_t hs_length = data_length;
  dtls_cookie_t mycookie;
  uint8 *extension = NULL;
  uint8 *p_suites = NULL;
  uint16_t suites_len;

  /* skip contents of client hello */
  data += DTLS_HS_LENGTH + DTLS_CH_LENGTH;
  data_length -= DTLS_HS_LENGTH + DTLS_CH_LENGTH;

  /*
   * legacy_session_id          := 1 byte
   * legacy_cookie              := 1 byte
   * cipher_suites length       := 2 bytes => 4 bytes
   */
  if (data_length < 4)
    return dtls_alert_fatal_create(DTLS_ALERT_HANDSHAKE_FAILURE);

  if (dtls_uint8_to_int(data) != 0)
    return dtls_alert_fatal_create(DTLS_ALERT_ILLEGAL_PARAMETER);

  if (dtls_uint8_to_int(data + 1) != 0)
    return dtls_alert_fatal_create(DTLS_ALERT_ILLEGAL_PARAMETER);

  /* session id and cookie */
  data += 2;
  data_length -= 2;

  /* cipher_suites length */
  suites_len = dtls_uint16_to_int(data);
  data += 2;
  data_length -= 2;
  p_suites = data;

  if ((suites_len % sizeof(uint16)) != 0) {
    dtls_debug("odd length for cipher suites\n");
    return dtls_alert_fatal_create(DTLS_ALERT_HANDSHAKE_FAILURE);
  }

  if (data_length < suites_len)
    return dtls_alert_fatal_create(DTLS_ALERT_HANDSHAKE_FAILURE);

  /* skip cipher suites */
  data += suites_len;
  data_length -= suites_len;

  /* legacy_compression_methods */
  if (data_length < 2 * sizeof(uint8))
    return dtls_alert_fatal_create(DTLS_ALERT_HANDSHAKE_FAILURE);

  /* only one compression method: Null Compression */
  if (dtls_uint8_to_int(data) != 1 || dtls_uint8_to_int(data + 1) != TLS_COMPRESSION_NULL)
    return dtls_alert_fatal_create(DTLS_ALERT_ILLEGAL_PARAMETER);

  data += 2 * sizeof(uint8);
  data_length -= 2 * sizeof(uint8);

  res = dtls_check_supported_versions(data, data_length, DTLS_HT_CLIENT_HELLO);
  if (res < 0)
    return res;

  res = find_ext_by_type(data, data_length, TLS_EXT_COOKIE, &extension, &len);
  if (res < 0)
    return res;

  /* Perform cookie check. */

  if (res > 0) {
    /* found cookie extension */
    if (dtls_check_cookie(ctx, ephemeral_peer->session, extension, len, cookie)) {
      dtls_debug("found matching cookie\n");
      return 0;
    } else {
      return dtls_alert_fatal_create(DTLS_ALERT_UNEXPECTED_MESSAGE);
    }
  }

  dtls_debug("no cookie extension\n");

  /* ClientHello did not contain any valid cookie, hence we send a
   * HelloVerifyRequest. */

  dtls_user_parameters_t user_parameters = default_user_parameters;
  if (ctx->h->get_user_parameters != NULL) {
    ctx->h->get_user_parameters(ctx, ephemeral_peer->session, &user_parameters);
  }

  res = 0;
  while ((suites_len >= (int)sizeof(uint16)) && !res) {
    // MF: determine key exchange algorithm from extensions
    memcpy(mycookie.cipher_suite, p_suites, sizeof(uint16));
    dtls_cipher_index_t cipher_index = get_cipher_index(&user_parameters, dtls_uint16_to_int(p_suites), DTLS_KEY_EXCHANGE_ECDHE_ECDSA);
    res = known_cipher_index(ctx, cipher_index, 0);
    suites_len -= sizeof(uint16);
    p_suites += sizeof(uint16);
  }

  if (!res) {
    dtls_warn("No matching cipher suite found\n");
    return dtls_alert_fatal_create(DTLS_ALERT_HANDSHAKE_FAILURE);
  }

  dtls_int_to_uint16(mycookie.named_group, TLS_NAMED_GROUP_SECP256R1);
  res = find_ext_by_type(data, data_length, TLS_EXT_KEY_SHARE, &extension, &len);
  if (res < 0)
    return res;

  if (res > 0) {
    res = verify_ext_key_share(extension, len, DTLS_HT_CLIENT_HELLO, NULL);
    if (res < 0)
      return res;

    /* Found a valid key share entry. That means we don't need
     * a key_share extension in hello retry request. */
    if (res > 0)
      dtls_int_to_uint16(mycookie.named_group, 0);
  }

  res = create_cookie(ctx, ephemeral_peer->session, hs_data, hs_length, &mycookie);
  if (res < 0)
    return res;

  res = dtls_0_send_hello_retry_request(ctx, ephemeral_peer, &mycookie);

  if (res < 0) {
    dtls_warn("cannot send HelloVerify request\n");
  }
  return res; /* HelloVerifyRequest is sent, now we cannot do anything but wait */
}

#ifdef DTLS_ECC
/*
 * Assumes that data_len is at least 1 */
static size_t
dtls_asn1_len(uint8 **data, size_t *data_len)
{
  size_t len = 0;

  if ((**data) & 0x80) {
    size_t octets = (**data) & 0x7f;
    (*data)++;
    (*data_len)--;
    if (octets > *data_len)
      return (size_t)-1;
    while (octets > 0) {
      len = (len << 8) + (**data);
      (*data)++;
      (*data_len)--;
      octets--;
    }
  }
  else {
    len = (**data) & 0x7f;
    (*data)++;
    (*data_len)--;
  }
  return len;
}

static int
dtls_asn1_integer_to_ec_key(uint8 *data, size_t data_len, uint8 *key,
                         size_t key_len)
{
  size_t length;

  if (data_len < 2) {
    dtls_alert("signature data length short\n");
    return dtls_alert_fatal_create(DTLS_ALERT_DECODE_ERROR);
  }
  if (dtls_uint8_to_int(data) != 0x02) {
    dtls_alert("wrong ASN.1 struct, expected Integer\n");
    return dtls_alert_fatal_create(DTLS_ALERT_DECODE_ERROR);
  }
  data += sizeof(uint8);
  data_len -= sizeof(uint8);

  length = dtls_asn1_len(&data, &data_len);
  if (length > data_len) {
    dtls_alert("asn1 integer length too long\n");
    return dtls_alert_fatal_create(DTLS_ALERT_DECODE_ERROR);
  }

  if (length < key_len) {
    /* pad with leading 0s */
    memset(key, 0, key_len - length);
    memcpy(key + key_len - length, data, length); 
  }
  else {
    /* drop leading 0s if needed */
    memcpy(key, data + length - key_len, key_len); 
  }
  return length + 2;
}

static int
dtls_check_ecdsa_signature_elem(uint8 *data, size_t data_length,
				unsigned char *result_r,
				unsigned char *result_s)
{
  int ret;
  uint8 *data_orig = data;

  /*
   * 1 sig hash sha256
   * 1 sig hash ecdsa
   * 2 data length
   * 1 sequence
   * 1 sequence length
   */
  if (data_length < 1 + 1 + 2 + 1 + 1) {
    dtls_alert("signature data length short\n");
    return dtls_alert_fatal_create(DTLS_ALERT_DECODE_ERROR);
  }
  if (dtls_uint8_to_int(data) != TLS_EXT_SIG_HASH_ALGO_SHA256) {
    dtls_alert("only sha256 is supported in certificate verify\n");
    return dtls_alert_fatal_create(DTLS_ALERT_HANDSHAKE_FAILURE);
  }
  data += sizeof(uint8);
  data_length -= sizeof(uint8);

  if (dtls_uint8_to_int(data) != TLS_EXT_SIG_HASH_ALGO_ECDSA) {
    dtls_alert("only ecdsa signature is supported in client verify\n");
    return dtls_alert_fatal_create(DTLS_ALERT_HANDSHAKE_FAILURE);
  }
  data += sizeof(uint8);
  data_length -= sizeof(uint8);

  if (data_length < dtls_uint16_to_int(data)) {
    dtls_alert("signature length wrong\n");
    return dtls_alert_fatal_create(DTLS_ALERT_DECODE_ERROR);
  }
  data += sizeof(uint16);
  data_length -= sizeof(uint16);

  if (dtls_uint8_to_int(data) != 0x30) {
    dtls_alert("wrong ASN.1 struct, expected SEQUENCE\n");
    return dtls_alert_fatal_create(DTLS_ALERT_DECODE_ERROR);
  }
  data += sizeof(uint8);
  data_length -= sizeof(uint8);

  if (data_length < dtls_uint8_to_int(data)) {
    dtls_alert("signature length wrong\n");
    return dtls_alert_fatal_create(DTLS_ALERT_DECODE_ERROR);
  }
  data += sizeof(uint8);
  data_length -= sizeof(uint8);

  ret = dtls_asn1_integer_to_ec_key(data, data_length, result_r, DTLS_EC_KEY_SIZE);
  if (ret <= 0)
    return ret;
  data += ret;
  data_length -= ret;

  ret = dtls_asn1_integer_to_ec_key(data, data_length, result_s, DTLS_EC_KEY_SIZE);
  if (ret <= 0)
    return ret;
  data += ret;
  data_length -= ret;

  return data - data_orig;
}

static int
check_client_certificate_verify(dtls_context_t *ctx,
				dtls_peer_t *peer,
				uint8 *data, size_t data_length)
{
  (void) ctx;
  dtls_handshake_parameters_t *config = peer->handshake_params;
  int ret;
  unsigned char result_r[DTLS_EC_KEY_SIZE];
  unsigned char result_s[DTLS_EC_KEY_SIZE];
  dtls_hash_ctx hs_hash;
  unsigned char sha256hash[DTLS_HMAC_DIGEST_SIZE];

  assert(is_key_exchange_ecdhe_ecdsa(config->cipher_index));

  data += DTLS_HS_LENGTH;
  data_length -= DTLS_HS_LENGTH;

  if (data_length < DTLS_CV_LENGTH - 2 * DTLS_EC_KEY_SIZE) {
    /*
     * Some of the ASN.1 integer in the signature may be less than
     * DTLS_EC_KEY_SIZE if leading bits are 0.
     * dtls_check_ecdsa_signature_elem() knows how to handle this undersize.
     */
    dtls_alert("the packet length does not match the expected\n");
    return dtls_alert_fatal_create(DTLS_ALERT_DECODE_ERROR);
  }

  ret = dtls_check_ecdsa_signature_elem(data, data_length, result_r, result_s);
  if (ret < 0) {
    return ret;
  }
  data += ret;
  data_length -= ret;

  copy_hs_hash(peer, &hs_hash);

  dtls_hash_finalize(sha256hash, &hs_hash);

  ret = dtls_ecdsa_verify_sig_hash(config->keyx.ecdsa.other_pub_x,
                                   config->keyx.ecdsa.other_pub_y,
                                   sizeof(config->keyx.ecdsa.other_pub_x),
                                   sha256hash, sizeof(sha256hash),
                                   result_r, result_s);

  if (ret < 0) {
    dtls_alert("wrong signature err: %i\n", ret);
    return dtls_alert_fatal_create(DTLS_ALERT_HANDSHAKE_FAILURE);
  }
  return 0;
}
#endif /* DTLS_ECC */

static int
dtls_send_server_hello(dtls_context_t *ctx, dtls_peer_t *peer)
{
  /* Ensure that the largest message to create fits in our source
   * buffer. (The size of the destination buffer is checked by the
   * encoding function, so we do not need to guess.)
   *
   * extensions length       := 2 bytes
   * client certificate type := 5 bytes
   * server certificate type := 5 bytes
   * ec_point_formats        := 6 bytes
   * extended master secret  := 4 bytes
   * key_share               := 73 bytes
   *
   * (no elliptic_curves in ServerHello.)
   */
  uint8 buf[DTLS_SH_LENGTH + 2 + 5 + 5 + 6 + 4 + 73];
  uint8 *p;
  uint8 *p_extension_size = NULL;
  uint8 extension_size = 0;
  dtls_handshake_parameters_t * const handshake = peer->handshake_params;
  const dtls_cipher_t cipher_suite = get_cipher_suite(handshake->cipher_index);
  const int ecdsa = is_key_exchange_ecdhe_ecdsa(handshake->cipher_index);

  /* Handshake header */
  p = buf;

  /* ServerHello */
  dtls_int_to_uint16(p, DTLS_VERSION);
  p += sizeof(uint16);

  /* Set 32 bytes of server random data. */
  dtls_prng(handshake->tmp.random.server, DTLS_RANDOM_LENGTH);

  memcpy(p, handshake->tmp.random.server, DTLS_RANDOM_LENGTH);
  p += DTLS_RANDOM_LENGTH;

  *p++ = 0;			/* no session id */

  if (cipher_suite != TLS_NULL_WITH_NULL_NULL) {
    /* selected cipher suite */
    dtls_int_to_uint16(p, cipher_suite);
    p += sizeof(uint16);

    /* selected compression method */
    *p++ = compression_methods[handshake->compression];
  }

  /* keep pointer to length of the extensions */
  p_extension_size = p;
  /* skip length of extensions field */
  p += sizeof(uint16);

  p += create_ext_supported_versions(p, peer->role);

  if (ecdsa) {
    p += create_ext_key_share_generate_key(p, peer->role, handshake);
  }
  if (handshake->extended_master_secret) {
    /* extended master secret, 4 bytes */
    dtls_int_to_uint16(p, TLS_EXT_EXTENDED_MASTER_SECRET);
    p += sizeof(uint16);

    /* length of this extension type */
    dtls_int_to_uint16(p, 0);
    p += sizeof(uint16);
  }

  /* length of the extensions */
  extension_size = (p - p_extension_size) - sizeof(uint16);
  dtls_int_to_uint16(p_extension_size, extension_size);

  assert((buf <= p) && ((unsigned int)(p - buf) <= sizeof(buf)));

  /* TODO use the same record sequence number as in the ClientHello,
     see 4.2.1. Denial-of-Service Countermeasures */
  return dtls_send_handshake_msg(ctx, peer, DTLS_HT_SERVER_HELLO,
				 buf, p - buf);
}

static int
dtls_send_encrypted_extensions(dtls_context_t *ctx, dtls_peer_t *peer)
{
  /*
   * extensions length          := 2 bytes
   * client cert type           := 5 bytes
   * server cert type           := 5 bytes
   */
  uint8 buf[2 + 5 + 5];
  uint8 *p = buf;

  // MF: check key_exchange. Send empty EE if PSK

  /* length of the extensions */
  p += dtls_int_to_uint16(buf, 5 + 5);

  p += create_ext_client_certificate_type(p, DTLS_SERVER);
  p += create_ext_server_certificate_type(p, DTLS_SERVER);

  assert(buf + sizeof(buf) == p);

  return dtls_send_handshake_msg(ctx, peer, DTLS_HT_ENCRYPTED_EXTENSIONS,
          buf, p - buf);
}

#ifdef DTLS_ECC
#define DTLS_EC_SUBJECTPUBLICKEY_SIZE (2 * DTLS_EC_KEY_SIZE + sizeof(cert_asn1_header))

static int
dtls_send_certificate_ecdsa(dtls_context_t *ctx, dtls_peer_t *peer,
			    const dtls_ecdsa_key_t *key)
{
  /**
   * Certificate:
   * 
   * certificate_request_context length   := 1 byte
   * certificate_request_context          := 0 bytes
   * certificate_list length              := 3 bytes
   * 
   * CertificateEntry:
   * 
   * certificate length                   := 3 bytes
   * certificate                          := 91 bytes
   * extensions length                    := 2 bytes
   */
  uint8 buf[1 + 3 + 3 + DTLS_EC_SUBJECTPUBLICKEY_SIZE + 2];
  uint8 *p;

  /* Certificate
   *
   * Start message construction at beginning of buffer. */
  p = buf;

  // MF: add context in post-handshake authentication
  /* length of certificate_request_context */
  dtls_int_to_uint8(p, 0);
  p += sizeof(uint8);

  /* length of this certificate entry */
  dtls_int_to_uint24(p, 3 + DTLS_EC_SUBJECTPUBLICKEY_SIZE + 2);
  p += sizeof(uint24);

  /* length of this certificate */
  dtls_int_to_uint24(p, DTLS_EC_SUBJECTPUBLICKEY_SIZE);
  p += sizeof(uint24);

  memcpy(p, &cert_asn1_header, sizeof(cert_asn1_header));
  p += sizeof(cert_asn1_header);

  memcpy(p, key->pub_key_x, DTLS_EC_KEY_SIZE);
  p += DTLS_EC_KEY_SIZE;

  memcpy(p, key->pub_key_y, DTLS_EC_KEY_SIZE);
  p += DTLS_EC_KEY_SIZE;

  /* length of extensions */
  dtls_int_to_uint16(p, 0);
  p += sizeof(uint16);

  assert(p <= (buf + sizeof(buf)));

  return dtls_send_handshake_msg(ctx, peer, DTLS_HT_CERTIFICATE,
				 buf, p - buf);
}

static uint8 *
dtls_add_ecdsa_signature_elem(uint8 *p, uint32_t *point_r, uint32_t *point_s)
{
  int len_r;
  int len_s;

#define R_KEY_OFFSET (1 + 1 + 2 + 1 + 1)
#define S_KEY_OFFSET(len_a) (R_KEY_OFFSET + (len_a))
  /* store the pointer to the r component of the signature and make space */
  len_r = dtls_ec_key_asn1_from_uint32(point_r, DTLS_EC_KEY_SIZE, p + R_KEY_OFFSET);
  len_s = dtls_ec_key_asn1_from_uint32(point_s, DTLS_EC_KEY_SIZE, p + S_KEY_OFFSET(len_r));

#undef R_KEY_OFFSET
#undef S_KEY_OFFSET

  /* sha256 */
  dtls_int_to_uint8(p, TLS_EXT_SIG_HASH_ALGO_SHA256);
  p += sizeof(uint8);

  /* ecdsa */
  dtls_int_to_uint8(p, TLS_EXT_SIG_HASH_ALGO_ECDSA);
  p += sizeof(uint8);

  /* length of signature */
  dtls_int_to_uint16(p, len_r + len_s + 2);
  p += sizeof(uint16);

  /* ASN.1 SEQUENCE */
  dtls_int_to_uint8(p, 0x30);
  p += sizeof(uint8);

  dtls_int_to_uint8(p, len_r + len_s);
  p += sizeof(uint8);

  /* ASN.1 Integer r */

  /* the point r ASN.1 integer was added here so skip */
  p += len_r;

  /* ASN.1 Integer s */

  /* the point s ASN.1 integer was added here so skip */
  p += len_s;

  return p;
}
#endif /* DTLS_ECC */

#ifdef DTLS_ECC
static int
dtls_send_server_certificate_request(dtls_context_t *ctx, dtls_peer_t *peer)
{
  /**
   * CertificateRequest:
   * 
   * certificate_request_context length   := 1 byte
   * certificate_request_context          := 0 bytes
   * extensions length                    := 2 bytes
   * signature_algorithms                 := 8 bytes
  */
  uint8 buf[1 + 2 + 8];
  uint8 *p;

  /* Start message construction at beginning of buffer. */
  p = buf;

  // MF: add context in post-handshake authentication
  /* length of certificate_request_context */
  dtls_int_to_uint8(p, 0);
  p += sizeof(uint8);

  /* length of extensions */
  dtls_int_to_uint16(p, 8);
  p += sizeof(uint16);

  /* signature_algorithms */
  p += create_ext_signature_algorithms(p);

  assert(p <= (buf + sizeof(buf)));

  return dtls_send_handshake_msg(ctx, peer, DTLS_HT_CERTIFICATE_REQUEST,
				 buf, p - buf);
}
#endif /* DTLS_ECC */

static int
dtls_send_server_hello_msgs(dtls_context_t *ctx, dtls_peer_t *peer)
{
  int res;
  dtls_key_exchange_algorithm_t key_exchange_algorithm;

  res = dtls_send_server_hello(ctx, peer);

  if (res < 0) {
    dtls_debug("dtls_server_hello: cannot prepare ServerHello record\n");
    return res;
  }
  key_exchange_algorithm = get_key_exchange_algorithm(peer->handshake_params->cipher_index);

  // MF: move key_block early data to check CH if early data is supported
  res = calculate_key_block(peer, EARLY_DATA_KEY);
  if (res < 0)
    return res;

  res = calculate_key_block(peer, HANDSHAKE_KEY);
  if (res < 0)
    return res;

  /* switch cipher suite. We are now in epoch DTLS_EPOCH_HANDSHAKE (2) */
  dtls_security_params_switch(peer);
  peer->handshake_params->hs_state.read_epoch = dtls_security_params(peer)->epoch;

  res = dtls_send_encrypted_extensions(ctx, peer);
  if (res < 0)
    return res;

#ifdef DTLS_ECC
  if (DTLS_KEY_EXCHANGE_ECDHE_ECDSA == key_exchange_algorithm) {

    if (is_ecdsa_client_auth_supported(ctx)) {
      res = dtls_send_server_certificate_request(ctx, peer);

      if (res < 0) {
        dtls_debug("dtls_server_hello: cannot prepare certificate Request record\n");
        return res;
      }
    }

    const dtls_ecdsa_key_t *ecdsa_key;

    res = CALL(ctx, get_ecdsa_key, &peer->session, &ecdsa_key);
    if (res < 0) {
      dtls_crit("no ecdsa certificate to send in certificate\n");
      return res;
    }

    res = dtls_send_certificate_ecdsa(ctx, peer, ecdsa_key);

    if (res < 0) {
      dtls_debug("dtls_server_hello: cannot prepare Certificate record\n");
      return res;
    }

    res = dtls_send_certificate_verify_ecdh(ctx, peer, ecdsa_key);

    if (res < 0) {
      dtls_debug("dtls_server_hello: cannot prepare CertificateVerify record\n");
      return res;
    }
  }
#endif /* DTLS_ECC */

  res = dtls_send_finished(ctx, peer);

  if (res < 0) {
      dtls_alert("dtls_server_hello: error in send_finished\n");
      return res;
    }

  return 0;
}

static inline int
dtls_send_ccs(dtls_context_t *ctx, dtls_peer_t *peer) {
  uint8 buf[1] = {1};

  return dtls_send(ctx, peer, DTLS_CT_CHANGE_CIPHER_SPEC, buf, 1);
}

#ifdef DTLS_ECC
static int
dtls_send_certificate_verify_ecdh(dtls_context_t *ctx, dtls_peer_t *peer,
				   const dtls_ecdsa_key_t *key)
{
  /* The ASN.1 Integer representation of an 32 byte unsigned int could be
   * 33 bytes long add space for that */
  uint8 buf[DTLS_CV_LENGTH + 2];
  uint8 *p;
  uint32_t point_r[9];
  uint32_t point_s[9];
  dtls_hash_ctx hs_hash;
  unsigned char sha256hash[DTLS_HMAC_DIGEST_SIZE];

  /* ServerKeyExchange
   *
   * Start message construction at beginning of buffer. */
  p = buf;

  copy_hs_hash(peer, &hs_hash);

  dtls_hash_finalize(sha256hash, &hs_hash);

  /* sign the ephemeral and its paramaters */
  dtls_ecdsa_create_sig_hash(key->priv_key, DTLS_EC_KEY_SIZE,
			     sha256hash, sizeof(sha256hash),
			     point_r, point_s);

  p = dtls_add_ecdsa_signature_elem(p, point_r, point_s);

  assert(p <= (buf + sizeof(buf)));

  return dtls_send_handshake_msg(ctx, peer, DTLS_HT_CERTIFICATE_VERIFY,
				 buf, p - buf);
}
#endif /* DTLS_ECC */

static int
dtls_send_finished(dtls_context_t *ctx, dtls_peer_t *peer)
{
  uint8 hmac_key[DTLS_HMAC_DIGEST_SIZE];
  uint8 buf[DTLS_FIN_LENGTH];
  dtls_peer_type key_side;

  union {
    dtls_hash_ctx hash;
    dtls_hmac_context_t hmac;
  } hs_ctx;

  if (peer->role == DTLS_CLIENT) {
    key_side = DTLS_CLIENT; /* client write MAC key */
  } else { /* server */
    key_side = DTLS_SERVER; /* server write MAC key */
  }

  int res = dtls_derive_finished_secret(peer, key_side, hmac_key);

  if (res < 0)
    return res;

  copy_hs_hash(peer, &hs_ctx.hash);
  dtls_hash_finalize(buf, &hs_ctx.hash);

  dtls_hmac_init(&hs_ctx.hmac, hmac_key, sizeof(hmac_key));
  dtls_hmac_update(&hs_ctx.hmac, buf, sizeof(buf));
  dtls_hmac_finalize(&hs_ctx.hmac, buf);

  dtls_debug_dump("finished key", hmac_key, sizeof(hmac_key));
  dtls_debug_dump("finished MAC", buf, DTLS_FIN_LENGTH);

  res = dtls_send_handshake_msg(ctx, peer, DTLS_HT_FINISHED, buf, sizeof(buf));
  if (res < 0)
    return res;

  return res;
}

static int
dtls_send_client_hello(dtls_context_t *ctx, dtls_peer_t *peer,
                       uint8 cookie[], size_t cookie_length) {
  uint8 buf[DTLS_CH_LENGTH_MAX];
  uint8_t *p = buf;
  uint8 *p_size;
  uint16_t size = 0;
  uint8_t index = 0;
#ifdef DTLS_ECC
  uint8_t ecdsa = is_ecdsa_supported(ctx, 1);
#endif
  dtls_handshake_parameters_t *handshake = peer->handshake_params;

  handshake->user_parameters = default_user_parameters;
  if (ctx->h->get_user_parameters != NULL) {
    ctx->h->get_user_parameters(ctx, &peer->session, &(handshake->user_parameters));
  }

  /* legacy version DTLSv1.2 */
  dtls_int_to_uint16(p, DTLS12_VERSION);
  p += sizeof(uint16);

  // MF: note. the hello retry request might not contain a cookie.
  // We still have to use the same client random from client hello 1.
  if (!handshake->second_client_hello) {
    /* Set 32 bytes of client random data */
    dtls_prng(handshake->tmp.random.client, DTLS_RANDOM_LENGTH);
  }

  /* we must use the same Client Random as for the previous request */
  memcpy(p, handshake->tmp.random.client, DTLS_RANDOM_LENGTH);
  p += DTLS_RANDOM_LENGTH;

  /* session id (length 0) */
  dtls_int_to_uint8(p, 0);
  p += sizeof(uint8);

  /* legacy cookie */
  dtls_int_to_uint8(p, 0);
  p += sizeof(uint8);

  /* keep pointer to size of cipher suites */
  p_size = p;
  /* skip size of cipher suites field */
  p += sizeof(uint16);

  /* add known cipher(s) */
  for (index = 0; handshake->user_parameters.cipher_suites[index] != TLS_NULL_WITH_NULL_NULL; ++index) {
    dtls_cipher_t code = handshake->user_parameters.cipher_suites[index];
    if (known_cipher_suite(code)) {
      dtls_int_to_uint16(p, code);
      p += sizeof(uint16);
    }
    /* ignore not supported cipher suite
       credentials callback is missing */
  }

  size = (p - p_size) - sizeof(uint16);
  if (size == 0) {
    dtls_crit("no supported cipher suite provided!\n");
    return dtls_alert_fatal_create(DTLS_ALERT_HANDSHAKE_FAILURE);
  }

  /* set size of known cipher suites */
  dtls_int_to_uint16(p_size, size);

  /* compression method */
  dtls_int_to_uint8(p, 1);
  p += sizeof(uint8);

  dtls_int_to_uint8(p, TLS_COMPRESSION_NULL);
  p += sizeof(uint8);

  /* keep pointer to length of the extensions */
  p_size = p;
  /* skip length of extensions field */
  p += sizeof(uint16);

  /* supported versions extension */
  p += create_ext_supported_versions(p, peer->role);

  if (cookie_length != 0) {
    /* cookie extension */
    p += create_ext_cookie(p, cookie, cookie_length);
  }

#ifdef DTLS_ECC
  if (ecdsa) {
    /* key share extension */
    if (cookie_length == 0) {
      p += create_ext_key_share_empty(p);
    } else {
      p += create_ext_key_share_generate_key(p, peer->role, peer->handshake_params);
    }

    /* client certificate type extension */
    p += create_ext_client_certificate_type(p, peer->role);

    /* server certificate type extension */
    p += create_ext_server_certificate_type(p, peer->role);

    /* supportedgroups extension */
    p += create_ext_supported_groups(p);

    /* signature algorithms extension */
    p += create_ext_signature_algorithms(p);
  }
#endif /* DTLS_ECC */

#if (DTLS_MAX_CID_LENGTH > 0)
  if (handshake->user_parameters.support_cid) {
    /* connection id, empty to indicate support */
    p += create_ext_connection_id(p);
  }
#endif /* DTLS_MAX_CID_LENGTH > 0 */

  /* length of the extensions */
  size = (p - p_size) - sizeof(uint16);
  /* set size of extensions */
  dtls_int_to_uint16(p_size, size);

  handshake->hs_state.read_epoch = dtls_security_params(peer)->epoch;
  assert((buf <= p) && ((unsigned int)(p - buf) <= sizeof(buf)));

  if (!handshake->second_client_hello)
    clear_hs_hash(peer);

  return dtls_send_handshake_msg_hash(ctx, peer, &peer->session,
				      DTLS_HT_CLIENT_HELLO,
				      buf, p - buf, 1);
}

static int
check_server_hello(dtls_context_t *ctx,
		      dtls_peer_t *peer,
		      uint8 *data, size_t data_length,
          uint16_t *type)
{
  int err;
  dtls_extension_info_t ext_info;
  dtls_handshake_parameters_t *handshake = peer->handshake_params;
  /* keep original data and length in case the server_hello is actually
   * a hello_retry_request an we have to create a message_hash message */
  uint8 *const hs_header = data;
  const size_t hs_length = data_length;

  /*
   * Check we have enough data for the ServerHello
   *   2 bytes for the version number
   *   1 byte for the session id length
   *   2 bytes for the selected cipher suite
   *   1 byte null compression
   *   2 bytes for the extension length
   */
  if (data_length < DTLS_HS_LENGTH + 2 + DTLS_RANDOM_LENGTH + 1 + 2 + 1 + 2) {
    dtls_alert("Insufficient length for ServerHello\n");
    return dtls_alert_fatal_create(DTLS_ALERT_DECODE_ERROR);
  }

  // update_hs_hash(peer, data, data_length);

  /* Get the server's random data and store selected cipher suite
   * and compression method (like dtls_update_parameters().
   * Then calculate master secret and wait for ServerHelloDone. When received,
   * send ClientKeyExchange (?) and ChangeCipherSpec + ClientFinished. */

  /* check server legacy version. Must be version of DTLS 1.2 */
  data += DTLS_HS_LENGTH;
  data_length -= DTLS_HS_LENGTH;

  if (dtls_uint16_to_int(data) != DTLS12_VERSION) {
    dtls_alert("unknown DTLS version\n");
    return dtls_alert_fatal_create(DTLS_ALERT_PROTOCOL_VERSION);
  }

  data += sizeof(uint16);	      /* skip version field */
  data_length -= sizeof(uint16);

  /* check if the server hello is a hello retry request */
  if (0 == memcmp(data, hello_retry_magic, DTLS_RANDOM_LENGTH)) {
    *type = DTLS_HT_HELLO_RETRY_REQUEST;
  } else {
    *type = DTLS_HT_SERVER_HELLO;
    /* store server random data */
    // MF: TODO ist the server random even necessary?
    memcpy(handshake->tmp.random.server, data, DTLS_RANDOM_LENGTH);
  }

  /* skip server random */
  data += DTLS_RANDOM_LENGTH;
  data_length -= DTLS_RANDOM_LENGTH;

  SKIP_VAR_FIELD(data, data_length, uint8); /* skip session id */
  /*
   * Need to re-check in case session id was not empty
   *   2 bytes for the selected cipher suite
   *   1 byte null compression
   */
  if (data_length < 2 + 1) {
    dtls_alert("Insufficient length for ServerHello\n");
    return dtls_alert_fatal_create(DTLS_ALERT_DECODE_ERROR);
  }

  /* Check if the cipher suite selected by the server
   *  is in our list of cipher suites. */
  // MF: determine key exchange algorithm from extensions
  handshake->cipher_index = get_cipher_index(&handshake->user_parameters, dtls_uint16_to_int(data), DTLS_KEY_EXCHANGE_ECDHE_ECDSA);

  // MF: when server_hello, check if cipher is the same as in retry request ?

  if (!known_cipher_index(ctx, handshake->cipher_index, 1)) {
    dtls_alert("unsupported cipher 0x%02x 0x%02x\n", data[0], data[1]);
    handshake->cipher_index = DTLS_CIPHER_INDEX_NULL;
    return dtls_alert_fatal_create(DTLS_ALERT_INSUFFICIENT_SECURITY);
  }

  data += sizeof(uint16);
  data_length -= sizeof(uint16);

  /* Check if NULL compression was selected. We do not know any other. */
  if (dtls_uint8_to_int(data) != TLS_COMPRESSION_NULL) {
    dtls_alert("unsupported compression method 0x%02x\n", data[0]);
    return dtls_alert_fatal_create(DTLS_ALERT_INSUFFICIENT_SECURITY);
  }
  data += sizeof(uint8);
  data_length -= sizeof(uint8);

  /* Server may not support extended master secret */
  handshake->extended_master_secret = 0;

  err = dtls_check_supported_versions(data, data_length, *type);
  if (err < 0)
    return err;

  // return dtls_check_tls_extension(peer, data, data_length, 0);
  err = dtls_parse_tls_extension(peer, data, data_length, *type, &ext_info);

  if (err < 0) {
    dtls_warn("error in dtls_parse_tls_extension err: %i\n", err);
    return err;
  }

  if (*type == DTLS_HT_HELLO_RETRY_REQUEST) {
    
    /* RFC 8446 4.1.4 "If a client receives a second HelloRetryRequest
     * in the same connection it MUST abort the handshake with an
     * unexpected_message alert"
     */
    if (handshake->second_client_hello)
      return dtls_alert_fatal_create(DTLS_ALERT_UNEXPECTED_MESSAGE);

    handshake->second_client_hello = 1;

    // MF: TODO (RFC 9147 5.1) Continue without cookie?
    // if (!ext_info.ext_cookie)
    //   return dtls_alert_fatal_create(DTLS_ALERT_MISSING_EXTENSION);

    /* RFC 8446 4.1.4 "Clients MUST abort the handshake with an illegal_parameter
     * alert if the HelloRetryRequest would not result in any change in the ClientHello."
     * Since we have sent an empty key_share, the hello_retry_request must contain
     * a key_share with group secp256r1. (If we had send a non empty key_share, there
     * must not be a key_share since we only support one group.)
     */
    if (!ext_info.ext_key_share)
      return dtls_alert_fatal_create(DTLS_ALERT_ILLEGAL_PARAMETER);

    hash_message_hash(peer, NULL);
    hash_handshake(peer, hs_header, hs_length);

    err = dtls_send_client_hello(ctx, peer, ext_info.cookie, ext_info.cookie_length);

    if (err < 0) {
      dtls_warn("cannot send ClientHello\n");
      return err;
    }
  } else {
    /* server_hello */
    if (!ext_info.ext_key_share) {
      return dtls_alert_fatal_create(DTLS_ALERT_MISSING_EXTENSION);
    }
    hash_handshake(peer, hs_header, hs_length);
    store_ecdhe_pub_key(peer, ext_info.pub_key);

    err = calculate_key_block(peer, HANDSHAKE_KEY);
    if (err < 0)
      return err;

    /* switch cipher suite. We are now in epoch DTLS_EPOCH_HANDSHAKE (2) */
    dtls_security_params_switch(peer);
    handshake->hs_state.read_epoch = dtls_security_params(peer)->epoch;
  }
  return 0;

error:
  return dtls_alert_fatal_create(DTLS_ALERT_DECODE_ERROR);
}

static int
check_encrypted_extensions(dtls_context_t *ctx,
                           dtls_peer_t *peer,
                           uint8 *data, size_t data_length)
{
  (void)ctx;
  int err;
  dtls_extension_info_t ext_info;
  hash_handshake(peer, data, data_length);

  data += DTLS_HS_LENGTH;
  data_length -= DTLS_HS_LENGTH;

  err = dtls_parse_tls_extension(peer, data, data_length, DTLS_HT_ENCRYPTED_EXTENSIONS, &ext_info);
  if (err < 0)
    return err;

  if (!ext_info.ext_client_cert_type || !ext_info.ext_server_cert_type) {
    dtls_warn("certificate type extensions missing in encrypted extensions\n");
    return dtls_alert_fatal_create(DTLS_ALERT_HANDSHAKE_FAILURE);
  }
  return 0;
}

#ifdef DTLS_ECC
static int
check_server_certificate(dtls_context_t *ctx,
			 dtls_peer_t *peer,
			 uint8 *data, size_t data_length,
       uint8 *no_cert)
{
  int err;
  uint32_t cert_length;
  dtls_handshake_parameters_t *config = peer->handshake_params;

  hash_handshake(peer, data, data_length);

  assert(is_key_exchange_ecdhe_ecdsa(config->cipher_index));

  data += DTLS_HS_LENGTH;

  // MF: why no check for data_length ?

  // MF: add context in post-handshake authentication
  if (dtls_uint8_to_int(data) != 0) {
    return dtls_alert_fatal_create(DTLS_ALERT_DECODE_ERROR);
  }
  data += sizeof(uint8);

  cert_length = dtls_uint24_to_int(data);
  data += sizeof(uint24);

  if (cert_length == 0 && peer->role == DTLS_SERVER) {
    dtls_info("empty client certificate received\n");
    *no_cert = 1;
    return 0;
  }

  *no_cert = 0;

  if (cert_length != 3 + DTLS_EC_SUBJECTPUBLICKEY_SIZE + 2) {
    dtls_alert("expect length of %zu bytes for certificate entry\n",
	       3 + DTLS_EC_SUBJECTPUBLICKEY_SIZE + 2);
    return dtls_alert_fatal_create(DTLS_ALERT_DECODE_ERROR);
  }

  if (dtls_uint24_to_int(data) != DTLS_EC_SUBJECTPUBLICKEY_SIZE) {
    dtls_alert("expect length of %zu bytes for certificate\n",
	       DTLS_EC_SUBJECTPUBLICKEY_SIZE);
    return dtls_alert_fatal_create(DTLS_ALERT_DECODE_ERROR);
  }
  data += sizeof(uint24);

  if (memcmp(data, cert_asn1_header, sizeof(cert_asn1_header))) {
    dtls_alert("got an unexpected Subject public key format\n");
    return dtls_alert_fatal_create(DTLS_ALERT_DECODE_ERROR);
  }
  data += sizeof(cert_asn1_header);

  memcpy(config->keyx.ecdsa.other_pub_x, data,
	 sizeof(config->keyx.ecdsa.other_pub_x));
  data += sizeof(config->keyx.ecdsa.other_pub_x);

  memcpy(config->keyx.ecdsa.other_pub_y, data,
	 sizeof(config->keyx.ecdsa.other_pub_y));
  data += sizeof(config->keyx.ecdsa.other_pub_y);

  err = CALL(ctx, verify_ecdsa_key, &peer->session,
	     config->keyx.ecdsa.other_pub_x,
	     config->keyx.ecdsa.other_pub_y,
	     sizeof(config->keyx.ecdsa.other_pub_x));
  if (err < 0) {
    dtls_warn("The certificate was not accepted\n");
    return err;
  }

  /* ignore extensions */

  return 0;
}
#endif /* DTLS_ECC */

#ifdef DTLS_ECC
static int
check_certificate_request(dtls_context_t *ctx,
			  dtls_peer_t *peer,
			  uint8 *data, size_t data_length)
{
  dtls_extension_info_t ext_info;
  (void)ctx;

  hash_handshake(peer, data, data_length);

  assert(is_key_exchange_ecdhe_ecdsa(peer->handshake_params->cipher_index));

  data += DTLS_HS_LENGTH;

  if (data_length < DTLS_HS_LENGTH + 1) {
    dtls_alert("the packet length does not match the expected\n");
    return dtls_alert_fatal_create(DTLS_ALERT_DECODE_ERROR);
  }

  data_length -= DTLS_HS_LENGTH + 1;

  // MF: add context in post-handshake authentication
  if (dtls_uint8_to_int(data) != 0) {
    return dtls_alert_fatal_create(DTLS_ALERT_HANDSHAKE_FAILURE);
  }
  data += sizeof(uint8);

  int err = dtls_parse_tls_extension(peer, data, data_length,
      DTLS_HT_CERTIFICATE_REQUEST, &ext_info);

  if (err < 0)
    return err;

  if (!ext_info.ext_sig_algo) {
    dtls_alert("missing signature algorithms extension\n");
    return dtls_alert_fatal_create(DTLS_ALERT_HANDSHAKE_FAILURE);
  }

  peer->handshake_params->do_client_auth = 1;
  return 0;
}
#endif /* DTLS_ECC */

static int
decrypt_verify(dtls_peer_t *peer, dtls_record_number_t *rn,
               uint8 *packet, size_t length,
               int header_length, uint8 **cleartext)
{
  dtls_security_parameters_t *security = dtls_security_params_read_epoch(peer, rn->epoch);
  int clen;

  *cleartext = (uint8 *)packet + header_length;
  clen = length - header_length;

  if (!security) {
    dtls_alert("No security context for epoch: %" PRIu64 "\n", rn->epoch);
    return -1;
  }

  if (security->cipher_index == DTLS_CIPHER_INDEX_NULL) {
    /* no cipher suite selected */
    return clen;
  } else {

    unsigned char nonce[DTLS_CCM_BLOCKSIZE];
    const uint8_t mac_len = get_cipher_suite_mac_len(security->cipher_index);
    /* For backwards-compatibility, dtls_encrypt_params is called with
     * M=<macLen> and L=3. */
    const dtls_ccm_params_t params = { nonce, mac_len, 3 };

    /* nonce is iv xored with seq num padded to the left with zeros to iv length */
    memset(nonce, 0, DTLS_CCM_BLOCKSIZE);
    dtls_int_to_uint64(nonce + DTLS_IV_LENGTH - sizeof(uint64_t), rn->seq_nr);
    memxor(nonce, dtls_kb_remote_iv(security, peer->role), dtls_kb_iv_size(security, peer->role));

    dtls_debug_dump("nonce:", nonce, DTLS_CCM_BLOCKSIZE);
    dtls_debug_dump("key:", dtls_kb_remote_write_key(security, peer->role), dtls_kb_key_size(security, peer->role));

    /* additional data is the record header */
    clen = dtls_decrypt_params(&params, *cleartext, clen, *cleartext,
              dtls_kb_remote_write_key(security, peer->role),
              dtls_kb_key_size(security, peer->role),
              packet, header_length);
  
    if (clen < 0)
      dtls_warn("decryption failed\n");
    else {
      /* remove zero padding from end of cleartext */
      int i = 0;
      for (; i < clen; i++) {
        if ((*cleartext)[clen - i - 1] != 0)
          break;
      }
      clen -= i;
      dtls_debug("decrypt_verify(): found %i bytes cleartext\n", clen);
      // MF: ACKs are send using the highest current sending epoch. That means
      // if we receive a record during the handshake with the current read_epoch,
      // the record no longer acknowledges prior messages, because it could
      // be an ACK. Only a message of type Handshake is implicitly acknowledging
      // the privious flights.
      // dtls_security_params_free_other(peer);
      dtls_debug_dump("cleartext", *cleartext, clen);
    }
  }

  return clen;
}

/**
 * Process verified ClientHellos.
 *
 * For a verified ClientHello a peer is available/created. This function
 * returns the number of bytes that were sent, or \c -1 if an error occurred.
 *
 * \param ctx          The DTLS context to use.
 * \param peer         The remote peer to exchange the handshake messages.
 * \param data         The data of the ClientHello containing the proposed crypto parameter.
 * \param data_length  The actual length of \p data.
 * \param cookie       The cookie from the ClientHello.
 * \return Less than zero on error, the number of bytes written otherwise.
 */
static int
handle_verified_client_hello(dtls_context_t *ctx, dtls_peer_t *peer,
		uint8 *data, size_t data_length, dtls_cookie_t *cookie) {

  clear_hs_hash(peer);

  /* First negotiation step: check for PSK
   *
   * Note that we already have checked that msg is a Handshake
   * message containing a ClientHello. dtls_get_cipher() therefore
   * does not check again.
   */
  int err = dtls_update_parameters(ctx, peer, data, data_length, cookie);
  if (err < 0) {
    dtls_warn("error updating security parameters\n");
    return err;
  }

  /* create message_hash message from hash of first client hello */
  hash_message_hash(peer, cookie->hash);
  /* reconstruct hash of hello retry request message from cookie */
  hash_hello_retry_request(peer, cookie);
  /* hash the second client hello */
  hash_handshake(peer, data, data_length);

  err = dtls_send_server_hello_msgs(ctx, peer);
  if (err < 0) {
    return err;
  }
  if (is_key_exchange_ecdhe_ecdsa(peer->handshake_params->cipher_index) &&
		  is_ecdsa_client_auth_supported(ctx))
    peer->state = DTLS_STATE_WAIT_CLIENTCERTIFICATE;
  else
    peer->state = DTLS_STATE_WAIT_CLIENTKEYEXCHANGE;

  return err;
}

static int
handle_handshake_msg(dtls_context_t *ctx, dtls_peer_t *peer, uint8 *data, size_t data_length) {

  int err = 0;
  const dtls_peer_type role = peer->role;
  const dtls_state_t state = peer->state;
  const dtls_key_exchange_algorithm_t key_exchange_algorithm =
              get_key_exchange_algorithm(peer->handshake_params->cipher_index);

  union {
    uint16_t type;
    uint8_t no_cert;
  } out;

  /* This will clear the retransmission buffer if we get an expected
   * handshake message. We have to make sure that no handshake message
   * should get expected when we still should retransmit something, when
   * we do everything accordingly to the DTLS 1.2 standard this should
   * not be a problem. */
  dtls_stop_retransmission(ctx, peer);

  // MF: moved here from decrypt_verify
  dtls_security_params_free_other(peer);

  /* The following switch construct handles the given message with
   * respect to the current internal state for this peer. In case of
   * error, it is left with return 0. */

  dtls_debug("handle handshake packet of type: %s (%i)\n",
	     dtls_handshake_type_to_name(data[0]), data[0]);
  switch (data[0]) {

  /************************************************************************
   * Client states
   ************************************************************************/
  case DTLS_HT_HELLO_VERIFY_REQUEST:
    return dtls_alert_fatal_create(DTLS_ALERT_UNEXPECTED_MESSAGE);
/*
    if (state != DTLS_STATE_CLIENTHELLO) {
      return dtls_alert_fatal_create(DTLS_ALERT_UNEXPECTED_MESSAGE);
    }

    err = check_server_hello_verify_request(ctx, peer, data, data_length);
    if (err < 0) {
      dtls_warn("error in check_server_hello_verify_request err: %i\n", err);
      return err;
    }
*/

    break;
  case DTLS_HT_SERVER_HELLO:

    if (state != DTLS_STATE_CLIENTHELLO) {
      return dtls_alert_fatal_create(DTLS_ALERT_UNEXPECTED_MESSAGE);
    }

    /* server hello could also be a hello retry request */
    err = check_server_hello(ctx, peer, data, data_length, &out.type);
    if (err < 0) {
      dtls_warn("error in check_server_hello err: %i\n", err);
      return err;
    }
#if 0
    /* check_server_hello sets the cipher_index */
    if (is_key_exchange_ecdhe_ecdsa(peer->handshake_params->cipher_index))
      peer->state = DTLS_STATE_WAIT_SERVERCERTIFICATE;
    else {
      peer->optional_handshake_message = DTLS_HT_SERVER_KEY_EXCHANGE;
      peer->state = DTLS_STATE_WAIT_SERVERHELLODONE;
    }
#endif
    if (out.type == DTLS_HT_SERVER_HELLO) {
      peer->state = DTLS_STATE_WAIT_ENCRYPTED_EXTENSIONS;
    }
    /* update_hs_hash(peer, data, data_length); */

    break;

  case DTLS_HT_ENCRYPTED_EXTENSIONS:

    if (state != DTLS_STATE_WAIT_ENCRYPTED_EXTENSIONS) {
      return dtls_alert_fatal_create(DTLS_ALERT_UNEXPECTED_MESSAGE);
    }

    err = check_encrypted_extensions(ctx, peer, data, data_length);
    if (err < 0) {
      dtls_warn("error in check_encrypted_extensions err: %i\n", err);
      return err;
    }
    // MF: note. only in DTLS_KEY_EXCHANGE_ECDHE_ECDSA
    peer->state = DTLS_STATE_WAIT_SERVERCERTIFICATE;
    peer->optional_handshake_message = DTLS_HT_CERTIFICATE_REQUEST;

    break;

#ifdef DTLS_ECC
  case DTLS_HT_CERTIFICATE:

    if ((role == DTLS_CLIENT && state != DTLS_STATE_WAIT_SERVERCERTIFICATE) ||
        (role == DTLS_SERVER && state != DTLS_STATE_WAIT_CLIENTCERTIFICATE)) {
      return dtls_alert_fatal_create(DTLS_ALERT_UNEXPECTED_MESSAGE);
    }

    if (role == DTLS_SERVER) {
      err = calculate_key_block(peer, TRAFFIC_KEY);
      if (err < 0) {
        dtls_warn("error in calculate_key_block err: %i\n", err);
        return err;
      }
    }

    // MF: why is this called "server" certificate?
    err = check_server_certificate(ctx, peer, data, data_length, &out.no_cert);
    if (err < 0) {
      dtls_warn("error in check_server_certificate err: %i\n", err);
      return err;
    }
    if (role == DTLS_CLIENT) {
      peer->state = DTLS_STATE_WAIT_CERTIFICATEVERIFY;
    } else { /* server */
      // MF: TODO what to do if client sends no certificate? continue or abort?
      // see also https://github.com/eclipse/tinydtls/issues/186
      if (out.no_cert) {
        peer->state = DTLS_STATE_WAIT_FINISHED;
      } else {
        peer->state = DTLS_STATE_WAIT_CERTIFICATEVERIFY;
      }
    }
    /* update_hs_hash(peer, data, data_length); */

    break;
#endif /* DTLS_ECC */

  case DTLS_HT_SERVER_KEY_EXCHANGE:
    return dtls_alert_fatal_create(DTLS_ALERT_UNEXPECTED_MESSAGE);
    break;

  case DTLS_HT_SERVER_HELLO_DONE:
    return dtls_alert_fatal_create(DTLS_ALERT_UNEXPECTED_MESSAGE);
    break;

#ifdef DTLS_ECC
  case DTLS_HT_CERTIFICATE_REQUEST:

    if (state != DTLS_STATE_WAIT_SERVERCERTIFICATE ||
        peer->optional_handshake_message != DTLS_HT_CERTIFICATE_REQUEST ||
        key_exchange_algorithm != DTLS_KEY_EXCHANGE_ECDHE_ECDSA) {
      return dtls_alert_fatal_create(DTLS_ALERT_UNEXPECTED_MESSAGE);
    }
    peer->optional_handshake_message = DTLS_HT_NO_OPTIONAL_MESSAGE;
    err = check_certificate_request(ctx, peer, data, data_length);
    if (err < 0) {
      dtls_warn("error in check_certificate_request err: %i\n", err);
      return err;
    }

    break;
#endif /* DTLS_ECC */

  case DTLS_HT_FINISHED:
    /* expect a Finished message from server */

    if (state != DTLS_STATE_WAIT_FINISHED) {
      return dtls_alert_fatal_create(DTLS_ALERT_UNEXPECTED_MESSAGE);
    }

    err = check_finished(ctx, peer, data, data_length);
    if (err < 0) {
      dtls_warn("error in check_finished err: %i\n", err);
      return err;
    }

    if (role == DTLS_SERVER) {
      dtls_handshake_free(peer->handshake_params);
      peer->handshake_params = NULL;
      dtls_debug("Handshake complete\n");
      check_stack();
      peer->state = DTLS_STATE_CONNECTED;
    } else {
      /* Client */
      peer->state = DTLS_STATE_WAIT_FINISHED_ACK;
    }

    /* return here to not increase the message receive counter */
    return err;

  /************************************************************************
   * Server states
   ************************************************************************/

  case DTLS_HT_CLIENT_KEY_EXCHANGE:
    return dtls_alert_fatal_create(DTLS_ALERT_UNEXPECTED_MESSAGE);
    break;

#ifdef DTLS_ECC
  case DTLS_HT_CERTIFICATE_VERIFY:

    if (state != DTLS_STATE_WAIT_CERTIFICATEVERIFY) {
      return dtls_alert_fatal_create(DTLS_ALERT_UNEXPECTED_MESSAGE);
    }

    // MF: TODO rename to check_certificate_verify
    err = check_client_certificate_verify(ctx, peer, data, data_length);
    if (err < 0) {
      dtls_warn("error in check_client_certificate_verify err: %i\n", err);
      return err;
    }

    hash_handshake(peer, data, data_length);
    peer->state = DTLS_STATE_WAIT_FINISHED;
    break;
#endif /* DTLS_ECC */

  case DTLS_HT_CLIENT_HELLO:

   /*
    * RFC 8446 4.1.2
    * Because TLS 1.3 forbids renegotiation, if a server has negotiated
    * TLS 1.3 and receives a ClientHello at any other time, it MUST
    * terminate the connection with an "unexpected_message" alert.
    */
    return dtls_alert_fatal_create(DTLS_ALERT_UNEXPECTED_MESSAGE);

#if 0
    if (state != DTLS_STATE_CONNECTED) {
      return dtls_alert_fatal_create(DTLS_ALERT_UNEXPECTED_MESSAGE);
    }

    /* At this point, we have a good relationship with this peer. This
     * state is left for re-negotiation of key material. */
     /* As per RFC 6347 - section 4.2.8 if this is an attempt to
      * rehandshake, we can delete the existing key material
      * as the client has demonstrated reachibility by completing
      * the cookie exchange */
    if (!peer->handshake_params) {
      dtls_handshake_header_t *hs_header = DTLS_HANDSHAKE_HEADER(data);

      peer->handshake_params = dtls_handshake_new();
      if (!peer->handshake_params)
        return dtls_alert_fatal_create(DTLS_ALERT_INTERNAL_ERROR);

      peer->handshake_params->hs_state.mseq_r = dtls_uint16_to_int(hs_header->message_seq);
      peer->handshake_params->hs_state.mseq_s = 1;
      peer->handshake_params->hs_state.read_epoch = dtls_security_params(peer)->epoch;
    }
    err = handle_verified_client_hello(ctx, peer, data, data_length);

    /* after sending the ServerHelloDone, we expect the
     * ClientKeyExchange (possibly containing the PSK id),
     * followed by a ChangeCipherSpec and an encrypted Finished.
     */

    break;
#endif

  case DTLS_HT_HELLO_REQUEST:

    if (state != DTLS_STATE_CONNECTED) {
      /* we should just ignore such packets when in handshake */
      return 0;
    }

    dtls_warn("renegotiation is not supported!\n");
    /* RFC5246, 7.2.2. Error Alerts, "no_renegotiation" is always a warning */
    return dtls_alert_create(DTLS_ALERT_LEVEL_WARNING, DTLS_ALERT_NO_RENEGOTIATION);

  default:
    dtls_crit("unhandled message %d\n", data[0]);
    return dtls_alert_fatal_create(DTLS_ALERT_UNEXPECTED_MESSAGE);
  }

  if (peer->handshake_params && err >= 0) {
    peer->handshake_params->hs_state.mseq_r++;
  }

  return err;
}

/**
 * Process verified ClientHellos of epoch 0.
 *
 * This function returns the number of bytes that were sent, or less than zero
 * if an error occurred.
 *
 * \param ctx              The DTLS context to use.
 * \param ephemeral_peer   The ephemeral remote peer.
 * \param data             The data received.
 * \param data_length      The actual length of \p buf.
 * \param cookie           The cookie from the ClientHello.
 * \return Less than zero on error, the number of bytes written otherwise.
 */
static int
handle_0_verified_client_hello(dtls_context_t *ctx,
         dtls_ephemeral_peer_t *ephemeral_peer,
         uint8 *data, size_t data_length,
         dtls_cookie_t *cookie) {
  int err;

  dtls_peer_t *peer = dtls_get_peer(ctx, ephemeral_peer->session);
  if (peer) {
     dtls_debug("removing the peer, new handshake\n");
     dtls_destroy_peer(ctx, peer, 0);
     peer = NULL;
  }
  dtls_debug("creating new peer\n");

  /* msg contains a ClientHello with a valid cookie, so we can
   * safely create the server state machine and continue with
   * the handshake. */
  peer = dtls_new_peer(ephemeral_peer->session);
  if (!peer) {
    dtls_alert("cannot create peer\n");
    return dtls_alert_fatal_create(DTLS_ALERT_INTERNAL_ERROR);
  }
  peer->role = DTLS_SERVER;

  dtls_security_parameters_t *security = dtls_security_params(peer);
  security->rseq = ephemeral_peer->rseq;
  security->cseq.cseq = ephemeral_peer->rseq;
  /* bitfield. B0 last seq seen.  B1 seq-1 seen, B2 seq-2 seen etc. */
  /* => set all, older "stateless records" will be duplicates. */
  security->cseq.bitfield = (uint64_t) -1L;

  if (dtls_add_peer(ctx, peer) < 0) {
    dtls_alert("cannot add peer\n");
    dtls_free_peer(peer);
    return dtls_alert_fatal_create(DTLS_ALERT_INTERNAL_ERROR);
  }

  peer->handshake_params = dtls_handshake_new();
  if (!peer->handshake_params) {
    dtls_alert("cannot create handshake parameter\n");
    DEL_PEER(ctx->peers, peer);
    dtls_free_peer(peer);
    return dtls_alert_fatal_create(DTLS_ALERT_INTERNAL_ERROR);
  }

  peer->handshake_params->hs_state.read_epoch = dtls_security_params(peer)->epoch;
  peer->handshake_params->hs_state.mseq_r = ephemeral_peer->mseq;
  peer->handshake_params->hs_state.mseq_s = ephemeral_peer->mseq;

  err = handle_verified_client_hello(ctx, peer, data, data_length, cookie);
  if (err < 0) {
    dtls_destroy_peer(ctx, peer, DTLS_DESTROY_CLOSE);
    return err;
  }

  peer->handshake_params->hs_state.mseq_r++;

  return err;
}

/**
 * Process initial ClientHello of epoch 0.
 *
 * In order to protect against "denial of service" attacks, RFC6347
 * contains in https://datatracker.ietf.org/doc/html/rfc6347#section-4.2.1
 * the advice to process initial a ClientHello in a stateless fashion.
 * If a ClientHello doesn't provide a matching cookie, a HelloVerifyRequest
 * is sent back based on the record and handshake message sequence numbers
 * contained in the \p ephemeral_peer. If a matching cookie is provided,
 * the server starts the handshake, also based on the record and handshake
 * message sequence numbers contained in the \p ephemeral_peer. This function
 * returns the number of bytes that were sent, or \c -1 if an error occurred.
 *
 * \param ctx              The DTLS context to use.
 * \param ephemeral_peer   The ephemeral remote peer.
 * \param data             The data to send.
 * \param data_length      The actual length of \p buf.
 * \return Less than zero on error, the number of bytes written otherwise.
 */
static int
handle_0_client_hello(dtls_context_t *ctx, dtls_ephemeral_peer_t *ephemeral_peer,
         uint8 *data, size_t data_length)
{
  /* The cookie stores information that is necessary to reconstruct 
   * the hello retry request message and the transcript hash. */
  dtls_cookie_t *cookie = NULL;
  dtls_handshake_header_t *hs_header;
  size_t packet_length;
  size_t fragment_length;
  size_t fragment_offset;
  int err;

  hs_header = DTLS_HANDSHAKE_HEADER(data);

  dtls_debug("received initial client hello\n");

  packet_length = dtls_uint24_to_int(hs_header->length);
  fragment_length = dtls_uint24_to_int(hs_header->fragment_length);
  fragment_offset = dtls_uint24_to_int(hs_header->fragment_offset);
  if (packet_length != fragment_length || fragment_offset != 0) {
    dtls_warn("No fragment support (yet)\n");
    return 0;
  }
  if (fragment_length + DTLS_HS_LENGTH != data_length) {
    dtls_warn("Fragment size does not match packet size\n");
    return 0;
  }
  ephemeral_peer->mseq = dtls_uint16_to_int(hs_header->message_seq);
  err = dtls_0_verify_peer(ctx, ephemeral_peer, data, data_length, &cookie);
  if (err < 0) {
    dtls_warn("error in dtls_verify_peer err: %i\n", err);
    return err;
  }

  if (err > 0) {
    dtls_debug("server hello verify was sent\n");
    return err;
  }

  assert(cookie);

  err = handle_0_verified_client_hello(ctx, ephemeral_peer, data, data_length, cookie);
  if (err < 0) {
    dtls_0_send_alert_from_err(ctx, ephemeral_peer, err);
  }
  return err;
}

static int
handle_handshake(dtls_context_t *ctx, dtls_peer_t *peer, uint8 *data, size_t data_length)
{
  dtls_handshake_header_t *hs_header;
  int res;
  size_t packet_length;
  size_t fragment_length;
  size_t fragment_offset;

  assert(peer);

  if (data_length < DTLS_HS_LENGTH) {
    dtls_warn("handshake message too short\n");
    return dtls_alert_fatal_create(DTLS_ALERT_DECODE_ERROR);
  }
  hs_header = DTLS_HANDSHAKE_HEADER(data);

  dtls_debug("received handshake packet of type: %s (%i)\n",
             dtls_handshake_type_to_name(hs_header->msg_type),
             hs_header->msg_type);

  packet_length = dtls_uint24_to_int(hs_header->length);
  fragment_length = dtls_uint24_to_int(hs_header->fragment_length);
  fragment_offset = dtls_uint24_to_int(hs_header->fragment_offset);
  if (packet_length != fragment_length || fragment_offset != 0) {
    dtls_warn("No fragment support (yet)\n");
    return dtls_alert_fatal_create(DTLS_ALERT_HANDSHAKE_FAILURE);
  }
  if (fragment_length + DTLS_HS_LENGTH != data_length) {
    dtls_warn("Fragment size does not match packet size\n");
    return dtls_alert_fatal_create(DTLS_ALERT_HANDSHAKE_FAILURE);
  }

  if (!peer->handshake_params) {

    dtls_warn("ignore unexpected handshake message\n");
    return 0;
  }
  uint16_t mseq = dtls_uint16_to_int(hs_header->message_seq);
  if (mseq < peer->handshake_params->hs_state.mseq_r) {
    dtls_warn("The message sequence number is too small, expected %i, got: %i\n",
	      peer->handshake_params->hs_state.mseq_r, mseq);
    return 0;
  } else if (mseq > peer->handshake_params->hs_state.mseq_r) {
    /* A packet in between is missing, buffer this packet. */
    netq_t *n;

    dtls_info("The message sequence number is too larger, expected %i, got: %i\n",
	      peer->handshake_params->hs_state.mseq_r, mseq);

    /* TODO: only add packet that are not too new. */
    if (data_length > DTLS_MAX_BUF) {
      dtls_warn("the packet is too big to buffer for reoder\n");
      return 0;
    }

    netq_t *node = netq_head(&peer->handshake_params->reorder_queue);
    while (node) {
      dtls_handshake_header_t *node_header = DTLS_HANDSHAKE_HEADER(node->data);
      if (dtls_uint16_to_int(node_header->message_seq) == mseq) {
        dtls_warn("a packet with this sequence number is already stored\n");
        return 0;
      }
      node = netq_next(node);
    }

    n = netq_node_new(data_length);
    if (!n) {
      dtls_warn("no space in reorder buffer\n");
      return 0;
    }

    n->peer = peer;
    n->length = data_length;
    memcpy(n->data, data, data_length);

    if (!netq_insert_node(&peer->handshake_params->reorder_queue, n)) {
      dtls_warn("cannot add packet to reorder buffer\n");
      netq_node_free(n);
    }
    dtls_info("Added packet %u for reordering\n", mseq);
    return 0;
  } else if (mseq == peer->handshake_params->hs_state.mseq_r) {
    /* Found the expected packet, use this and all the buffered packet */
    int next = 1;

    res = handle_handshake_msg(ctx, peer, data, data_length);
    if (res < 0)
      return res;

    /* We do not know in which order the packet are in the list just search the list for every packet. */
    while (next && peer->handshake_params) {
      next = 0;
      netq_t *node = netq_head(&peer->handshake_params->reorder_queue);
      while (node) {
        dtls_handshake_header_t *node_header = DTLS_HANDSHAKE_HEADER(node->data);

        if (dtls_uint16_to_int(node_header->message_seq) == peer->handshake_params->hs_state.mseq_r) {
          netq_remove(&peer->handshake_params->reorder_queue, node);
          next = 1;
          res = handle_handshake_msg(ctx, peer, node->data, node->length);

          /* free message data */
          netq_node_free(node);

          if (res < 0) {
            return res;
          }

          break;
        } else {
          node = netq_next(node);
        }
      }
    }
    return res;
  }
  assert(0);
  return 0;
}

static int
handle_ack(dtls_context_t *ctx, dtls_peer_t *peer,
           uint8 *data, size_t data_length)
{
  (void)ctx;
  (void)peer;

  dtls_security_parameters_t *security;
  dtls_record_number_t rn;
  uint16_t len;

  if (data_length < 2)
    return dtls_alert_fatal_create(DTLS_ALERT_DECODE_ERROR);

  len = dtls_uint16_to_int(data);
  data += sizeof(uint16);
  data_length -= sizeof(uint16);

  if (data_length < len)
    return dtls_alert_fatal_create(DTLS_ALERT_DECODE_ERROR);

  if ((len & 0xf) != 0) {
    dtls_debug("handle_ack: length must be a multiple of 16");
    return dtls_alert_fatal_create(DTLS_ALERT_DECODE_ERROR);
  }

  while (len) {
    rn.epoch = dtls_uint64_to_int(data);
    data += 8;
    rn.seq_nr = dtls_uint64_to_int(data);
    data += 8;
    len -= 16;

    if (peer->role == DTLS_CLIENT && peer->state == DTLS_STATE_WAIT_FINISHED_ACK && rn.epoch == HANDSHAKE_KEY) {
      assert(peer->handshake_params);
      security = dtls_security_params_epoch(peer, rn.epoch);

      // MF: ack acknowledges last record (the finished message)
      if (security && rn.seq_nr == security->rseq - 1) {
        dtls_security_params_free_other(peer);
        dtls_handshake_free(peer->handshake_params);
        peer->handshake_params = NULL;
        dtls_debug("Handshake complete\n");
        check_stack();
        peer->state = DTLS_STATE_CONNECTED;
      }
    }

    // MF: TODO implement ACK (RFC 9147 7.)
  }
  
  return 0;
}

/**
 * Handles incoming Alert messages. This function returns \c 1 if the
 * connection should be closed and the peer is to be invalidated.
 * \c 0 if the Alert is valid, but not closing the connection.
 * Less than \c 0 if the Alert could not be decoded.
 */
static int
handle_alert(dtls_context_t *ctx, dtls_peer_t *peer,
	     uint8 *record_header, uint8 *data, size_t data_length) {
  int free_peer = 0;		/* indicates whether to free peer */
  int close_notify = 0;
  (void)record_header;

  assert(peer);

  if (data_length < 2)
    return dtls_alert_fatal_create(DTLS_ALERT_DECODE_ERROR);

  dtls_info("** Alert: level %d, description %d\n", data[0], data[1]);

  /* The peer object is invalidated for FATAL alerts and close
   * notifies. This is done in two steps.: First, remove the object
   * from our list of peers. After that, the event handler callback is
   * invoked with the still existing peer object. Finally, the storage
   * used by peer is released.
   */
  close_notify = data[1] == DTLS_ALERT_CLOSE_NOTIFY;
  if (data[0] == DTLS_ALERT_LEVEL_FATAL || close_notify) {
    if (close_notify)
      dtls_info("invalidate peer (Close Notify)\n");
    else
      dtls_alert("%d invalidate peer\n", data[1]);

    DEL_PEER(ctx->peers, peer);

#ifdef WITH_CONTIKI
#ifndef NDEBUG
    PRINTF("removed peer [");
    PRINT6ADDR(&peer->session.addr);
    PRINTF("]:%d\n", uip_ntohs(peer->session.port));
#endif
#endif /* WITH_CONTIKI */

    free_peer = 1;

  }

  (void)CALL(ctx, event, &peer->session,
	     (dtls_alert_level_t)data[0], (unsigned short)data[1]);
  if (close_notify) {
    /* If state is DTLS_STATE_CLOSING, we have already sent a
     * close_notify so, do not send that again. */
    if (peer->state != DTLS_STATE_CLOSING) {
      peer->state = DTLS_STATE_CLOSING;
      dtls_send_alert(ctx, peer, DTLS_ALERT_LEVEL_WARNING,
                      DTLS_ALERT_CLOSE_NOTIFY);
    } else
      peer->state = DTLS_STATE_CLOSED;
  }

  if (free_peer) {
    dtls_destroy_peer(ctx, peer, DTLS_DESTROY_CLOSE);
  }

  return free_peer;
}

static int dtls_alert_send_from_err(dtls_context_t *ctx, dtls_peer_t *peer, int err)
{
  assert(peer);

  if (dtls_is_alert(err)) {
    dtls_alert_level_t level = ((-err) & 0xff00) >> 8;
    dtls_alert_t desc = (-err) & 0xff;
    peer->state = DTLS_STATE_CLOSING;
    return dtls_send_alert(ctx, peer, level, desc);
  } else if (err == -1) {
    peer->state = DTLS_STATE_CLOSING;
    return dtls_send_alert(ctx, peer, DTLS_ALERT_LEVEL_FATAL, DTLS_ALERT_INTERNAL_ERROR);
  }
  return -1;
}

/**
 * Handles incoming data as DTLS message from given peer.
 */
int
dtls_handle_message(dtls_context_t *ctx,
		    session_t *session,
		    uint8 *msg, int msglen) {
  dtls_peer_t *peer = NULL;
  unsigned int rlen;		/* record length */
  uint8 *data = NULL;		/* (decrypted) payload */
  int data_length;		/* length of decrypted payload
				   (without MAC and padding) */
  dtls_record_type record_type;
  int err;

  /* check for ClientHellos of epoch 0, maybe a peer's start over */
  if (is_plaintext_record(msg,msglen)) {
    dtls_record_header_t *header = DTLS_RECORD_HEADER(msg);
    uint16_t epoch = dtls_get_epoch(header);
    uint8_t content_type = dtls_get_content_type(header);
    const char* content_type_name = dtls_message_type_to_name(content_type);
    rlen = DTLS_RH_LENGTH + dtls_get_length(header);
    if (content_type_name) {
      dtls_info("received message (%d bytes), starting with '%s', epoch %u\n", msglen, content_type_name, epoch);
    } else {
      dtls_info("received message (%d bytes), starting with unknown ct '%u', epoch %u\n", msglen, content_type, epoch);
    }
    if (DTLS_CT_HANDSHAKE == content_type && 0 == epoch) {
      dtls_info("handshake message epoch 0\n");
      data = msg + DTLS_RH_LENGTH;
      data_length = rlen - DTLS_RH_LENGTH;
      if ((size_t) data_length < DTLS_HS_LENGTH) {
        dtls_warn("ignore too short handshake message\n");
        return 0;
      }
      dtls_handshake_header_t *hs_header = DTLS_HANDSHAKE_HEADER(data);
      if (hs_header->msg_type == DTLS_HT_CLIENT_HELLO) {
        /*
         * Stateless processing of ClientHello in epoch 0.
         *
         * In order to protect against "denial of service" attacks, RFC6347
         * contains in https://datatracker.ietf.org/doc/html/rfc6347#section-4.2.1
         * the advice to process initial a ClientHello in a stateless fashion.
         * Therefore no peer is used, but a ephemeral peer with the required
         * record and handshake sequence numbers along with the ip-endoint.
         * If the ClientHello contains no matching cookie, the client will be
         * challenged using a HelloVerifyRequest. If a matching cookie is provided,
         * a peer is created and the handshake is continued using the state of the
         * peer.
         */
        dtls_info("client_hello epoch 0\n");
        dtls_ephemeral_peer_t ephemeral_peer = {session, dtls_uint48_to_int(header->sequence_number), 0};
        err = handle_0_client_hello(ctx, &ephemeral_peer, data, data_length);
        if (err < 0) {
          dtls_warn("error while handling handshake packet\n");
        }
        return 0;
      }
    }
  }

  while (is_record(msg, msglen, &record_type)) {
    dtls_record_number_t rn;
    dtls_security_parameters_t *security = NULL;
    uint8_t content_type = 0;
    int header_length = 0;

    /* check if we have DTLS state for addr/port/ifindex */
    peer = dtls_get_peer(ctx, session);
    if (peer) {
        dtls_debug("dtls_handle_message: FOUND PEER\n");
    } else {
      if (data) {
        dtls_info("Additional record after peer has been removed.\n");
      } else {
        dtls_debug("dtls_handle_message: PEER NOT FOUND\n");
        dtls_dsrv_log_addr(DTLS_LOG_DEBUG, "peer addr", session);
      }
      /** no peer => drop it */
      return 0;
    }

    if (record_type == DTLS_PLAINTEXT) {
      dtls_record_header_t *header = DTLS_RECORD_HEADER(msg);
      header_length = DTLS_RH_LENGTH;
      content_type = dtls_get_content_type(header);
      const char *content_type_name = dtls_message_type_to_name(content_type);
      rn.epoch = dtls_get_epoch(header);
      rn.seq_nr = dtls_get_sequence_number(header);
      rlen = DTLS_RH_LENGTH + dtls_get_length(header);

      if (content_type_name) {
        dtls_info("Plaintext: got '%s' epoch %" PRIu64 " sequence %" PRIu64 " (%d bytes)\n",
                  content_type_name, rn.epoch, rn.seq_nr, rlen);
      } else {
        dtls_info("Plaintext: got 'unknown %u' epoch %" PRIu64 " sequence %" PRIu64 " (%d bytes)\n",
                  content_type, rn.epoch, rn.seq_nr, rlen);
      }
    } else {
      /* DTLS_CIPHERTEXT */
      int ret = dtls_parse_unified_header(peer, msg, msglen, &rn, &header_length);
      if (ret < 0)
        return 0;
      rlen = ret;
    }

    security = dtls_security_params_read_epoch(peer, rn.epoch);

    if (!security) {
      dtls_warn("No security context for epoch: %" PRIu64 "\n", rn.epoch);
      data_length = -1;
    } else {
      dtls_debug("bitfield is %" PRIx64 " sequence base %" PRIx64 " rseqn %" PRIx64 "\n",
                  security->cseq.bitfield, security->cseq.cseq, rn.seq_nr);
      if (security->cseq.bitfield == 0) { /* first message of epoch */
        data_length = decrypt_verify(peer, &rn, msg, rlen, header_length, &data);
        if(data_length > 0) {
            security->cseq.cseq = rn.seq_nr;
            security->cseq.bitfield = 1;
            dtls_debug("init bitfield is %" PRIx64 " sequence base %" PRIx64 "\n",
                        security->cseq.bitfield, security->cseq.cseq);
        }
      } else {
        int64_t seqn_diff = (int64_t)(rn.seq_nr - security->cseq.cseq);
        if(seqn_diff == 0) {
          /* already seen */
          dtls_debug("Drop: duplicate packet arrived (cseq=%" PRIu64 " bitfield's start)\n", rn.seq_nr);
          return 0;
        } else if (seqn_diff < 0) { /* older rn.seq_nr < security->cseq.cseq */
          if (seqn_diff < -63) { /* too old */
            dtls_debug("Drop: packet from before the bitfield arrived\n");
            return 0;
          }
          uint64_t seqn_bit = ((uint64_t)1 << -seqn_diff);
          if (security->cseq.bitfield & seqn_bit) { /* seen it */
            dtls_debug("Drop: duplicate packet arrived (bitfield)\n");
            return 0;
          }
          dtls_debug("Packet arrived out of order\n");
          data_length = decrypt_verify(peer, &rn, msg, rlen, header_length, &data);
          if(data_length > 0) {
            security->cseq.bitfield |= seqn_bit;
            dtls_debug("update bitfield is %" PRIx64 " keep sequence base %" PRIx64 "\n",
                        security->cseq.bitfield, security->cseq.cseq);
          }
        } else { /* newer rn.seq_nr > security->cseq.cseq */
          data_length = decrypt_verify(peer, &rn, msg, rlen, header_length, &data);
          if(data_length > 0) {
            security->cseq.cseq = rn.seq_nr;
            /* bitfield. B0 last seq seen.  B1 seq-1 seen, B2 seq-2 seen etc. */
            if (seqn_diff > 63) {
              /* reset bitfield if new packet number is beyond its boundaries */
              security->cseq.bitfield = 1;
            } else {
              /* shift bitfield */
              security->cseq.bitfield <<= seqn_diff;
              security->cseq.bitfield |= 1;
            }
            dtls_debug("update bitfield is %" PRIx64 " new sequence base %" PRIx64 "\n",
                        security->cseq.bitfield, security->cseq.cseq);
          }
        }
      }
    }
    if (data_length < 0) {
      dtls_info("decrypt_verify() failed, drop message.\n");
      return 0;
    }

    if (record_type == DTLS_CIPHERTEXT) {
      /* content type is at the end of plaintext */
      content_type = data[data_length - 1];
      data_length--;
    }

    // dtls_debug_hexdump("receive header", msg, header_length);
    // dtls_debug_hexdump("receive unencrypted", data, data_length);

    /* Handle received record according to the first byte of the
     * message, i.e. the subprotocol. We currently do not support
     * combining multiple fragments of one type into a single
     * record. */

    switch (content_type) {

    case DTLS_CT_CHANGE_CIPHER_SPEC:
      break;

    case DTLS_CT_ALERT:
      if (peer->state == DTLS_STATE_WAIT_FINISHED) {
        dtls_info("** drop alert before Finish.\n");
        return 0;
      }
      err = handle_alert(ctx, peer, msg, data, data_length);
      if (err < 0) {
        /* Alert could not be decoded, ignore it */
        dtls_info("** drop alert, decode error.\n");
        return err;
      }
      if (err == 1) {
        if (data[1] == DTLS_ALERT_CLOSE_NOTIFY)
          dtls_info("received close_notify alert, peer has been invalidated\n");
        else
          dtls_warn("received fatal alert, peer has been invalidated\n");
        /* handle alert has invalidated peer */
        peer = NULL;
        err = -1;
        /* no more valid records after fatal alerts */
        return 0;
      } else {
        dtls_stop_retransmission(ctx, peer);
      }
      break;

    case DTLS_CT_HANDSHAKE:

      err = handle_handshake(ctx, peer, data, data_length);
      if (err < 0) {
        dtls_warn("error while handling handshake packet\n");
        dtls_alert_send_from_err(ctx, peer, err);

        if (peer && DTLS_ALERT_LEVEL_FATAL == ((-err) & 0xff00) >> 8) {
          /* invalidate peer */
          peer->state = DTLS_STATE_CLOSED;
          dtls_stop_retransmission(ctx, peer);
          dtls_destroy_peer(ctx, peer, DTLS_DESTROY_CLOSE);
          peer = NULL;
        }
        return err;
      }
      if (peer && peer->state == DTLS_STATE_CONNECTED) {
	/* stop retransmissions */
	dtls_stop_retransmission(ctx, peer);
	CALL(ctx, event, &peer->session, 0, DTLS_EVENT_CONNECTED);
      }
      break;

    case DTLS_CT_APPLICATION_DATA:
      if (rn.epoch == 0 || peer->state == DTLS_STATE_WAIT_FINISHED) {
          dtls_info("** drop application data before Finish.\n");
          return 0;
      }
      dtls_info("** application data:\n");
      dtls_stop_retransmission(ctx, peer);
      CALL(ctx, read, &peer->session, data, data_length);
      break;

    case DTLS_CT_ACK:
      err = handle_ack(ctx, peer, data, data_length);
      if (err < 0) {
        dtls_warn("error while handling ACK message\n");
      }
      break;

    default:
      dtls_info("dropped unknown message of type %d\n",msg[0]);
    }

    /* advance msg by length of ciphertext */
    msg += rlen;
    msglen -= rlen;
  }

  return 0;
}

dtls_context_t *
dtls_new_context(void *app_data) {
  dtls_context_t *c;
  dtls_tick_t now;

  dtls_ticks(&now);
  dtls_prng_init(now);

  c = malloc_context();
  if (!c)
    goto error;

  memset(c, 0, sizeof(dtls_context_t));
  c->app = app_data;

#ifdef WITH_CONTIKI
  process_start(&dtls_retransmit_process, (char *)c);
  PROCESS_CONTEXT_BEGIN(&dtls_retransmit_process);
  /* the retransmit timer must be initialized to some large value */
  etimer_set(&c->retransmit_timer, 0xFFFF);
  PROCESS_CONTEXT_END(&coap_retransmit_process);
#endif /* WITH_CONTIKI */

  if (dtls_prng(c->cookie_secret, DTLS_COOKIE_SECRET_LENGTH))
    c->cookie_secret_age = now;
  else
    goto error;

  return c;

 error:
  dtls_alert("cannot create DTLS context\n");
  if (c)
    dtls_free_context(c);
  return NULL;
}

void dtls_reset_peer(dtls_context_t *ctx, dtls_peer_t *peer)
{
  dtls_destroy_peer(ctx, peer, DTLS_DESTROY_CLOSE);
}

void
dtls_free_context(dtls_context_t *ctx) {
  dtls_peer_t *p, *tmp;

  if (!ctx) {
    return;
  }

  if (ctx->peers) {
#ifdef DTLS_PEERS_NOHASH
    LL_FOREACH_SAFE(ctx->peers, p, tmp) {
#else /* DTLS_PEERS_NOHASH */
    HASH_ITER(hh, ctx->peers, p, tmp) {
#endif /* DTLS_PEERS_NOHASH */
      dtls_destroy_peer(ctx, p, DTLS_DESTROY_CLOSE);
    }
  }

  free_context(ctx);
}

int
dtls_connect_peer(dtls_context_t *ctx, dtls_peer_t *peer) {
  int res;
  dtls_peer_t* previous_peer;

  assert(peer);
  if (!peer)
    return -1;

  previous_peer = dtls_get_peer(ctx, &peer->session);
  /* check if the same peer is already in our list */
  if (previous_peer) {
    if (previous_peer->role == DTLS_SERVER) {
        dtls_debug("found peer in server role, exchange role to client\n");
    } else {
        dtls_debug("found peer in client role\n");
    }
    /* no close_notify, otherwise the other peer may respond. */
    dtls_destroy_peer(ctx, previous_peer, 0);
  }

  /* set local peer role to client, remote is server */
  peer->role = DTLS_CLIENT;

  if (dtls_add_peer(ctx, peer) < 0) {
    dtls_alert("cannot add peer\n");
    return -1;
  }

  /* send ClientHello with empty Cookie */
  peer->handshake_params = dtls_handshake_new();
      if (!peer->handshake_params)
        return -1;

  peer->handshake_params->hs_state.mseq_r = 0;
  peer->handshake_params->hs_state.mseq_s = 0;
  res = dtls_send_client_hello(ctx, peer, NULL, 0);
  if (res < 0)
    dtls_warn("cannot send ClientHello\n");
  else
    peer->state = DTLS_STATE_CLIENTHELLO;

  // MF: when sending early data, do:
  // key_block(EARLY_DATA) -> switch -> send early data -> switch back
  // because epoch 1, not epoch 0 has to be overwritten by epoch 2
  res = calculate_key_block(peer, EARLY_DATA_KEY);

  return res;
}

int
dtls_connect(dtls_context_t *ctx, const session_t *dst) {
  dtls_peer_t *peer;
  int res;

  peer = dtls_get_peer(ctx, dst);

  if (!peer)
    peer = dtls_new_peer(dst);

  if (!peer) {
    dtls_crit("cannot create new peer\n");
    return -1;
  }

  res = dtls_connect_peer(ctx, peer);

  /* Invoke event callback to indicate connection attempt or
   * re-negotiation. */
  if (res > 0) {
    CALL(ctx, event, &peer->session, 0, DTLS_EVENT_CONNECT);
  } else if (res == 0) {
    CALL(ctx, event, &peer->session, 0, DTLS_EVENT_RENEGOTIATE);
  }

  return res;
}

static void
dtls_retransmit(dtls_context_t *context, netq_t *node) {
  if (!context || !node)
    return;

  /* re-initialize timeout when maximum number of retransmissions are not reached yet */
  if (node->retransmit_cnt < DTLS_DEFAULT_MAX_RETRANSMIT) {
#ifndef DTLS_CONSTRAINED_STACK
      unsigned char sendbuf[DTLS_MAX_BUF];
#endif /* ! DTLS_CONSTRAINED_STACK */
      size_t len = sizeof(sendbuf);
      int err;
      unsigned char *data = node->data;
      size_t length = node->length;
      dtls_tick_t now;
      dtls_security_parameters_t *security = dtls_security_params_epoch(node->peer, node->epoch);

      if (node->job == TIMEOUT) {
        if (node->type == DTLS_CT_ALERT) {
          dtls_debug("** alert times out\n");
          handle_alert(context, node->peer, NULL, data, length);
        }
        netq_node_free(node);
        return;
      }

#ifdef DTLS_CONSTRAINED_STACK
      dtls_mutex_lock(&static_mutex);
#endif /* DTLS_CONSTRAINED_STACK */

      dtls_ticks(&now);
      node->retransmit_cnt++;
      node->t = now + (node->timeout << node->retransmit_cnt);
      netq_insert_node(&context->sendqueue, node);

      if (node->type == DTLS_CT_HANDSHAKE) {
        dtls_handshake_header_t *hs_header = DTLS_HANDSHAKE_HEADER(data);
        dtls_debug("** retransmit handshake packet of type: %s (%i)\n",
                   dtls_handshake_type_to_name(hs_header->msg_type),
                   hs_header->msg_type);
      } else {
        dtls_debug("** retransmit packet\n");
      }

      err = dtls_prepare_record(node->peer, security, node->type, &data, &length,
                1, sendbuf, &len);
      if (err < 0) {
        dtls_warn("can not retransmit packet, err: %i\n", err);
        goto return_unlock;
      }
      dtls_debug_hexdump("retransmit header", sendbuf, sizeof(dtls_record_header_t));
      dtls_debug_hexdump("retransmit unencrypted", node->data, node->length);

      (void)CALL(context, write, &node->peer->session, sendbuf, len);
return_unlock:
#ifdef DTLS_CONSTRAINED_STACK
      dtls_mutex_unlock(&static_mutex);
#endif /* DTLS_CONSTRAINED_STACK */

      return;
  }

  /* no more retransmissions, remove node from system */

  dtls_debug("** removed transaction\n");

  /* And finally delete the node */
  netq_node_free(node);
}

static void
dtls_stop_retransmission(dtls_context_t *context, dtls_peer_t *peer) {
  netq_t *node;
  node = netq_head(&context->sendqueue);

  while (node) {
    if (dtls_session_equals(&node->peer->session, &peer->session)) {
      netq_t *tmp = node;
      node = netq_next(node);
      netq_remove(&context->sendqueue, tmp);
      netq_node_free(tmp);
    } else
      node = netq_next(node);
  }
}

void
dtls_check_retransmit(dtls_context_t *context, clock_time_t *next) {
  dtls_tick_t now;
  netq_t *node = netq_head(&context->sendqueue);

  dtls_ticks(&now);
  /* comparison considering 32bit overflow */
  while (node && DTLS_IS_BEFORE_TIME(node->t, now)) {
    netq_pop_first(&context->sendqueue);
    dtls_retransmit(context, node);
    node = netq_head(&context->sendqueue);
  }

  if (next) {
    *next = node ? node->t : 0;
  }
}

#ifdef WITH_CONTIKI
/*---------------------------------------------------------------------------*/
/* message retransmission */
/*---------------------------------------------------------------------------*/
PROCESS_THREAD(dtls_retransmit_process, ev, data)
{
  clock_time_t now;
  netq_t *node;

  PROCESS_BEGIN();

  dtls_debug("Started DTLS retransmit process\r\n");

  while(1) {
    PROCESS_YIELD();
    if (ev == PROCESS_EVENT_TIMER) {
      if (etimer_expired(&the_dtls_context.retransmit_timer)) {

	node = netq_head(&the_dtls_context.sendqueue);

	now = clock_time();
	if (node && node->t <= now) {
	  netq_pop_first(&the_dtls_context.sendqueue);
	  dtls_retransmit(&the_dtls_context, node);
	  node = netq_head(&the_dtls_context.sendqueue);
	}

	/* need to set timer to some value even if no nextpdu is available */
	if (node) {
	  etimer_set(&the_dtls_context.retransmit_timer,
		     node->t <= now ? 1 : node->t - now);
	} else {
	  etimer_set(&the_dtls_context.retransmit_timer, 0xFFFF);
	}
      }
    }
  }

  PROCESS_END();
}
#endif /* WITH_CONTIKI */
