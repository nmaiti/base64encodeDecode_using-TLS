#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#define OP_ENCODE 0
#define OP_DECODE 1

#if defined(USED_OPENSSL)
#include <openssl/bio.h>
#include <openssl/evp.h>

int b64_encdecode(const unsigned char *input, size_t input_len, char *output,
                  int output_len, int op) {
  int ret = -1;
  BIO *b64 = BIO_new(BIO_f_base64());
  BIO *bio = BIO_new(BIO_s_mem());
  BIO_set_flags(b64, BIO_FLAGS_BASE64_NO_NL);
  BIO_push(b64, bio);

  if (op == OP_ENCODE) {
    ret = BIO_write(b64, input, (int)input_len);
    BIO_flush(b64);
    if (ret > 0) {
      ret = BIO_read(bio, output, (int)output_len);
    }
  } else {
    ret = BIO_write(bio, input, (int)input_len);
    BIO_flush(bio);
    if (ret) {
      ret = BIO_read(b64, output, (int)output_len);
    }
  }
  BIO_free_all(b64);
  return ret;
}
#else
#include "mbedtls/base64.h"

int b64_encdecode(const unsigned char *input, size_t input_len, char *output,
                  int output_len, int op) {

  int ret = -1;
  size_t calculated_len = 0;
  unsigned char *tmp = NULL;

  tmp = (char *)malloc(output_len + 1);
  if (op == OP_ENCODE) {
    ret = mbedtls_base64_encode((unsigned char *)tmp, output_len + 1,
                                &calculated_len, input, input_len);
  } else {
    ret = mbedtls_base64_decode((unsigned char *)tmp, output_len + 1,
                                &calculated_len, input, input_len);
  }

  if (NULL == memcpy(output, tmp, calculated_len))
    ret = -1;
  free(tmp);
  if (ret == 0)
    ret = calculated_len;
  return ret;
}
#endif

/* change the encoding and decoding as per need */
int main(void) {
  char clear_txt[] = "Hello World to encode!";
  int ret = -1;
  char *decoded_buf = NULL;
  int decode_buf_size = 0;
  int decoded_len = 0;
  int enccoded_len = 0;
  /*
   * base64 convert 3byte to 4byte conversion,
   * pad it when less than multiple of 3 byte
   */
  char *output = NULL;
  size_t encode_buff_len = (((sizeof(clear_txt) / 3) + 1) * 4);

  output = (char *)malloc(encode_buff_len);
  enccoded_len = b64_encdecode(clear_txt, sizeof(clear_txt), output,
                               encode_buff_len, OP_ENCODE);

  printf("base64 Encoded data [%s] len [%d]\n", output, enccoded_len);

  decode_buf_size = (enccoded_len / 4) * 3 + 1;
  decoded_buf = (char *)malloc(decode_buf_size);
  decoded_len = b64_encdecode(output, enccoded_len, decoded_buf,
                              decode_buf_size, OP_DECODE);

  printf("Decoded data from b64 [%s] len [%d]\n", decoded_buf, decoded_len);

  ret = 0;
err:
  if (output)
    free(output);
  if (decoded_buf)
    free(decoded_buf);
  return ret;
}
