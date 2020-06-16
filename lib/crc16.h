#ifndef _CRC_CRC16_H
#define _CRC_CRC16_H

#include <stdint.h>
#ifdef __cplusplus
extern "C" {
#endif /* __cplusplus  */

unsigned short crc16_ccitt(const unsigned char *buf, int len);
int check(unsigned short crc, const unsigned char *buf, int sz);

#ifdef __cplusplus
}
#endif /* __cplusplus  */
#endif

