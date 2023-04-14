/*
 * Support routine for configuring link layer address 
 */

#ifndef LLADDR_H
#define LLADDR_H

#include "misc.h"

#ifdef __cplusplus
extern "C" {
#endif

int set_lladdr (const char *ifname, const char *lladdr, const struct env_set *es);

#ifdef __cplusplus
}
#endif

#endif
