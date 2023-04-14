#ifndef __COMPAT_STDBOOL_H
#define __COMPAT_STDBOOL_H

#ifndef __cplusplus

#ifdef HAVE_STDBOOL_H
#include <stdbool.h>
#else
typedef int bool;
#define false 0
#define true 1
#endif

#endif

#endif
