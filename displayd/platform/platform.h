#ifndef _PLATFORM_H_
#define _PLATFORM_H_

struct display_mode_info {
	const char *identify;
	int code;
};

#ifdef PLATFORM_SUN50IW6P1
#include "platform-sun50iw6p1.h"
#endif

#endif

