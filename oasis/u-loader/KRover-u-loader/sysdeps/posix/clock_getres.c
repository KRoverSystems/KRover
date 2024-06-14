/* clock_getres -- Get the resolution of a POSIX clockid_t.
   Copyright (C) 1999-2019 Free Software Foundation, Inc.
   This file is part of the GNU C Library.

   The GNU C Library is free software; you can redistribute it and/or
   modify it under the terms of the GNU Lesser General Public
   License as published by the Free Software Foundation; either
   version 2.1 of the License, or (at your option) any later version.

   The GNU C Library is distributed in the hope that it will be useful,
   but WITHOUT ANY WARRANTY; without even the implied warranty of
   MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
   Lesser General Public License for more details.

   You should have received a copy of the GNU Lesser General Public
   License along with the GNU C Library; if not, see
   <http://www.gnu.org/licenses/>.  */

#include <errno.h>
#include <stdint.h>
#include <time.h>
#include <unistd.h>
#include <sys/param.h>
#include <libc-internal.h>


static inline int
realtime_getres (struct timespec *res)
{
  long int clk_tck = __sysconf (_SC_CLK_TCK);

  if (__glibc_likely (clk_tck != -1))
    {
      /* This implementation assumes that the realtime clock has a
	 resolution higher than 1 second.  This is the case for any
	 reasonable implementation.  */
      res->tv_sec = 0;
      res->tv_nsec = 1000000000 / clk_tck;
      return 0;
    }

  return -1;
}


/* Get resolution of clock.  */
int
__clock_getres (clockid_t clock_id, struct timespec *res)
{
  int retval = -1;

  switch (clock_id)
    {
    case CLOCK_REALTIME:
      retval = realtime_getres (res);
      break;

    default:
      __set_errno (EINVAL);
      break;
    }

  return retval;
}
weak_alias (__clock_getres, clock_getres)
