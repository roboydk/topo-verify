/*
 * Copyright (c) 2015 by Cisco Systems, Inc.
 * All rights reserved.
 * 
 * Description: utility to send packets over raw L2 socket 
 */


 /*
  *  IPv6 fixed header
  *
  *  BEWARE, it is incorrect. The first 4 bits of flow_lbl
  *  are glued to priority now, forming "class".
  */
 
 struct ipv6hdr {
 #if defined(__LITTLE_ENDIAN_BITFIELD)
     __u8            priority:4,
                 version:4;
 #elif defined(__BIG_ENDIAN_BITFIELD)
     __u8            version:4,
                 priority:4;
 #else
 #error  "Please fix <asm/byteorder.h>"
 #endif
     __u8            flow_lbl[3];
 
     __be16          payload_len;
     __u8            nexthdr;
     __u8            hop_limit;
 
     struct  in6_addr    saddr;
     struct  in6_addr    daddr;
 };

