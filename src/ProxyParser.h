/*
 * Authored by Alex Hultman, 2018-2020.
 * Intellectual property of third-party.

 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at

 *     http://www.apache.org/licenses/LICENSE-2.0

 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

/*
 * Modified by Herman Banken, 2021 to add PROXY v1.
 */

/* This module implements The PROXY Protocol v1 & v2 */

#ifndef UWS_PROXY_PARSER_H
#define UWS_PROXY_PARSER_H

#ifdef UWS_WITH_PROXY

namespace uWS {

struct proxy_hdr_v2 {
    uint8_t sig[12];  /* hex 0D 0A 0D 0A 00 0D 0A 51 55 49 54 0A */
    uint8_t ver_cmd;  /* protocol version and command */
    uint8_t fam;      /* protocol family and address */
    uint16_t len;     /* number of following bytes part of the header */
};

union proxy_addr {
    struct {        /* for TCP/UDP over IPv4, len = 12 */
        uint32_t src_addr;
        uint32_t dst_addr;
        uint16_t src_port;
        uint16_t dst_port;
    } ipv4_addr;
    struct {        /* for TCP/UDP over IPv6, len = 36 */
            uint8_t  src_addr[16];
            uint8_t  dst_addr[16];
            uint16_t src_port;
            uint16_t dst_port;
    } ipv6_addr;
};

/* Byte swap for little-endian systems */
/* Todo: This functions should be shared with the one in WebSocketProtocol.h! */
template <typename T>
T _cond_byte_swap(T value) {
    uint32_t endian_test = 1;
    if (*((char *)&endian_test)) {
        union {
            T i;
            uint8_t b[sizeof(T)];
        } src = { value }, dst;

        for (unsigned int i = 0; i < sizeof(value); i++) {
            dst.b[i] = src.b[sizeof(value) - 1 - i];
        }

        return dst.i;
    }
    return value;
}

struct ProxyParser {
private:
    union proxy_addr addr;

    /* Default family of 0 signals no proxy address */
    uint8_t family = 0;

public:
    /* Returns 4 or 16 bytes source address */
    std::string_view getSourceAddress() {

        // UNSPEC family and protocol
        if (family == 0) {
            return {};
        }

        if ((family & 0xf0) >> 4 == 1) {
            /* Family 1 is INET4 */
            return {(char *) &addr.ipv4_addr.src_addr, 4};
        } else {
            /* Family 2 is INET6 */
            return {(char *) &addr.ipv6_addr.src_addr, 16};
        }
    }

    /* Returns [done, consumed] where done = false on failure */
    std::pair<bool, unsigned int> parse(std::string_view data) {

        /* We require at least four bytes to determine protocol */
        if (data.length() < 4) {
            return {false, 0};
        }

        /* HTTP can never start with "PROX", but PROXY v1 always does */
        if (memcmp(data.data(), "\x50\x52\x4F\x58", 4) == 0) {
            return parseV1(data);
        }

        return parseV2(data);
    }


    std::pair<bool, unsigned int> parseV1(std::string_view data) {

        /* Check for the full "PROXY TCP4 " or "PROXY TCP6 " */
        if (data.length() < 11 || memcmp(data.data(), "PROXY", 5)) {
            return {false, 0};
        }

        /* Header is at most 108 bytes */
        unsigned int len = (unsigned int) data.length() - 1;
        if (data.length() > 108) {
            len = 108;
        }
        char line[108];
        int size;
        memcpy(&line, data.data(), len);

        /* locate \r in header */
        char *end = (char*)memchr(line, '\r', len);
        if (!end || end[1] != '\n') {
            /* partial or invalid header */
            return {false, 0};
        }
        *end = '\0'; /* terminate the string to ease parsing */
        size = end + 2 - line; /* skip header + CRLF */
        printf("v1 line: %s\n", line);

        if (memcmp(data.data(), "PROXY TCP4 ", 11) == 0) {
            // PROXY TCP4 255.255.255.255 255.255.255.255 65535 65535\r\n
            uint32_t *b = &addr.ipv4_addr.src_addr;
            uint32_t *c = &addr.ipv4_addr.dst_addr;
            sscanf(line + 11, "%u.%u.%u.%u %u.%u.%u.%u %d %d",
                b, b + 1, b + 2, b + 3,
                c, c + 1, c + 2, c + 3,
                &addr.ipv4_addr.src_port, 
                &addr.ipv4_addr.dst_port);
        } else if (memcmp(data.data(), "PROXY TCP6 ", 11) == 0) {
            // PROXY TCP6 ffff:f...f:ffff ffff:f...f:ffff 65535 65535\r\n
            // TODO
        } else if (data.length() >= 13 && memcmp(data.data(), "PROXY UNKNOWN", 13)) {
            /* Read UNKNOWN but don't do anything with it */
            /* We consumed the whole header */
            return {true, size};
        }

        /* Invalid/unhandled format */
        return {false, 0};
    }

    std::pair<bool, unsigned int> parseV2(std::string_view data) {

        /* HTTP can never start with "\r\n\r\n", but PROXY v2 always does */
        if (memcmp(data.data(), "\r\n\r\n", 4)) {
            /* This is HTTP, so be done */
            return {true, 0};
        }

        /* We assume we are parsing PROXY V2 here */

        /* We require 16 bytes here */
        if (data.length() < 16) {
            return {false, 0};
        }

        /* Header is 16 bytes */
        struct proxy_hdr_v2 header;
        memcpy(&header, data.data(), 16);

        if (memcmp(header.sig, "\x0D\x0A\x0D\x0A\x00\x0D\x0A\x51\x55\x49\x54\x0A", 12)) {
            /* This is not PROXY protocol at all */
            return {false, 0};
        }

        /* We only support version 2 */
        if ((header.ver_cmd & 0xf0) >> 4 != 2) {
            return {false, 0};
        }

        printf("Version: %d\n", (header.ver_cmd & 0xf0) >> 4);
        printf("Command: %d\n", (header.ver_cmd & 0x0f));

        /* We get length in network byte order (todo: share this function with the rest) */
        uint16_t hostLength = _cond_byte_swap<uint16_t>(header.len);

        /* We must have all the data available */
        if (data.length() < 16u + hostLength) {
            return {false, 0};
        }

        /* Payload cannot be more than sizeof proxy_addr */
        if (sizeof(proxy_addr) < hostLength) {
            return {false, 0};
        }

        printf("Family: %d\n", (header.fam & 0xf0) >> 4);
        printf("Transport: %d\n", (header.fam & 0x0f));

        /* We have 0 family by default, and UNSPEC is 0 as well */
        family = header.fam;

        /* Copy payload */
        memcpy(&addr, data.data() + 16, hostLength);

        /* We consumed everything */
        return {true, 16 + hostLength};
    }
};

}

#endif

#endif // UWS_PROXY_PARSER_H