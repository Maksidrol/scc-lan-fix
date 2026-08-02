/*
 * systemdetection.dll — Splinter Cell: Conviction LAN fix via IAT hooking
 *
 * Drop next to conviction_game.exe. Works on Windows and Linux/Steam Deck.
 *
 * On load:
 *   1. Starts an internal TCP server on 127.0.0.1:3074 that serves
 *      a fake Ubisoft matchmaking XML response (same as bypass_server_check.py)
 *   2. Patches the game's Import Address Table so:
 *      - connect() to port 3074 is redirected to 127.0.0.1:3074
 *      - bind() tracks UDP sockets bound to port 46000
 *      - recvfrom()/WSARecvFrom() fix host IP in LAN session info packets
 *        (same logic as fix_lan_packet.py)
 *      - closesocket() cleans up the UDP tracking table
 */

#define WIN32_LEAN_AND_MEAN
#include <winsock2.h>
#include <windows.h>
#include <tlhelp32.h>
#include <iphlpapi.h>
#include <string.h>
#include <stdio.h>
#include <stdlib.h>
#include <stdarg.h>

/* ------------------------------------------------------------------ */
/* Debug log — written to network_log.txt next to the exe (only if file exists) */
/* ------------------------------------------------------------------ */

static FILE *g_log = NULL;

static void log_init(void) {
    char path[MAX_PATH];
    GetModuleFileNameA(NULL, path, MAX_PATH);
    char *slash = strrchr(path, '\\');
    if (slash) *(slash + 1) = '\0';
    strcat(path, "network_log.txt");
    if (GetFileAttributesA(path) == INVALID_FILE_ATTRIBUTES) return;
    g_log = fopen(path, "w");
    if (g_log) { setvbuf(g_log, NULL, _IONBF, 0); }
}

static void dbg(const char *fmt, ...) {
    if (!g_log) return;
    va_list ap; va_start(ap, fmt); vfprintf(g_log, fmt, ap); va_end(ap);
    fprintf(g_log, "\n");
}

#define DBG(...) dbg(__VA_ARGS__)

/* ------------------------------------------------------------------ */
/* Real ws2_32.dll function pointers (resolved in DllMain)            */
/* ------------------------------------------------------------------ */

static HMODULE real_ws2 = NULL;

static int    (WINAPI *real_connect)    (SOCKET, const struct sockaddr *, int)           = NULL;
static int    (WINAPI *real_send)       (SOCKET, const char *, int, int)                 = NULL;
static int    (WINAPI *real_recv)       (SOCKET, char *, int, int)                       = NULL;
static int    (WINAPI *real_bind)       (SOCKET, const struct sockaddr *, int)           = NULL;
static int    (WINAPI *real_recvfrom)   (SOCKET, char *, int, int, struct sockaddr *, int *) = NULL;
static int    (WINAPI *real_closesocket)(SOCKET)                                         = NULL;
static int    (WINAPI *real_WSARecvFrom)(SOCKET, LPWSABUF, DWORD, LPDWORD, LPDWORD, struct sockaddr *, LPINT, LPWSAOVERLAPPED, LPWSAOVERLAPPED_COMPLETION_ROUTINE) = NULL;

/* ------------------------------------------------------------------ */
/* Fake Ubisoft matchmaking response                                   */
/* ------------------------------------------------------------------ */

static const char matchmaking_response[] =
    "HTTP/1.1 200 OK\r\n"
    "Cache-Control: private\r\n"
    "Content-Type: text/html; charset=utf-8\r\n"
    "Server: Microsoft-IIS/10.0\r\n"
    "X-AspNet-Version: 2.0.50727\r\n"
    "X-Powered-By: ASP.NET\r\n"
    "Date: Mon, 01 Jan 2024 23:10:02 GMT\r\n"
    "Content-Length: 1183\r\n"
    "\r\n"
    "<RESPONSE xmlns=\"\">"
    "<AuthenticationServer><VALUE>lb-agora.ubisoft.com:3081</VALUE></AuthenticationServer>"
    "<CreateAccount><VALUE>https://secure.ubi.com/login/CreateUser.aspx?lang=%s</VALUE></CreateAccount>"
    "<LobbyServer><VALUE>lb-lsg-prod.ubisoft.com:3105</VALUE></LobbyServer>"
    "<MmpTitleId><VALUE>0xA004</VALUE></MmpTitleId>"
    "<SandboxUrl><VALUE>prudp:/address=lb-rdv-as-prod01.ubisoft.com;port=23931</VALUE></SandboxUrl>"
    "<SandboxUrlWS><VALUE>ne1-z3-as-rdv03.ubisoft.com:23930</VALUE></SandboxUrlWS>"
    "<SerialName><VALUE>SPLINTERCELL5PC</VALUE></SerialName>"
    "<uplay_DownloadServiceUrl><VALUE>https://secure.ubi.com/UplayServices/UplayFacade/DownloadServicesRESTXML.svc/REST/XML/?url=</VALUE></uplay_DownloadServiceUrl>"
    "<uplay_DynContentBaseUrl><VALUE>http://static8.cdn.ubi.com/u/Uplay/</VALUE></uplay_DynContentBaseUrl>"
    "<uplay_DynContentSecureBaseUrl><VALUE>http://static8.cdn.ubi.com/</VALUE></uplay_DynContentSecureBaseUrl>"
    "<uplay_PackageBaseUrl><VALUE>http://static8.cdn.ubi.com/u/Uplay/Packages/1.0.1/</VALUE></uplay_PackageBaseUrl>"
    "<uplay_WebServiceBaseUrl><VALUE>https://secure.ubi.com/UplayServices/UplayFacade/ProfileServicesFacadeRESTXML.svc/REST/</VALUE></uplay_WebServiceBaseUrl>"
    "</RESPONSE>";

#define MATCHMAKING_RESPONSE_LEN ((int)(sizeof(matchmaking_response) - 1))

/* ------------------------------------------------------------------ */
/* Internal TCP server on 127.0.0.1:3074 — serves fake Ubisoft XML   */
/* ------------------------------------------------------------------ */

/* Saved before patch_iat — used by server thread and detach cleanup */
static int (WINAPI *orig_closesocket)(SOCKET) = NULL;

static SOCKET g_server_sock = INVALID_SOCKET;

static DWORD WINAPI tcp_server_thread(LPVOID unused) {
    (void)unused;

    SOCKET srv = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
    if (srv == INVALID_SOCKET) { DBG("server: socket() failed"); return 1; }

    BOOL reuse = TRUE;
    setsockopt(srv, SOL_SOCKET, SO_REUSEADDR, (const char *)&reuse, sizeof(reuse));

    struct sockaddr_in addr;
    addr.sin_family      = AF_INET;
    addr.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
    addr.sin_port        = htons(3074);

    if (real_bind(srv, (struct sockaddr *)&addr, sizeof(addr)) != 0) {
        DBG("server: bind() failed on 127.0.0.1:3074");
        orig_closesocket(srv);
        return 1;
    }
    listen(srv, 10);
    g_server_sock = srv;
    DBG("server: listening on 127.0.0.1:3074");

    while (1) {
        SOCKET client = accept(srv, NULL, NULL);
        if (client == INVALID_SOCKET) break;
        DBG("server: accepted connection");

        /* 3-second timeouts — prevents hanging if game opens socket but sends/reads nothing */
        DWORD tv = 3000;
        setsockopt(client, SOL_SOCKET, SO_RCVTIMEO, (const char *)&tv, sizeof(tv));
        setsockopt(client, SOL_SOCKET, SO_SNDTIMEO, (const char *)&tv, sizeof(tv));

        /* Drain the HTTP request — read until we get double CRLF or timeout */
        char buf[2048];
        int  total = 0;
        while (total < (int)sizeof(buf) - 1) {
            int n = real_recv(client, buf + total, sizeof(buf) - 1 - total, 0);
            if (n <= 0) break;
            total += n;
            buf[total] = '\0';
            if (strstr(buf, "\r\n\r\n")) break;
        }

        /* sendall — loop until every byte is sent */
        const char *p = matchmaking_response;
        int left = MATCHMAKING_RESPONSE_LEN;
        while (left > 0) {
            int n = real_send(client, p, left, 0);
            if (n <= 0) break;
            p    += n;
            left -= n;
        }

        orig_closesocket(client);
        DBG("server: sent fake response and closed client");
    }
    return 0;
}

static void start_tcp_server(void) {
    HANDLE t = CreateThread(NULL, 0, tcp_server_thread, NULL, 0, NULL);
    if (t) { CloseHandle(t); }
    else { DBG("ERROR: CreateThread for tcp_server_thread failed (%lu)", GetLastError()); }
}

/* ------------------------------------------------------------------ */
/* Bind IP override — reads from SCC_BIND_IP env or my_ip.txt        */
/* ------------------------------------------------------------------ */

/* Auto-detect: find IP of interface with lowest metric to 255.255.255.255.
 * Same logic as find_interface_priority.py but via WinAPI (no text parsing). */
static int get_broadcast_interface_ip(char *out, int out_len) {
    /* Step 1: find interface index with lowest metric to 255.255.255.255 */
    ULONG fwd_size = 0;
    GetIpForwardTable(NULL, &fwd_size, FALSE);
    if (fwd_size == 0) return 0;

    MIB_IPFORWARDTABLE *fwd = (MIB_IPFORWARDTABLE *)HeapAlloc(GetProcessHeap(), 0, fwd_size);
    if (!fwd) return 0;

    if (GetIpForwardTable(fwd, &fwd_size, FALSE) != NO_ERROR) {
        HeapFree(GetProcessHeap(), 0, fwd);
        return 0;
    }

    DWORD best_metric = 0xFFFFFFFF;
    DWORD best_ifindex = 0;
    int found = 0;

    for (DWORD i = 0; i < fwd->dwNumEntries; i++) {
        MIB_IPFORWARDROW *row = &fwd->table[i];
        /* Match route to 255.255.255.255/255.255.255.255 */
        if (row->dwForwardDest == 0xFFFFFFFF && row->dwForwardMask == 0xFFFFFFFF) {
            if (!found || row->dwForwardMetric1 < best_metric) {
                best_metric   = row->dwForwardMetric1;
                best_ifindex  = row->dwForwardIfIndex;
                found = 1;
            }
        }
    }
    HeapFree(GetProcessHeap(), 0, fwd);
    if (!found) return 0;

    /* Step 2: find IP address for that interface index */
    ULONG addr_size = 0;
    GetIpAddrTable(NULL, &addr_size, FALSE);
    if (addr_size == 0) return 0;

    MIB_IPADDRTABLE *addrs = (MIB_IPADDRTABLE *)HeapAlloc(GetProcessHeap(), 0, addr_size);
    if (!addrs) return 0;

    if (GetIpAddrTable(addrs, &addr_size, FALSE) != NO_ERROR) {
        HeapFree(GetProcessHeap(), 0, addrs);
        return 0;
    }

    int ok = 0;
    for (DWORD i = 0; i < addrs->dwNumEntries; i++) {
        if (addrs->table[i].dwIndex == best_ifindex) {
            struct in_addr a;
            a.s_addr = addrs->table[i].dwAddr;
            const char *ip_str = inet_ntoa(a);
            if (ip_str && strcmp(ip_str, "0.0.0.0") != 0) {
                strncpy(out, ip_str, out_len - 1);
                out[out_len - 1] = '\0';
                ok = 1;
            }
            break;
        }
    }
    HeapFree(GetProcessHeap(), 0, addrs);
    return ok;
}

static const char *get_bind_ip_override(void) {
    /* Priority 1: environment variable */
    const char *env = getenv("SCC_BIND_IP");
    if (env && env[0] != '\0') return env;

    /* Priority 2: my_ip.txt next to conviction_game.exe */
    static char file_ip[64] = {0};
    static int  file_checked = 0;
    if (file_checked) goto try_auto;

    file_checked = 1;
    {
        char path[MAX_PATH];
        GetModuleFileNameA(NULL, path, MAX_PATH);
        char *slash = strrchr(path, '\\');
        if (slash) {
            *(slash + 1) = '\0';
            strcat(path, "my_ip.txt");
            FILE *f = fopen(path, "r");
            if (f) {
                char line[64] = {0};
                if (fgets(line, sizeof(line), f)) {
                    char *p = line + strlen(line) - 1;
                    while (p >= line && (*p == '\r' || *p == '\n' || *p == ' ')) *p-- = '\0';
                    if (line[0] != '\0')
                        strncpy(file_ip, line, sizeof(file_ip) - 1);
                }
                fclose(f);
            }
        }
    }
    if (file_ip[0] != '\0') return file_ip;

try_auto:

    /* Priority 3: auto-detect interface with lowest metric to 255.255.255.255 */
    static char auto_ip[64] = {0};
    if (auto_ip[0] != '\0') return auto_ip; /* cached */
    if (get_broadcast_interface_ip(auto_ip, sizeof(auto_ip))) {
        DBG("get_bind_ip_override: auto-detected broadcast interface IP=%s", auto_ip);
        return auto_ip;
    }

    return NULL;
}

/* ------------------------------------------------------------------ */
/* UDP port-46000 socket table                                        */
/* ------------------------------------------------------------------ */

#define MAX_UDP46_SOCKETS 16

static SOCKET           udp46_sockets[MAX_UDP46_SOCKETS];
static int              udp46_socket_count = 0;
static CRITICAL_SECTION udp46_lock;

static void udp46_add(SOCKET s) {
    EnterCriticalSection(&udp46_lock);
    if (udp46_socket_count < MAX_UDP46_SOCKETS)
        udp46_sockets[udp46_socket_count++] = s;
    LeaveCriticalSection(&udp46_lock);
}

static void udp46_remove(SOCKET s) {
    EnterCriticalSection(&udp46_lock);
    for (int i = 0; i < udp46_socket_count; i++) {
        if (udp46_sockets[i] == s) {
            udp46_sockets[i] = udp46_sockets[--udp46_socket_count];
            break;
        }
    }
    LeaveCriticalSection(&udp46_lock);
}

static int udp46_is_tracked(SOCKET s) {
    EnterCriticalSection(&udp46_lock);
    for (int i = 0; i < udp46_socket_count; i++) {
        if (udp46_sockets[i] == s) {
            LeaveCriticalSection(&udp46_lock);
            return 1;
        }
    }
    LeaveCriticalSection(&udp46_lock);
    return 0;
}

/* ------------------------------------------------------------------ */
/* Our interceptors                                                    */
/* ------------------------------------------------------------------ */

static int WINAPI my_connect(SOCKET s, const struct sockaddr *name, int namelen) {
    if (name && name->sa_family == AF_INET) {
        const struct sockaddr_in *addr = (const struct sockaddr_in *)name;
        int port = ntohs(addr->sin_port);
        if (port == 3074) {
            struct sockaddr_in local;
            local.sin_family      = AF_INET;
            local.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
            local.sin_port        = htons(3074);
            int r = real_connect(s, (struct sockaddr *)&local, sizeof(local));
            /* r=0 (blocking) or -1/WSAEWOULDBLOCK (non-blocking) — both OK */
            DBG("connect() -> redirected to 127.0.0.1:3074, result=%d err=%d", r, WSAGetLastError());
            return r;
        }
    }
    return real_connect(s, name, namelen);
}

static int WINAPI my_bind(SOCKET s, const struct sockaddr *addr, int addrlen) {
    if (addr && addr->sa_family == AF_INET) {
        const struct sockaddr_in *a = (const struct sockaddr_in *)addr;
        int port = ntohs(a->sin_port);
        if (port == 46000) {
            udp46_add(s);
            DBG("bind() -> tracking socket=%lu for UDP port 46000", (unsigned long)s);

            /* If SCC_BIND_IP env or scc_bind_ip.txt is set, force bind to that interface.
             * Useful on Steam Deck / multi-interface setups (e.g. ZeroTier, Radmin).
             * Option 1 — Steam Launch Options: SCC_BIND_IP=10.x.x.x %command%
             * Option 2 — create my_ip.txt next to conviction_game.exe with the IP on first line */
            const char *bind_ip = get_bind_ip_override();
            if (bind_ip) {
                unsigned long ip = inet_addr(bind_ip);
                if (ip != INADDR_NONE) {
                    struct sockaddr_in patched = *a;
                    patched.sin_addr.s_addr = ip;
                    DBG("bind() -> overriding bind IP to %s", bind_ip);
                    return real_bind(s, (struct sockaddr *)&patched, addrlen);
                } else {
                    DBG("bind() -> invalid IP '%s', using original address", bind_ip);
                }
            }
        }
    }
    return real_bind(s, addr, addrlen);
}

static int WINAPI my_recvfrom(SOCKET s, char *buf, int len, int flags,
                               struct sockaddr *from, int *fromlen) {
    int result = real_recvfrom(s, buf, len, flags, from, fromlen);
    if (result <= 0 || !udp46_is_tracked(s))
        return result;
    if (result <= 500 || !from || from->sa_family != AF_INET || result < 0x5c + 8)
        return result;

    unsigned char *payload = (unsigned char *)buf;
    struct sockaddr_in *src = (struct sockaddr_in *)from;

    unsigned char ip_field[8];
    ip_field[0] = 0x07;
    memcpy(&ip_field[1], &src->sin_addr.s_addr, 4);
    ip_field[5] = 0x05;
    ip_field[6] = 0x23;
    ip_field[7] = 0x8F;

    int num_ips = (int)payload[0x5b] - 1;

    if (num_ips <= 0) {
        if (result + 8 <= len) {
            memmove(payload + 0x5c + 8, payload + 0x5c, result - 0x5c);
            memcpy(payload + 0x5c, ip_field, 8);
            result += 8;
        }
    } else if (num_ips >= 2) {
        int tail_src = 0x5c + num_ips * 8;
        if (tail_src > result) return result;
        memmove(payload + 0x5c + 8, payload + tail_src, result - tail_src);
        memcpy(payload + 0x5c, ip_field, 8);
        result -= (num_ips - 1) * 8;
    } else {
        memcpy(payload + 0x5c, ip_field, 8);
    }

    payload[0x5b] = 2;
    DBG("recvfrom() patched host IP in LAN packet, result=%d", result);
    return result;
}

static int WINAPI my_closesocket(SOCKET s) {
    udp46_remove(s);
    return real_closesocket(s);
}

/* WSARecvFrom — fix host IP in LAN session info packets (port 46000 inbound) */
static int WINAPI my_WSARecvFrom(SOCKET s, LPWSABUF bufs, DWORD buf_count,
                                  LPDWORD bytes_recv, LPDWORD flags,
                                  struct sockaddr *from, LPINT fromlen,
                                  LPWSAOVERLAPPED overlapped,
                                  LPWSAOVERLAPPED_COMPLETION_ROUTINE completion) {
    int result = real_WSARecvFrom(s, bufs, buf_count, bytes_recv, flags,
                                   from, fromlen, overlapped, completion);
    if (result != 0 || !bytes_recv) return result;

    DWORD recv_len = *bytes_recv;
    if (!udp46_is_tracked(s)) return result;
    if (recv_len <= 500) return result;
    if (!from || from->sa_family != AF_INET) return result;
    if (recv_len < 0x5c + 8) return result;
    if (buf_count == 0) return result;

    /* Reassemble into first buffer for patching (game typically uses one buffer) */
    unsigned char *payload = (unsigned char *)bufs[0].buf;
    if (bufs[0].len < recv_len) return result;

    struct sockaddr_in *src = (struct sockaddr_in *)from;
    unsigned char ip_field[8];
    ip_field[0] = 0x07;
    memcpy(&ip_field[1], &src->sin_addr.s_addr, 4);
    ip_field[5] = 0x05;
    ip_field[6] = 0x23;
    ip_field[7] = 0x8F;

    int num_ips = (int)payload[0x5b] - 1;
    int r = (int)recv_len;

    if (num_ips <= 0) {
        if (r + 8 <= (int)bufs[0].len) {
            memmove(payload + 0x5c + 8, payload + 0x5c, r - 0x5c);
            memcpy(payload + 0x5c, ip_field, 8);
            r += 8;
        }
    } else if (num_ips >= 2) {
        int tail_src = 0x5c + num_ips * 8;
        if (tail_src > r) return result;
        memmove(payload + 0x5c + 8, payload + tail_src, r - tail_src);
        memcpy(payload + 0x5c, ip_field, 8);
        r -= (num_ips - 1) * 8;
    } else {
        memcpy(payload + 0x5c, ip_field, 8);
    }

    payload[0x5b] = 2;
    *bytes_recv = (DWORD)r;
    DBG("WSARecvFrom() patched host IP in LAN packet");
    return 0;
}

/* ------------------------------------------------------------------ */
/* IAT patch — replaces function pointers in the game's import table  */
/* ------------------------------------------------------------------ */

typedef struct {
    const char *name;
    WORD        ordinal; /* ws2_32.dll ordinal (0 = not imported by ordinal) */
    void       *hook;
    void      **original;
} Hook;

static Hook hooks[] = {
    { "connect",     4,  my_connect,     (void **)&real_connect     },
    { "bind",        2,  my_bind,        (void **)&real_bind         },
    { "recvfrom",   17,  my_recvfrom,    (void **)&real_recvfrom     },
    { "closesocket", 3,  my_closesocket, (void **)&real_closesocket  },
    { "WSARecvFrom", 93, my_WSARecvFrom, (void **)&real_WSARecvFrom  },
};
#define NUM_HOOKS (sizeof(hooks) / sizeof(hooks[0]))

static void patch_module_iat(BYTE *base) {
    IMAGE_DOS_HEADER     *dos = (IMAGE_DOS_HEADER *)base;
    if (dos->e_magic != IMAGE_DOS_SIGNATURE) return;

    IMAGE_NT_HEADERS     *nt  = (IMAGE_NT_HEADERS *)(base + dos->e_lfanew);
    if (nt->Signature != IMAGE_NT_SIGNATURE) return;

    IMAGE_DATA_DIRECTORY *dir =
        &nt->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT];
    if (!dir->VirtualAddress) return;

    IMAGE_IMPORT_DESCRIPTOR *imp =
        (IMAGE_IMPORT_DESCRIPTOR *)(base + dir->VirtualAddress);

    for (; imp->Name; imp++) {
        const char *dll_name = (const char *)(base + imp->Name);

        /* Patch both ws2_32.dll and wsock32.dll */
        if (_stricmp(dll_name, "ws2_32.dll")  != 0 &&
            _stricmp(dll_name, "wsock32.dll") != 0)
            continue;

        DBG("patch_module_iat: found %s in module at base=%p", dll_name, (void*)base);

        /* Use OriginalFirstThunk for names, fall back to FirstThunk if zero */
        IMAGE_THUNK_DATA *orig_thunk = imp->OriginalFirstThunk
            ? (IMAGE_THUNK_DATA *)(base + imp->OriginalFirstThunk)
            : (IMAGE_THUNK_DATA *)(base + imp->FirstThunk);
        IMAGE_THUNK_DATA *iat_thunk  =
            (IMAGE_THUNK_DATA *)(base + imp->FirstThunk);

        for (; orig_thunk->u1.AddressOfData; orig_thunk++, iat_thunk++) {
            if (orig_thunk->u1.Ordinal & IMAGE_ORDINAL_FLAG) {
                WORD ord = (WORD)(orig_thunk->u1.Ordinal & 0xffff);
                for (int i = 0; i < (int)NUM_HOOKS; i++) {
                    if (hooks[i].ordinal == 0 || hooks[i].ordinal != ord)
                        continue;
                    if (*hooks[i].original == NULL)
                        *hooks[i].original = (void *)iat_thunk->u1.Function;
                    DWORD old_protect;
                    VirtualProtect(&iat_thunk->u1.Function,
                                   sizeof(void *), PAGE_READWRITE, &old_protect);
                    iat_thunk->u1.Function = (ULONG_PTR)hooks[i].hook;
                    VirtualProtect(&iat_thunk->u1.Function,
                                   sizeof(void *), old_protect, &old_protect);
                    DBG("  PATCHED ordinal %u -> %s", (unsigned)ord, hooks[i].name);
                }
                continue;
            }

            IMAGE_IMPORT_BY_NAME *by_name =
                (IMAGE_IMPORT_BY_NAME *)(base + orig_thunk->u1.AddressOfData);

            for (int i = 0; i < (int)NUM_HOOKS; i++) {
                if (_stricmp((char *)by_name->Name, hooks[i].name) != 0)
                    continue;

                /* Save original only on first patch (don't overwrite with our own hook) */
                if (*hooks[i].original == NULL)
                    *hooks[i].original = (void *)iat_thunk->u1.Function;

                DWORD old_protect;
                VirtualProtect(&iat_thunk->u1.Function,
                               sizeof(void *), PAGE_READWRITE, &old_protect);
                iat_thunk->u1.Function = (ULONG_PTR)hooks[i].hook;
                VirtualProtect(&iat_thunk->u1.Function,
                               sizeof(void *), old_protect, &old_protect);
                DBG("  PATCHED: %s", hooks[i].name);
            }
        }
    }
}

static void patch_iat(void) {
    HMODULE self = GetModuleHandleA("systemdetection.dll");
    HMODULE exe  = GetModuleHandleA(NULL);

    /* Patch the main executable */
    DBG("patching main exe at %p", (void*)exe);
    patch_module_iat((BYTE *)exe);

    HANDLE snap = CreateToolhelp32Snapshot(TH32CS_SNAPMODULE, 0);
    if (snap == INVALID_HANDLE_VALUE) { DBG("snapshot failed"); return; }

    MODULEENTRY32 me = { sizeof(me) };
    if (Module32First(snap, &me)) {
        do {
            /* Skip our own DLL and the main exe (already patched above) */
            if ((HMODULE)me.modBaseAddr == self) continue;
            if ((HMODULE)me.modBaseAddr == exe)  continue;
            patch_module_iat((BYTE *)me.modBaseAddr);
        } while (Module32Next(snap, &me));
    }
    CloseHandle(snap);
}

/* ------------------------------------------------------------------ */
/* Stubs — game expects these exports from systemdetection.dll        */
/* ------------------------------------------------------------------ */

__declspec(dllexport) void *WINAPI GetHardwareInstance(void) { return NULL; }
__declspec(dllexport) void *WINAPI GetScoreInstance(void)    { return NULL; }

/* ------------------------------------------------------------------ */
/* DllMain                                                            */
/* ------------------------------------------------------------------ */

BOOL WINAPI DllMain(HINSTANCE hinstDLL, DWORD fdwReason, LPVOID lpvReserved) {
    (void)hinstDLL; (void)lpvReserved;

    if (fdwReason == DLL_PROCESS_ATTACH) {
        log_init();
        DBG("=== systemdetection.dll loaded ===");
        InitializeCriticalSection(&udp46_lock);
        udp46_socket_count = 0;

        /* Load ws2_32 so real_* pointers are valid fallbacks before patch */
        real_ws2 = LoadLibraryA("ws2_32.dll");
        if (!real_ws2) { DBG("ERROR: ws2_32.dll not found"); return FALSE; }

        /* Set real_* to originals from ws2_32 as safe defaults */
        real_connect     = (void *)GetProcAddress(real_ws2, "connect");
        real_send        = (void *)GetProcAddress(real_ws2, "send");
        real_recv        = (void *)GetProcAddress(real_ws2, "recv");
        real_bind        = (void *)GetProcAddress(real_ws2, "bind");
        real_recvfrom    = (void *)GetProcAddress(real_ws2, "recvfrom");
        real_closesocket = (void *)GetProcAddress(real_ws2, "closesocket");
        real_WSARecvFrom = (void *)GetProcAddress(real_ws2, "WSARecvFrom");
        orig_closesocket = real_closesocket; /* save before patch_iat overwrites IAT */
        if (!real_connect || !real_send || !real_recv || !real_bind ||
            !real_recvfrom || !real_closesocket || !real_WSARecvFrom) {
            DBG("ERROR: failed to resolve ws2_32 functions");
            return FALSE;
        }
        DBG("real_connect=%p real_bind=%p real_recvfrom=%p",
            (void*)real_connect, (void*)real_bind, (void*)real_recvfrom);

        /* Start internal TCP server on 127.0.0.1:3074 */
        start_tcp_server();

        /* Patch the game's IAT */
        DBG("calling patch_iat...");
        patch_iat();
        DBG("patch_iat done");
        DBG("hooks patched: connect bind recvfrom closesocket WSARecvFrom");

    } else if (fdwReason == DLL_PROCESS_DETACH) {
        DBG("=== systemdetection.dll unloading ===");
        if (g_server_sock != INVALID_SOCKET) {
            orig_closesocket(g_server_sock);
            g_server_sock = INVALID_SOCKET;
        }
        DeleteCriticalSection(&udp46_lock);
        if (real_ws2) FreeLibrary(real_ws2);
        if (g_log) { fclose(g_log); g_log = NULL; }
    }

    return TRUE;
}
