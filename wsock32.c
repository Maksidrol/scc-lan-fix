/*
 * systemdetection.dll — Splinter Cell: Conviction LAN fix via IAT hooking
 *
 * Drop next to conviction_game.exe. Works on Windows and Linux/Steam Deck.
 *
 * On load:
 *   1. Lazily starts an internal TCP server on a private loopback port that serves
 *      a fake Ubisoft matchmaking XML response (same as bypass_server_check.py)
 *   2. Patches the game's Import Address Table so:
 *      - connect() to port 3074 is redirected to the private loopback server
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
#include <timeapi.h>

/* ------------------------------------------------------------------ */
/* Debug log — written to log.txt next to the exe (only if file exists) */
/* ------------------------------------------------------------------ */

static FILE *g_log = NULL;

static void log_init(void) {
    char path[MAX_PATH];
    GetModuleFileNameA(NULL, path, MAX_PATH);
    char *slash = strrchr(path, '\\');
    if (slash) *(slash + 1) = '\0';
    strcat(path, "log.txt");
    if (GetFileAttributesA(path) == INVALID_FILE_ATTRIBUTES) return;
    g_log = fopen(path, "a");
    if (g_log) {
        setvbuf(g_log, NULL, _IONBF, 0);
        SYSTEMTIME st;
        GetLocalTime(&st);
        fprintf(g_log, "\n===== %04d-%02d-%02d %02d:%02d:%02d =====\n",
            st.wYear, st.wMonth, st.wDay, st.wHour, st.wMinute, st.wSecond);
    }
}

static void dbg(const char *fmt, ...) {
    /* stdio is allowed to overwrite the calling thread's Winsock last error.
     * Hooks must be observational: diagnostics cannot change game behaviour. */
    int saved_wsa_error = WSAGetLastError();
    if (!g_log) {
        WSASetLastError(saved_wsa_error);
        return;
    }
    va_list ap; va_start(ap, fmt); vfprintf(g_log, fmt, ap); va_end(ap);
    fprintf(g_log, "\n");
    WSASetLastError(saved_wsa_error);
}

#define DBG(...) dbg(__VA_ARGS__)

/* ------------------------------------------------------------------ */
/* Crash dump handler                                                  */
/* ------------------------------------------------------------------ */

typedef struct {
    DWORD               ThreadId;
    PEXCEPTION_POINTERS ExceptionPointers;
    BOOL                ClientPointers;
} MY_MINIDUMP_EXCEPTION_INFO;

typedef BOOL (WINAPI *MiniDumpWriteDump_t)(
    HANDLE, DWORD, HANDLE, DWORD,
    MY_MINIDUMP_EXCEPTION_INFO *, PVOID, PVOID);

static LPTOP_LEVEL_EXCEPTION_FILTER g_prev_filter  = NULL;
static MiniDumpWriteDump_t          g_MiniDumpWrite = NULL;
static char                         g_crash_path[MAX_PATH]; /* built at init, not at crash */

/* Minimal handler — no heap ops, no printf, only kernel calls */
static LONG WINAPI crash_handler(EXCEPTION_POINTERS *ep) {
    if (g_MiniDumpWrite && g_crash_path[0]) {
        HANDLE hf = CreateFileA(g_crash_path, GENERIC_WRITE, 0, NULL,
                                CREATE_ALWAYS, FILE_ATTRIBUTE_NORMAL, NULL);
        if (hf != INVALID_HANDLE_VALUE) {
            MY_MINIDUMP_EXCEPTION_INFO mei;
            mei.ThreadId          = GetCurrentThreadId();
            mei.ExceptionPointers = ep;
            mei.ClientPointers    = FALSE;
            g_MiniDumpWrite(GetCurrentProcess(), GetCurrentProcessId(),
                            hf, 0 /* MiniDumpNormal */, &mei, NULL, NULL);
            CloseHandle(hf);
        }
    }
    if (g_prev_filter)
        return g_prev_filter(ep);
    return EXCEPTION_CONTINUE_SEARCH;
}

static void install_crash_handler(void) {
    /* Pre-build path at startup — safe to use in crash_handler without heap ops */
    char path[MAX_PATH];
    GetModuleFileNameA(NULL, path, MAX_PATH);
    char *slash = strrchr(path, '\\');
    if (slash) {
        *(slash + 1) = '\0';
        strcat(path, "crash.dmp");
        strncpy(g_crash_path, path, MAX_PATH - 1);
        g_crash_path[MAX_PATH - 1] = '\0';
    }
    /* Only install if log.txt exists — same opt-in marker as the debug log */
    if (!g_log) return;
    /* dbghelp.dll is a system DLL — already in memory, LoadLibrary just bumps ref count */
    HMODULE dbghelp = LoadLibraryA("dbghelp.dll");
    if (!dbghelp) { DBG("crash_handler: dbghelp.dll not found, skipping"); return; }
    g_MiniDumpWrite = (MiniDumpWriteDump_t)GetProcAddress(dbghelp, "MiniDumpWriteDump");
    if (!g_MiniDumpWrite) { DBG("crash_handler: MiniDumpWriteDump not found, skipping"); return; }
    /* Save previous filter and chain to it — don't break other handlers */
    g_prev_filter = SetUnhandledExceptionFilter(crash_handler);
    DBG("crash_handler: installed (prev=%p, path=%s)", (void*)g_prev_filter, g_crash_path);
}

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
static BOOL   (WINAPI *real_SetProcessAffinityMask)(HANDLE, DWORD_PTR)                  = NULL;
static void   (WINAPI *real_Sleep)(DWORD)                                               = NULL;
static DWORD  (WINAPI *real_SleepEx)(DWORD, BOOL)                                      = NULL;
static void   (WINAPI *real_D3DXCpuOptimizations)(BOOL)                                 = NULL;

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
/* Internal TCP server on private loopback port — serves fake Ubisoft XML */
/* ------------------------------------------------------------------ */

/* Saved before patch_iat — used by server thread and detach cleanup */
static int (WINAPI *orig_closesocket)(SOCKET) = NULL;

static SOCKET g_server_sock = INVALID_SOCKET;
static HANDLE g_server_ready_event = NULL;
static volatile LONG g_server_port = 0;
static HMODULE g_self_module = NULL;
static SOCKET g_last_redirect_socket = INVALID_SOCKET;
static DWORD  g_last_redirect_tick = 0;

enum {
    SERVER_NOT_STARTED = 0,
    SERVER_STARTING    = 1,
    SERVER_READY       = 2,
    SERVER_FAILED   = -1
};

static volatile LONG g_server_state = SERVER_NOT_STARTED;

static void set_server_state(LONG state) {
    InterlockedExchange(&g_server_state, state);
    if (g_server_ready_event)
        SetEvent(g_server_ready_event);
}

static DWORD WINAPI tcp_server_thread(LPVOID unused) {
    (void)unused;

    /* Keep a Winsock reference owned by this DLL. The game may balance its
     * own WSAStartup with WSACleanup before the LAN menu is opened; without
     * this reference that cleanup can invalidate our listener. */
    WSADATA wsa;
    int wsa_result = WSAStartup(MAKEWORD(2, 2), &wsa);
    if (wsa_result != 0) {
        DBG("server: WSAStartup failed (%d)", wsa_result);
        set_server_state(SERVER_FAILED);
        return 1;
    }

    SOCKET srv = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
    if (srv == INVALID_SOCKET) {
        DBG("server: socket() failed (%d)", WSAGetLastError());
        set_server_state(SERVER_FAILED);
        WSACleanup();
        return 1;
    }

    struct sockaddr_in addr;
    addr.sin_family      = AF_INET;
    addr.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
    /* Let Windows select a private per-process port. Port 3074 can remain
     * owned briefly by SCC's bootstrap process even after that PID vanishes. */
    addr.sin_port        = 0;

    if (real_bind(srv, (struct sockaddr *)&addr, sizeof(addr)) != 0) {
        DBG("server: bind() failed on private loopback port (%d)", WSAGetLastError());
        orig_closesocket(srv);
        set_server_state(SERVER_FAILED);
        WSACleanup();
        return 1;
    }
    if (listen(srv, 10) != 0) {
        DBG("server: listen() failed on private loopback port (%d)", WSAGetLastError());
        orig_closesocket(srv);
        set_server_state(SERVER_FAILED);
        WSACleanup();
        return 1;
    }

    {
        int addr_len = sizeof(addr);
        if (getsockname(srv, (struct sockaddr *)&addr, &addr_len) != 0 ||
            ntohs(addr.sin_port) == 0) {
            DBG("server: getsockname() failed (%d)", WSAGetLastError());
            orig_closesocket(srv);
            set_server_state(SERVER_FAILED);
            WSACleanup();
            return 1;
        }
        InterlockedExchange(&g_server_port, (LONG)ntohs(addr.sin_port));
    }

    g_server_sock = srv;
    set_server_state(SERVER_READY);
    DBG("server: listening on 127.0.0.1:%ld (pid=%lu tid=%lu socket=%lu)",
        InterlockedCompareExchange(&g_server_port, 0, 0),
        GetCurrentProcessId(), GetCurrentThreadId(), (unsigned long)srv);

    while (1) {
        SOCKET client = accept(srv, NULL, NULL);
        if (client == INVALID_SOCKET) {
            DBG("server: accept() stopped (%d)", WSAGetLastError());
            break;
        }
        DBG("server: accepted connection (socket=%lu)", (unsigned long)client);

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

    g_server_sock = INVALID_SOCKET;
    InterlockedExchange(&g_server_port, 0);
    set_server_state(SERVER_FAILED);
    WSACleanup();
    DBG("server: stopped");
    return 0;
}

static void start_tcp_server(void) {
    HANDLE t = CreateThread(NULL, 0, tcp_server_thread, NULL, 0, NULL);
    if (t) { CloseHandle(t); }
    else {
        DBG("ERROR: CreateThread for tcp_server_thread failed (%lu)", GetLastError());
        set_server_state(SERVER_FAILED);
    }
}

/* SCC starts a short-lived bootstrap process before the real game process.
 * Starting the listener from DllMain lets that bootstrap process keep 3074
 * occupied while the real process is loading. Start it only when this process
 * actually makes the GameConnect request. The CAS also makes simultaneous
 * non-blocking connect attempts share one listener and one ready event. */
static void ensure_tcp_server_started(void) {
    LONG previous = InterlockedCompareExchange(
        &g_server_state, SERVER_STARTING, SERVER_NOT_STARTED);

    if (previous == SERVER_NOT_STARTED) {
        DBG("server: lazy start requested (pid=%lu tid=%lu)",
            GetCurrentProcessId(), GetCurrentThreadId());

        /* The accept worker executes code from this DLL for the rest of the
         * process lifetime. Pin only now: bootstrap processes that never use
         * LAN can still unload the DLL normally and never create a worker. */
        {
            HMODULE pinned = NULL;
            if (!g_self_module ||
                !GetModuleHandleExA(GET_MODULE_HANDLE_EX_FLAG_FROM_ADDRESS |
                                    GET_MODULE_HANDLE_EX_FLAG_PIN,
                                    (LPCSTR)g_self_module, &pinned)) {
                DBG("server: failed to pin DLL (%lu)", GetLastError());
                set_server_state(SERVER_FAILED);
                return;
            }
        }
        start_tcp_server();
    }
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
            /* The bootstrap process never reaches this endpoint, so it never
             * owns 3074. In the real process wait until bind/listen is ready. */
            ensure_tcp_server_started();
            DWORD wait_result = g_server_ready_event
                ? WaitForSingleObject(g_server_ready_event, 5000)
                : WAIT_FAILED;
            LONG server_state = InterlockedCompareExchange(&g_server_state, 0, 0);

            if (wait_result != WAIT_OBJECT_0 || server_state != SERVER_READY) {
                int error = (wait_result == WAIT_TIMEOUT) ? WSAETIMEDOUT : WSAECONNREFUSED;
                DBG("connect: local server unavailable (wait=%lu state=%ld error=%d)",
                    wait_result, server_state, error);
                WSASetLastError(error);
                return SOCKET_ERROR;
            }

            LONG local_server_port = InterlockedCompareExchange(&g_server_port, 0, 0);
            if (local_server_port <= 0 || local_server_port > 65535) {
                DBG("connect: local server published invalid port (%ld)", local_server_port);
                WSASetLastError(WSAECONNREFUSED);
                return SOCKET_ERROR;
            }

            struct sockaddr_in bound;
            int bound_len = sizeof(bound);
            int socket_type = 0;
            int type_len = sizeof(socket_type);
            memset(&bound, 0, sizeof(bound));
            getsockname(s, (struct sockaddr *)&bound, &bound_len);
            getsockopt(s, SOL_SOCKET, SO_TYPE, (char *)&socket_type, &type_len);

            {
                DWORD src = ntohl(bound.sin_addr.s_addr);
                DWORD dst = ntohl(addr->sin_addr.s_addr);
                DBG("connect: socket=%lu type=%d local=%lu.%lu.%lu.%lu:%u original=%lu.%lu.%lu.%lu:3074",
                    (unsigned long)s, socket_type,
                    (src >> 24) & 0xff, (src >> 16) & 0xff,
                    (src >> 8) & 0xff, src & 0xff, ntohs(bound.sin_port),
                    (dst >> 24) & 0xff, (dst >> 16) & 0xff,
                    (dst >> 8) & 0xff, dst & 0xff);
            }

            struct sockaddr_in local;
            memset(&local, 0, sizeof(local));
            local.sin_family      = AF_INET;
            local.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
            local.sin_port        = htons((u_short)local_server_port);
            /* TCP_NODELAY: disable Nagle on loopback — no real RTT, only adds latency */
            BOOL nodelay = TRUE;
            setsockopt(s, IPPROTO_TCP, TCP_NODELAY, (const char *)&nodelay, sizeof(nodelay));
            g_last_redirect_socket = s;
            g_last_redirect_tick = GetTickCount();
            int r = real_connect(s, (struct sockaddr *)&local, sizeof(local));
            int error = (r == SOCKET_ERROR) ? WSAGetLastError() : 0;
            if (r == 0) {
                DBG("connect: redirected port 3074 to 127.0.0.1:%ld",
                    local_server_port);
            } else {
                if (error == WSAEWOULDBLOCK || error == WSAEINPROGRESS ||
                    error == WSAEALREADY)
                    DBG("connect: redirect pending (%d)", error);
                else
                    DBG("connect: redirect failed (%d)", error);
            }

            /* DBG/stdio and other Win32 calls may overwrite the thread's last
             * error. The game checks WSAGetLastError after non-blocking
             * connect(), so restore the exact result from real_connect. */
            if (r == SOCKET_ERROR)
                WSASetLastError(error);
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

            /* Enlarge receive buffer — default 8KB drops packets during CPU spikes.
             * 256KB gives the OS room to queue packets while the game is busy. */
            int rcvbuf = 256 * 1024;
            setsockopt(s, SOL_SOCKET, SO_RCVBUF, (const char *)&rcvbuf, sizeof(rcvbuf));

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
                    return real_bind(s, (struct sockaddr *)&patched, addrlen);
                }
            }
        } else if (port == 9103) {
            /* Enlarge receive buffer for gameplay traffic too */
            int rcvbuf = 256 * 1024;
            setsockopt(s, SOL_SOCKET, SO_RCVBUF, (const char *)&rcvbuf, sizeof(rcvbuf));
        }
    }
    return real_bind(s, addr, addrlen);
}

static int WINAPI my_recvfrom(SOCKET s, char *buf, int len, int flags,
                               struct sockaddr *from, int *fromlen) {
    int result = real_recvfrom(s, buf, len, flags, from, fromlen);
    if (result <= 0)
        return result;

    if (!udp46_is_tracked(s))
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

    if (num_ips < -1 || num_ips > 8) {
        return result;
    }

    if (num_ips <= 0) {
        if (result + 8 <= len) {
            memmove(payload + 0x5c + 8, payload + 0x5c, result - 0x5c);
            memcpy(payload + 0x5c, ip_field, 8);
            result += 8;
        }
    } else if (num_ips >= 2) {
        if (payload[0x5c] != 0x07) {
            return result;
        }
        int tail_src = 0x5c + num_ips * 8;
        if (tail_src > result) return result;
        memmove(payload + 0x5c + 8, payload + tail_src, result - tail_src);
        memcpy(payload + 0x5c, ip_field, 8);
        result -= (num_ips - 1) * 8;
    } else {
        if (payload[0x5c] != 0x07) {
            return result;
        }
        memcpy(payload + 0x5c, ip_field, 8);
    }

    payload[0x5b] = 2;
    return result;
}

static int WINAPI my_closesocket(SOCKET s) {
    int was_redirected = (s == g_last_redirect_socket);
    DWORD redirect_lifetime = was_redirected
        ? GetTickCount() - g_last_redirect_tick
        : 0;

    udp46_remove(s);
    int result = real_closesocket(s);
    int error = WSAGetLastError();

    if (was_redirected) {
        g_last_redirect_socket = INVALID_SOCKET;
        DBG("connect: redirected socket closed after %lu ms (result=%d error=%d)",
            redirect_lifetime, result, error);
        WSASetLastError(error);
    }

    return result;
}

/* Precision sleep: coarse Sleep() + spin-wait on last 2 ms.
 * Sleep(N) on Windows can overshoot by 10-15 ms even with timeBeginPeriod(1).
 *
 * Safety filters:
 *  - Sleep(0)       — yield semantics, pass through
 *  - Sleep(INFINITE)— worker thread wait, pass through (never wake early!)
 *  - ms < 10        — short sleeps, pass through (audio, timers)
 *  - ms > 100       — long sleeps, pass through (loading screens, idle)
 * Only 10-100 ms range (frame-rate sleeps: 16ms=60fps, 33ms=30fps) gets spin.
 *
 * QPC start is captured BEFORE coarse sleep so spin measures total elapsed
 * time, not just post-wake time (avoids sleeping 2x the requested duration). */
static LONGLONG g_qpc_freq = 0; /* cached — constant at runtime */

static void WINAPI my_Sleep(DWORD ms) {
    if (!real_Sleep) return;
    if (ms == 0 || ms == INFINITE || ms < 10 || ms > 100) {
        real_Sleep(ms);
        return;
    }
    /* Cache QPC frequency — constant, queried once */
    if (!g_qpc_freq) {
        LARGE_INTEGER f;
        QueryPerformanceFrequency(&f);
        g_qpc_freq = f.QuadPart;
    }
    /* Snapshot time BEFORE coarse sleep — spin is measured from total start */
    LARGE_INTEGER start;
    QueryPerformanceCounter(&start);

    real_Sleep(ms - 2);

    /* Spin-wait until full ms has elapsed from start */
    LARGE_INTEGER now;
    LONGLONG target = (LONGLONG)ms * g_qpc_freq / 1000;
    do {
        QueryPerformanceCounter(&now);
    } while ((now.QuadPart - start.QuadPart) < target);
}

/* SleepEx — same precision treatment as Sleep; bAlertable pass-through when alertable */
static DWORD WINAPI my_SleepEx(DWORD ms, BOOL alertable) {
    if (!real_SleepEx) return 0;
    if (alertable || ms == 0 || ms == INFINITE || ms < 10 || ms > 100)
        return real_SleepEx(ms, alertable);
    if (!g_qpc_freq) {
        LARGE_INTEGER f;
        QueryPerformanceFrequency(&f);
        g_qpc_freq = f.QuadPart;
    }
    LARGE_INTEGER start;
    QueryPerformanceCounter(&start);
    real_SleepEx(ms - 2, FALSE);
    LARGE_INTEGER now;
    LONGLONG target = (LONGLONG)ms * g_qpc_freq / 1000;
    do {
        QueryPerformanceCounter(&now);
    } while ((now.QuadPart - start.QuadPart) < target);
    return 0;
}

static BOOL WINAPI my_SetProcessAffinityMask(HANDLE hProcess, DWORD_PTR mask) {
    if (!real_SetProcessAffinityMask) {
        SetLastError(ERROR_PROC_NOT_FOUND);
        return FALSE;
    }
    /* Override mask=1 to 4 cores (0xF) — Conviction shipped targeting quad-core CPUs.
     * Multiplayer locks to 30fps via its own internal network rate limiter regardless
     * of core count; 60fps after disconnect is the game returning to single-player mode.
     * If 60fps appears mid-game in multiplayer, change 0xF -> 0x3 to limit to 2 cores. */
    if (mask == 1)
        return real_SetProcessAffinityMask(hProcess, 0xF);
    return real_SetProcessAffinityMask(hProcess, mask);
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

    if (num_ips < -1 || num_ips > 8) {
        return result;
    }

    if (num_ips <= 0) {
        if (r + 8 <= (int)bufs[0].len) {
            memmove(payload + 0x5c + 8, payload + 0x5c, r - 0x5c);
            memcpy(payload + 0x5c, ip_field, 8);
            r += 8;
        }
    } else if (num_ips >= 2) {
        if (payload[0x5c] != 0x07) {
            return result;
        }
        int tail_src = 0x5c + num_ips * 8;
        if (tail_src > r) return result;
        memmove(payload + 0x5c + 8, payload + tail_src, r - tail_src);
        memcpy(payload + 0x5c, ip_field, 8);
        r -= (num_ips - 1) * 8;
    } else {
        if (payload[0x5c] != 0x07) {
            return result;
        }
        memcpy(payload + 0x5c, ip_field, 8);
    }

    payload[0x5b] = 2;
    *bytes_recv = (DWORD)r;
    return 0;
}

/* ------------------------------------------------------------------ */
/* Pattern scanner                                                     */
/* ------------------------------------------------------------------ */

/* Parse "AB CD ? EF" mask pattern. Returns matched address or NULL.
 * '?' matches any byte. Scans the entire module image. */
static BYTE *pattern_scan(BYTE *base, SIZE_T size, const char *pattern) {
    /* Parse pattern into bytes + wildcard mask */
    unsigned char bytes[256];
    unsigned char wild[256];
    int len = 0;

    const char *p = pattern;
    while (*p && len < 256) {
        while (*p == ' ') p++;
        if (!*p) break;
        if (p[0] == '?' && (p[1] == '?' || p[1] == ' ' || !p[1])) {
            bytes[len] = 0;
            wild[len]  = 1;
            len++;
            p++;
            if (*p == '?') p++;
        } else if (p[0] && p[1]) {
            char h[3] = { p[0], p[1], 0 };
            bytes[len] = (unsigned char)strtoul(h, NULL, 16);
            wild[len]  = 0;
            len++;
            p += 2;
        } else {
            break;
        }
    }
    if (len == 0) return NULL;

    for (SIZE_T i = 0; i + (SIZE_T)len <= size; i++) {
        int match = 1;
        for (int j = 0; j < len; j++) {
            if (!wild[j] && base[i + j] != bytes[j]) { match = 0; break; }
        }
        if (match) return base + i;
    }
    return NULL;
}

/* Write bytes to read-only memory using VirtualProtect */
static void mem_write(void *dst, const void *src, SIZE_T n) {
    DWORD old;
    VirtualProtect(dst, n, PAGE_EXECUTE_READWRITE, &old);
    memcpy(dst, src, n);
    VirtualProtect(dst, n, old, &old);
}

/* NOP n bytes at dst */
static void mem_nop(void *dst, SIZE_T n) {
    DWORD old;
    VirtualProtect(dst, n, PAGE_EXECUTE_READWRITE, &old);
    memset(dst, 0x90, n);
    VirtualProtect(dst, n, old, &old);
}

/* ------------------------------------------------------------------ */
/* Game patches — exe in-memory byte patches                          */
/* ------------------------------------------------------------------ */

static void apply_game_patches(void) {
    BYTE *base = (BYTE *)GetModuleHandleA(NULL);
    if (!base) return;

    /* Get module size from PE header */
    IMAGE_DOS_HEADER *dos = (IMAGE_DOS_HEADER *)base;
    if (dos->e_magic != IMAGE_DOS_SIGNATURE) return;
    IMAGE_NT_HEADERS *nt = (IMAGE_NT_HEADERS *)(base + dos->e_lfanew);
    if (nt->Signature != IMAGE_NT_SIGNATURE) return;
    SIZE_T img_size = nt->OptionalHeader.SizeOfImage;

    /* ---- Patch: Disable Uplay connection requirement ----
     * JZ -> JMP: skips Uplay initialization block.
     * Without this the game may hang waiting for Ubisoft servers. */
    {
        BYTE *addr = pattern_scan(base, img_size,
            "74 28 E8 ? ? ? ? 8B 10 8B C8 FF 92 ? ? ? ? 3B C3");
        if (addr) {
            BYTE b = 0xEB;
            mem_write(addr, &b, 1);
            DBG("game_patch: uplay bypass applied at %p", (void*)addr);
        } else {
            DBG("game_patch: uplay bypass pattern not found");
        }
    }

    /* ---- Patch: Achievement unlock crash fix ----
     * Replace sub_4D6DD5 start with xor eax,eax / ret.
     * Without Uplay the achievement system crashes when trying to unlock. */
    {
        BYTE *addr = pattern_scan(base, img_size,
            "56 8B F1 0F B6 46 ? 50 8B 46");
        if (addr) {
            /* xor eax,eax (2 bytes) + ret (1 byte) */
            BYTE patch[] = { 0x33, 0xC0, 0xC3 };
            mem_write(addr, patch, sizeof(patch));
            DBG("game_patch: achievement crash fix applied at %p", (void*)addr);
        } else {
            DBG("game_patch: achievement crash pattern not found");
        }
    }

    /* ---- Patch: Skip intro videos ----
     * Write RET at the intro-play function start. */
    {
        BYTE *addr = pattern_scan(base, img_size,
            "55 8D 6C 24 88 81 EC ? ? ? ? A1 ? ? ? ? 33 C5 89 45 74 53 56 57 BE ? ? ? ? 68 ? ? ? ? 8B CE E8 ? ? ? ? E8 ? ? ? ? 50");
        if (addr) {
            BYTE b = 0xC3;
            mem_write(addr, &b, 1);
            DBG("game_patch: skip intro applied at %p", (void*)addr);
        } else {
            DBG("game_patch: skip intro pattern not found");
        }
    }

    /* ---- Patch: Force Xbox 360 controller scheme ----
     * NOP 14 bytes: removes two 16-bit comparisons that select controller type. */
    {
        BYTE *addr = pattern_scan(base, img_size,
            "66 81 FF ? ? 75 0E 66 81 FE ? ? 75 13");
        if (addr) {
            mem_nop(addr, 14);
            DBG("game_patch: force X360 controller applied at %p", (void*)addr);
        } else {
            DBG("game_patch: force X360 controller pattern not found");
        }
    }

    /* ---- Patch: DLC unlock ----
     * Multiple patches to bypass DLC ownership checks. */
    {
        int count = 0;

        /* UEPECInventory check 1 */
        BYTE *addr = pattern_scan(base, img_size,
            "74 15 FF 74 24 08 8B CE E8 ? ? ? ? 8B 40 08");
        if (addr) { BYTE b = 0xEB; mem_write(addr, &b, 1); count++; }

        /* UEPECInventory check 2 */
        addr = pattern_scan(base, img_size,
            "74 15 FF 74 24 08 8B CE E8 ? ? ? ? 8B 40 04 F7 D0");
        if (addr) { BYTE b = 0xEB; mem_write(addr, &b, 1); count++; }

        /* MenuUniformSelect */
        addr = pattern_scan(base, img_size, "75 25 FF 75 FC");
        if (addr) { BYTE b = 0xEB; mem_write(addr, &b, 1); count++; }

        /* MapConfigurationDLC.xml check 1 */
        addr = pattern_scan(base, img_size, "0F 85 ? ? ? ? 39 7D EC");
        if (addr) { mem_nop(addr, 6); count++; }

        /* MapConfigurationDLC.xml check 2 */
        addr = pattern_scan(base, img_size, "0F 84 ? ? ? ? 8D 45 E8 50 8B CB");
        if (addr) { mem_nop(addr, 6); count++; }

        /* UEChallengeProfileExternal1 — challenge profile DLC bit check.
         * MOV EAX,[ECX+7C] / SHR EAX,1 / NOT EAX = reads and inverts DLC bit.
         * FusionFix NOPs 10 bytes + mid-hook sets EAX=0. Same effect:
         * XOR EAX,EAX (2 bytes) + 8 NOPs = EAX forced to 0 at this point. */
        addr = pattern_scan(base, img_size, "8B 41 7C D1 E8 F7 D0");
        if (addr) {
            BYTE patch[10] = { 0x33, 0xC0, 0x90, 0x90, 0x90, 0x90, 0x90, 0x90, 0x90, 0x90 };
            mem_write(addr, patch, sizeof(patch));
            count++;
        }

        /* UEChallengeProfileExternal2 — same as above, different shift.
         * MOV EAX,[ECX+7C] / SHR EAX,3 = reads DLC bit with different shift.
         * FusionFix NOPs 11 bytes + mid-hook sets EAX=0. Same effect:
         * XOR EAX,EAX (2 bytes) + 9 NOPs. */
        addr = pattern_scan(base, img_size, "8B 41 7C C1 E8 03");
        if (addr) {
            BYTE patch[11] = { 0x33, 0xC0, 0x90, 0x90, 0x90, 0x90, 0x90, 0x90, 0x90, 0x90, 0x90 };
            mem_write(addr, patch, sizeof(patch));
            count++;
        }

        /* DLC map configuration JMP redirect.
         * Redirects a code path so DLC map config is always loaded.
         * Both patterns must be found — if either is missing, skip entirely. */
        {
            BYTE *src = pattern_scan(base, img_size, "7E 50 8B 45 E8");
            BYTE *dst = pattern_scan(base, img_size,
                "8B 0D ? ? ? ? 8B 01 57 FF 35 ? ? ? ? 57 68 ? ? ? ? FF 50 10 8B D8");
            if (src && dst) {
                INT32 rel32 = (INT32)(dst - (src + 5));
                BYTE jmp[5] = { 0xE9, 0x00, 0x00, 0x00, 0x00 };
                memcpy(jmp + 1, &rel32, 4);
                mem_write(src, jmp, 5);
                count++;
            }
        }

        DBG("game_patch: DLC unlock applied %d/8 patches", count);
    }
}

/* ------------------------------------------------------------------ */
/* Runtime exe patches — fix known crashes in conviction_game.exe    */
/* ------------------------------------------------------------------ */

static void apply_exe_patches(void) {
    BYTE *base = (BYTE *)GetModuleHandleA(NULL);
    if (!base) return;

    /* The DLL can also be loaded by launch/bootstrap helpers. Never probe a
     * game-specific RVA unless it is inside this process's executable image. */
    IMAGE_DOS_HEADER *dos = (IMAGE_DOS_HEADER *)base;
    if (dos->e_magic != IMAGE_DOS_SIGNATURE) return;
    IMAGE_NT_HEADERS *nt = (IMAGE_NT_HEADERS *)(base + dos->e_lfanew);
    if (nt->Signature != IMAGE_NT_SIGNATURE) return;

    /* ---- Patch 1: NULL sub-object crash at RVA 0x7C41AA ----
     *
     * Function at 0x00BC4170 checks this->field_4:
     *   == 2 -> return 2
     *   == 1 -> return 1
     *   else -> MOV ECX, [EDI+24h]  ; load sub-object pointer
     *           MOV EDX, [ECX]      ; CRASH if field_24h == NULL
     *
     * During certain state transitions field_24h is NULL while field_4
     * is not yet reset to 1/2, causing a reproducible access violation.
     *
     * Fix: trampoline that returns 0 when field_24h == NULL.
     */
    {
        SIZE_T patch_rva = 0x00BC41AA - 0x00400000;
        BYTE *patch;
        BYTE  expected[] = { 0x8B, 0x4F, 0x24, 0x8B, 0x11 }; /* MOV ECX,[EDI+24h]; MOV EDX,[ECX] */

        if (patch_rva + sizeof(expected) > nt->OptionalHeader.SizeOfImage) {
            DBG("exe_patch1: target RVA outside executable image, skipping");
            return;
        }
        patch = base + patch_rva;

        if (memcmp(patch, expected, 5) != 0) {
            DBG("exe_patch1: bytes at +7C41AA don't match — wrong exe version, skipping");
            return;
        }

        /* Trampoline layout (23 bytes):
         *  +00  8b 4f 24        MOV ECX, [EDI+24h]
         *  +03  85 c9           TEST ECX, ECX
         *  +05  75 09           JNZ +9  -> non-NULL path at +10h
         *  +07  33 c0           XOR EAX, EAX       ; return 0
         *  +09  5f              POP EDI
         *  +0a  83 c4 14        ADD ESP, 14h
         *  +0d  c2 0c 00        RET 0Ch
         *  +10  8b 11           MOV EDX, [ECX]      ; original instruction
         *  +12  e9 XX XX XX XX  JMP -> patch+5 (0x00BC41AF)
         */
        BYTE *tramp = (BYTE *)VirtualAlloc(NULL, 32,
                              MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE);
        if (!tramp) {
            DBG("exe_patch1: VirtualAlloc failed (%lu)", GetLastError());
            return;
        }

        BYTE *p = tramp;
        *p++ = 0x8B; *p++ = 0x4F; *p++ = 0x24; /* MOV ECX, [EDI+24h] */
        *p++ = 0x85; *p++ = 0xC9;               /* TEST ECX, ECX      */
        *p++ = 0x75; *p++ = 0x09;               /* JNZ +9             */
        *p++ = 0x33; *p++ = 0xC0;               /* XOR EAX, EAX       */
        *p++ = 0x5F;                             /* POP EDI            */
        *p++ = 0x83; *p++ = 0xC4; *p++ = 0x14;  /* ADD ESP, 14h       */
        *p++ = 0xC2; *p++ = 0x0C; *p++ = 0x00;  /* RET 0Ch            */
        *p++ = 0x8B; *p++ = 0x11;               /* MOV EDX, [ECX]     */
        {
            BYTE  *ret_addr = patch + 5; /* 0x00BC41AF */
            INT32  rel32    = (INT32)(ret_addr - (p + 5));
            *p++ = 0xE9; memcpy(p, &rel32, 4); p += 4;
        }

        /* Overwrite original 5 bytes with JMP to trampoline */
        DWORD old_prot;
        VirtualProtect(patch, 5, PAGE_EXECUTE_READWRITE, &old_prot);
        {
            INT32 rel32 = (INT32)(tramp - (patch + 5));
            patch[0] = 0xE9; memcpy(patch + 1, &rel32, 4);
        }
        VirtualProtect(patch, 5, old_prot, &old_prot);

        DBG("exe_patch1: applied NULL guard at +7C41AA (trampoline=%p)", (void*)tramp);
    }
}

/* ------------------------------------------------------------------ */
/* IAT patch — replaces function pointers in the game's import table  */
/* ------------------------------------------------------------------ */

/* D3DXCpuOptimizations — force OFF for cross-CPU-vendor determinism.
 *
 * conviction_game.exe imports D3DXVec3Normalize / D3DXVec3TransformCoord /
 * D3DXVec3TransformNormal and calls D3DXCpuOptimizations. With CPU
 * optimizations enabled, D3DX picks vendor-specific SSE/3DNow code paths whose
 * fast reciprocal-sqrt differs bit-for-bit between Intel and AMD. In the
 * deterministic co-op simulation that divergence compounds through the
 * position-integration feedback loop and desyncs the moment a player walks
 * (instantaneous actions — aim/shoot/crouch — don't accumulate, so they don't
 * trip it). Forcing FALSE makes both machines use the identical reference C
 * path regardless of CPU. Harmless otherwise: slightly slower helper math. */
static void WINAPI my_D3DXCpuOptimizations(BOOL enable) {
    (void)enable;
    if (real_D3DXCpuOptimizations) {
        real_D3DXCpuOptimizations(FALSE);
        DBG("d3dx: forced D3DXCpuOptimizations(FALSE) (game requested %d)", enable);
    }
}

typedef struct {
    const char *name;
    WORD        ordinal; /* ws2_32.dll ordinal (0 = not imported by ordinal) */
    void       *hook;
    void      **original;
} Hook;

static Hook hooks_ws2[] = {
    { "connect",     4,  my_connect,     (void **)&real_connect     },
    { "bind",        2,  my_bind,        (void **)&real_bind         },
    { "recvfrom",   17,  my_recvfrom,    (void **)&real_recvfrom     },
    { "closesocket", 3,  my_closesocket, (void **)&real_closesocket  },
    { "WSARecvFrom", 93, my_WSARecvFrom, (void **)&real_WSARecvFrom  },
};
#define NUM_HOOKS_WS2 (sizeof(hooks_ws2) / sizeof(hooks_ws2[0]))

static Hook hooks_kernel32[] = {
    { "SetProcessAffinityMask", 0, my_SetProcessAffinityMask, (void **)&real_SetProcessAffinityMask },
    { "Sleep",                  0, my_Sleep,                  (void **)&real_Sleep                  },
    { "SleepEx",                0, my_SleepEx,                (void **)&real_SleepEx                },
};
#define NUM_HOOKS_KERNEL32 (sizeof(hooks_kernel32) / sizeof(hooks_kernel32[0]))

static Hook hooks_d3dx10[] = {
    { "D3DXCpuOptimizations", 0, my_D3DXCpuOptimizations, (void **)&real_D3DXCpuOptimizations },
};
#define NUM_HOOKS_D3DX10 (sizeof(hooks_d3dx10) / sizeof(hooks_d3dx10[0]))

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

        Hook *hook_table = NULL;
        int   hook_count = 0;

        if (_stricmp(dll_name, "ws2_32.dll")  == 0 ||
            _stricmp(dll_name, "wsock32.dll") == 0) {
            hook_table = hooks_ws2;
            hook_count = (int)NUM_HOOKS_WS2;
        } else if (_stricmp(dll_name, "kernel32.dll") == 0) {
            hook_table = hooks_kernel32;
            hook_count = (int)NUM_HOOKS_KERNEL32;
        } else if (_stricmp(dll_name, "d3dx10_41.dll") == 0) {
            hook_table = hooks_d3dx10;
            hook_count = (int)NUM_HOOKS_D3DX10;
        } else {
            continue;
        }

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
                for (int i = 0; i < hook_count; i++) {
                    if (hook_table[i].ordinal == 0 || hook_table[i].ordinal != ord)
                        continue;
                    if (*hook_table[i].original == NULL)
                        *hook_table[i].original = (void *)iat_thunk->u1.Function;
                    DWORD old_protect;
                    VirtualProtect(&iat_thunk->u1.Function,
                                   sizeof(void *), PAGE_READWRITE, &old_protect);
                    iat_thunk->u1.Function = (ULONG_PTR)hook_table[i].hook;
                    VirtualProtect(&iat_thunk->u1.Function,
                                   sizeof(void *), old_protect, &old_protect);
                    DBG("  PATCHED ordinal %u -> %s", (unsigned)ord, hook_table[i].name);
                }
                continue;
            }

            IMAGE_IMPORT_BY_NAME *by_name =
                (IMAGE_IMPORT_BY_NAME *)(base + orig_thunk->u1.AddressOfData);

            for (int i = 0; i < hook_count; i++) {
                if (_stricmp((char *)by_name->Name, hook_table[i].name) != 0)
                    continue;

                if (*hook_table[i].original == NULL)
                    *hook_table[i].original = (void *)iat_thunk->u1.Function;

                DWORD old_protect;
                VirtualProtect(&iat_thunk->u1.Function,
                               sizeof(void *), PAGE_READWRITE, &old_protect);
                iat_thunk->u1.Function = (ULONG_PTR)hook_table[i].hook;
                VirtualProtect(&iat_thunk->u1.Function,
                               sizeof(void *), old_protect, &old_protect);
                DBG("  PATCHED: %s", hook_table[i].name);
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
    if (fdwReason == DLL_PROCESS_ATTACH) {
        g_self_module = hinstDLL;
        log_init();
        DBG("=== systemdetection.dll loaded ===");
        timeBeginPeriod(1);
        InitializeCriticalSection(&udp46_lock);
        udp46_socket_count = 0;

        /* ws2_32 is already a static dependency of this DLL. Reuse its loaded
         * module instead of changing loader reference counts from DllMain. */
        real_ws2 = GetModuleHandleA("ws2_32.dll");
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

        /* Created in DllMain, but no server thread or socket is started here.
         * The short-lived bootstrap process therefore cannot occupy 3074. */
        g_server_ready_event = CreateEventA(NULL, TRUE, FALSE, NULL);
        if (!g_server_ready_event) {
            DBG("ERROR: CreateEvent for TCP server failed (%lu)", GetLastError());
            InterlockedExchange(&g_server_state, SERVER_FAILED);
        }

        /* Resolve kernel32 functions — needed as fallback even if IAT hook not found */
        HMODULE k32 = GetModuleHandleA("kernel32.dll");
        if (k32) {
            real_SetProcessAffinityMask =
                (BOOL (WINAPI *)(HANDLE, DWORD_PTR))GetProcAddress(k32, "SetProcessAffinityMask");
            real_Sleep   = (void  (WINAPI *)(DWORD))       GetProcAddress(k32, "Sleep");
            real_SleepEx = (DWORD (WINAPI *)(DWORD, BOOL)) GetProcAddress(k32, "SleepEx");
            DBG("real_SetProcessAffinityMask=%p real_Sleep=%p real_SleepEx=%p",
                (void*)real_SetProcessAffinityMask, (void*)real_Sleep, (void*)real_SleepEx);
        }

        /* Patch the game's IAT */
        DBG("calling patch_iat...");
        patch_iat();
        DBG("patch_iat done");
        DBG("hooks patched: connect bind recvfrom closesocket WSARecvFrom SetProcessAffinityMask Sleep");

        /* Force D3DX onto the vendor-neutral reference math path for co-op
         * determinism. The IAT hook already catches the game's own call, but if
         * d3dx10_41.dll is already loaded, assert it now too (covers the case
         * where the game relies on the default, which is optimizations ON). */
        {
            HMODULE d3dx = GetModuleHandleA("d3dx10_41.dll");
            if (d3dx) {
                if (!real_D3DXCpuOptimizations)
                    real_D3DXCpuOptimizations =
                        (void (WINAPI *)(BOOL))GetProcAddress(d3dx, "D3DXCpuOptimizations");
                if (real_D3DXCpuOptimizations) {
                    real_D3DXCpuOptimizations(FALSE);
                    DBG("d3dx: D3DXCpuOptimizations(FALSE) asserted at load");
                }
            } else {
                DBG("d3dx: d3dx10_41.dll not yet loaded — relying on IAT hook");
            }
        }

        /* Patch known crash sites directly in exe memory */
        apply_exe_patches();

        /* Game behaviour patches: uplay bypass, achievement crash fix,
         * skip intro, force X360 controller, DLC unlock */
        apply_game_patches();

        /* Raise process priority slightly — helps on Steam Deck / low-power systems.
         * ABOVE_NORMAL is safe: less aggressive than HIGH, won't starve audio/compositor */
        SetPriorityClass(GetCurrentProcess(), ABOVE_NORMAL_PRIORITY_CLASS);
        DBG("process priority set to ABOVE_NORMAL");

        /* Disable Windows 11 EcoQoS / Power Throttling for this process.
         * Without this, Windows may silently throttle old exes it deems "background".
         * Dynamic lookup — struct/constants not in older MinGW headers. */
        {
            typedef struct {
                ULONG Version;
                ULONG ControlMask;
                ULONG StateMask;
            } MY_PROCESS_POWER_THROTTLING_STATE;
            typedef BOOL (WINAPI *SetProcessInfo_t)(HANDLE, DWORD, LPVOID, DWORD);
            HMODULE kern = GetModuleHandleA("kernel32.dll");
            SetProcessInfo_t spi = kern
                ? (SetProcessInfo_t)GetProcAddress(kern, "SetProcessInformation")
                : NULL;
            if (spi) {
                MY_PROCESS_POWER_THROTTLING_STATE state;
                state.Version     = 1;   /* PROCESS_POWER_THROTTLING_CURRENT_VERSION */
                state.ControlMask = 0x1; /* PROCESS_POWER_THROTTLING_EXECUTION_SPEED */
                state.StateMask   = 0;   /* 0 = disable throttling */
                if (spi(GetCurrentProcess(), 4 /* ProcessPowerThrottling */,
                        &state, sizeof(state))) {
                    DBG("EcoQoS/power throttling disabled");
                } else {
                    DBG("SetProcessInformation failed (%lu) — older Windows, no-op", GetLastError());
                }
            } else {
                DBG("SetProcessInformation not available — pre-Win10, skipping EcoQoS");
            }
        }

        /* Install crash dump handler — writes crash.dmp next to exe on unhandled exception.
         * Only active when log.txt exists (same opt-in marker as debug log). */
        install_crash_handler();

    } else if (fdwReason == DLL_PROCESS_DETACH) {
        /* On process termination Windows has already stopped other threads
         * and will reclaim handles/sockets. Avoid touching worker-owned state.
         * lpvReserved==NULL is the safe explicit-unload path; a process that
         * started the server is pinned and cannot reach it via FreeLibrary. */
        if (lpvReserved != NULL)
            return TRUE;

        DBG("=== systemdetection.dll unloading ===");
        timeEndPeriod(1);
        if (g_server_sock != INVALID_SOCKET && orig_closesocket) {
            orig_closesocket(g_server_sock);
            g_server_sock = INVALID_SOCKET;
        }
        if (g_server_ready_event) {
            CloseHandle(g_server_ready_event);
            g_server_ready_event = NULL;
        }
        DeleteCriticalSection(&udp46_lock);
        if (g_log) { fclose(g_log); g_log = NULL; }
    }

    return TRUE;
}
