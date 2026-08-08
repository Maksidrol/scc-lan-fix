# Splinter Cell: Conviction LAN Fix

Fixes LAN multiplayer in Splinter Cell: Conviction on Windows and Steam Deck/Linux, with additional stability improvements and game patches.

Just drop one DLL next to the game.

## What it fixes

| Component | Result |
|---|---|
| Local matchmaking server (127.0.0.1:3074) | Game works without Ubisoft servers |
| connect() redirect to localhost | LAN sessions work |
| recvfrom/WSARecvFrom IP patch | Other players are visible in LAN lobby |
| SO_RCVBUF 256KB (ports 46000, 9103) | No packet loss under CPU load |
| Precision Sleep/SleepEx | Stable framerate in multiplayer |
| SetProcessAffinityMask (1→4 cores) | No freezes on modern multi-core CPUs |
| ABOVE_NORMAL process priority | Stable performance on low-end systems and Steam Deck |
| EcoQoS / Power Throttling disabled | Windows 11 does not throttle the game in the background |
| NULL pointer crash fix | No crash during game state transitions |
| Uplay bypass | Game runs without connecting to Ubisoft |
| Achievement crash fix | No crash when unlocking achievements |
| Skip intro videos | Launches directly to menu without logo screens |
| DLC unlock | All maps, outfits and challenges are available |
| Force Xbox 360 controller | Correct button layout on all gamepads |
| Crash dump (crash.dmp) | A dump file is created on crash for diagnostics |

## Installation

1. Copy `systemdetection.dll` next to `conviction_game.exe`
2. Launch the game — LAN multiplayer works, stability improvements and game patches apply automatically

## Steam Deck / Linux

Works out of the box via Proton.

If other players can't see your session, the game may be broadcasting on the wrong network interface. Fix it with one of these:

**Option 1 — Steam launch options:**
```
SCC_BIND_IP=10.x.x.x %command%
```

**Option 2 — `my_ip.txt` file:**  
Create `my_ip.txt` next to `conviction_game.exe` and put your IP on the first line:
```
10.147.20.5
```

If neither is set, the DLL auto-detects the best interface using the routing table.

## Playing over the internet

LAN sessions are local network only. To play with someone in another location use a VPN that creates a virtual LAN:

- [ZeroTier](https://www.zerotier.com) — free, works on Steam Deck
- [Tailscale](https://tailscale.com) — free, easiest setup, works on Steam Deck
- [Radmin VPN](https://www.radmin-vpn.com) — free, Windows only

## Troubleshooting

Create an empty file named `log.txt` next to `conviction_game.exe` — the DLL will write a debug log there on next launch. If the game crashes, a `crash.dmp` file will also be created in the same folder.

## Building from source

**Windows (Visual Studio Build Tools):**
```
build.bat
```

**Linux/Steam Deck (MinGW):**
```
make
```
