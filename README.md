# Splinter Cell: Conviction LAN Fix

Fixes LAN multiplayer in Splinter Cell: Conviction on Windows and Steam Deck/Linux.

Just drop one DLL next to the game.

## Installation

1. Copy `systemdetection.dll` next to `conviction_game.exe`
2. Launch the game — LAN multiplayer works

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
- [Radmin VPN](https://www.radmin-vpn.com) — free, Windows only

## Troubleshooting

Create an empty file named `network_log.txt` next to `conviction_game.exe` — the DLL will write a log there on next launch.

## Building from source

**Windows (Visual Studio Build Tools):**
```
build.bat
```

**Linux/Steam Deck (MinGW):**
```
make
```
