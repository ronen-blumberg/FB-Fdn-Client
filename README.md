# khn-client-fb — kolhaam-network client for FreeBASIC + libvt

A native, GUI-windowed [kolhaam-network](https://github.com/ronen-blumberg/kolhaam-network) client written in
FreeBASIC on top of [libvt](https://github.com/rbreitinger/libvt).
Wire-compatible with the reference `client.c` / `client.py` and either
`server.c` / `server.py`: any combination of clients and servers can
interoperate.

Source: [`khn-client-fb.bas`](khn-client-fb.bas).
Binary (after build): `./khn-client-fb`.

---

## Requirements

- **FreeBASIC 1.10.1** or newer
- **libvt** installed in FreeBASIC's include path
  (`/usr/local/include/freebasic/vt/vt.bi` on Linux)
- **SDL2** (`libsdl2-dev` on Debian/Ubuntu) — libvt renders into an SDL2 window
- A graphical desktop (X11 or Wayland); the client opens its own window

Standard library only otherwise — no extra FB libraries to install.

---

## Building

```sh
fbc khn-client-fb.bas
```

The `#cmdline` directive at the top of the source already sets
`-s gui -w all -gen gcc -O 2`, so a plain `fbc` is enough. Output is a
single executable, `khn-client-fb`, in the current directory.

---

## Running

```
khn-client-fb [--big] <server> <port> <keyphrase> [<nickname>] [<room>]
```

| Argument     | Meaning                                                    |
|--------------|------------------------------------------------------------|
| `--big`/`-b` | Use the 16×24 font (default is 8×16). Place anywhere.      |
| `--small`/`-s` | Force the 8×16 font (this is the default).               |
| `<server>`   | Host name or IP of the kolhaam-network server.                 |
| `<port>`     | TCP port (1..65535).                                       |
| `<keyphrase>`| Shared secret used to derive the AES-256 key. Required.    |
| `<nickname>` | Optional. `""` (empty) → server picks a random nick.       |
| `<room>`     | Optional. `""` (empty) → server places you in some room.   |

Examples:

```sh
# Local server, you supply everything
./khn-client-fb 127.0.0.1 6667 'midnight-in-the-garden' alice main

# Public server, anonymous (server picks nick + room)
./khn-client-fb kolhaam-network.tech 5190 'midnight-in-the-garden' "" ""

# Same, with the larger font for a Hi-DPI display
./khn-client-fb --big kolhaam-network.tech 5190 'midnight-in-the-garden' alice main
```

A short pause on connect is normal — the keyphrase goes through 100 000
SHA-256 iterations to derive the AES-256 session key, as defined by the
kolhaam-network protocol.

---

## The window

```
+----------------------------------------------------------------+
| kolhaam-network 0.1.2  -  alice  @  main                           |  ← title bar
|----------------------------------------------------------------|
| [12:34] kolhaam-network 0.1.2 - FreeBASIC client                   |
| [12:34] Connected as "alice" in room "main".                   |  ← chat history
| [12:34] [main] users (2): alice, bob                           |    (scrollable)
| [12:35] [main] bob: hey alice                                  |
| ...                                                            |
|----------------------------------------------------------------|
| alice> _                                                       |  ← input line
| Rooms: main   F1 help  F10 quit                                |  ← status bar
+----------------------------------------------------------------+
```

The chat history is a 1000-line ring buffer; long lines are word-wrapped
at the screen width. Each line is timestamped `[HH:MM]` (dim grey) and
colourised by kind: chat (green), your own messages (yellow), emotes
(magenta), DMs (blue), file transfers (bright magenta), system/errors
(yellow/red).

The window is freely resizable down to **60 columns × 20 rows**; the
layout reflows automatically.

---

## Keys and mouse

| Key / button   | Action                                                  |
|----------------|---------------------------------------------------------|
| **Enter**      | Send the current input line.                            |
| **F1**         | Print the command list into the chat area.              |
| **F10**        | Quit cleanly (`QUIT` packet + close socket).            |
| **PgUp**       | Scroll history up 3 lines.                              |
| **PgDn**       | Scroll history down 3 lines.                            |
| **End**        | Jump back to the live (bottom) view.                    |
| **Mouse wheel**| Scroll history (up = back, down = forward).             |
| **Shift+Ins** / **MMB** | Paste clipboard into input.                    |
| **LMB drag** + **RMB click** | Copy a region from history to the clipboard. |
| **Window close (×)** | Quit cleanly, same as F10.                        |

Cursor keys and Home/End within the input line work the way they do in
any single-line text field; the line history (previous commands) is not
re-bound.

---

## Commands

Type a plain line and press Enter to send it to your current room.
Commands start with `/`:

| Command                       | What it does                                                                 |
|-------------------------------|------------------------------------------------------------------------------|
| `/join <room>`                | Join a room — or switch to it if you're already there.                       |
| `/part [<room>]`              | Leave a room (default: the current one).                                     |
| `/msg <nick> <text>`          | Send a private message to one user.                                          |
| `/send <nick> <abs-path>`     | Send a file (≤ 10 MB). Path must be absolute (`/home/me/x.png`).             |
| `/me <action>`                | Emote in current room → `* alice waves *`.                                   |
| `/nick <newnick>`             | Change your nickname; log file rotates to the new name.                      |
| `/who [<room>]`               | List users in a room.                                                        |
| `/list`                       | List all (non-secret) rooms with user counts.                                |
| `/ignore [<nick>]`            | Hide messages/DMs/files from a user. No args = print the current list.       |
| `/unignore <nick>`            | Remove a user from your ignore list.                                         |
| `/quit`                       | Disconnect and exit.                                                         |
| `/help`                       | Print the command list.                                                      |
| `//text`                      | Send a literal line that starts with `/` (e.g. `//usr/bin` chats `/usr/bin`).|

Nickname and room rules (enforced both client- and server-side):

- 1 to 31 characters
- no whitespace, no `:` or `,`

Rooms beginning with `+` are **secret rooms** (not shown by `/list`,
never auto-assigned). See [`MANIFESTO.txt`](https://github.com/ronen-blumberg/kolhaam-network) §3.13.

---

## Files written

In the current working directory:

- `kolhaam-net-<nick>.log` — a plain-text transcript of everything you
  see (timestamped). Re-opened with a new name whenever you `/nick`.
  Append mode, so multiple sessions accumulate.
- Received files (`/send` from someone) are saved under their original
  basename in the cwd; if the name is taken, `.1`, `.2`, … are appended
  before any failure.

Nothing is ever written outside the cwd, and nothing is sent to the
network beyond what the protocol calls for. There is no telemetry, no
update check, no account.

---

## Wire compatibility

This client speaks the exact byte-for-byte protocol described in
[`MANIFESTO.txt`](https://github.com/ronen-blumberg/kolhaam-network) §8:

```
[4 byte big-endian length N]  [16 byte IV]  [N - 16 bytes ciphertext]
plaintext = [1 byte type] [payload]
```

- **KDF:** `SHA-256(passphrase ‖ "KolHaAmNet-v1")` then 100 000 rounds of
  `SHA-256(buf ‖ passphrase)`.
- **Cipher:** AES-256-CBC, PKCS#7 padded, fresh random 16-byte IV per
  frame, drawn from `/dev/urandom`.
- **Packet types** are single ASCII letters: `H M O D F W L N J T X E
  P Q` — same set the C and Python clients use.

All crypto (SHA-256, AES, KDF, framing) is implemented inside
`khn-client-fb.bas` itself — no OpenSSL, no mbedTLS, no other
dependency.

---

## Differences from `client.c` / `client.py`

The wire protocol is identical. The user-visible differences:

- **Single graphical window** (libvt/SDL2), not a terminal. The C and
  Python clients run in your terminal; this one opens its own window
  with bitmap fonts and a built-in title/status bar.
- **One "active room" view.** No multi-window layout, no separate user
  pane (you can `/join` up to 10 rooms; the status bar lists them and
  `/join <room>` switches between them).
- **Resizable window + scrollback** with PgUp/PgDn/End and mouse wheel.
- **Two font sizes**: `--big` (16×24) or default (8×16), set at launch.
- **Clipboard integration** for copy (RMB after LMB-drag) and paste
  (Shift+Ins or MMB), provided by libvt.

What's intentionally not present (yet): saved settings file, runtime
font toggle, multi-pane layout, channel browser, ANSI/mIRC colour
rendering inside messages.

---

## Troubleshooting

- **`libvt requires a graphical desktop (X11/Wayland)`** — you're
  running on a headless terminal. `DISPLAY` and (on X11) `XAUTHORITY`
  must point at a real display you have access to.
- **Connects then immediately disconnects with "Decrypt failed (bad
  keyphrase?)"** — the keyphrase doesn't match the server's. Quote it
  if it has spaces, and check for stray shell expansion.
- **`DNS resolution failed`** — the host name didn't resolve. Try an
  IP, or check `/etc/resolv.conf`.
- **`File too large (> 10485760 bytes)`** — the protocol caps file
  transfers at 10 MB. Split the file first.

---

## License / project context

`khn-client-fb.bas` is a kolhaam-network client — same project, same
spirit, same protocol as everything else in this directory. See
[`MANIFESTO.txt`](https://github.com/ronen-blumberg/kolhaam-network) for the philosophy, the protocol, and
the limits, and [`libvt/README.md`](https://github.com/rbreitinger/libvt/README.md) for the
UI library this client is built on.
