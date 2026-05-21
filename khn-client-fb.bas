' =============================================================================
' khn-client-fb.bas -- kolhaam-network client, FreeBASIC + libvt
'
' Wire-compatible with client.c / client.py / server.c / server.py from
' the kolhaam-network project (see MANIFESTO.txt). Same KDF, same AES-256-CBC,
' same packet layouts -- any combination of clients/servers interoperate.
'
' Usage:
'   khn-client-fb [--big] <server> <port> <keyphrase> [<nickname>] [<room>]
'
' Pass "" for nickname or room to let the server pick one randomly.
' --big (or -b) uses the 16x24 font; default is 8x16.
'
' Build (Linux, libvt installed in FB's include path):
'   fbc -s gui -w all -gen gcc -O 2 khn-client-fb.bas
'
' Commands at the prompt:
'   /join <room>             join a room (or switch to it)
'   /part [<room>]           leave a room (default: current)
'   /msg  <nick> <text>      private message
'   /send <nick> <abs-path>  send a file (<= 10 MB)
'   /me   <action>           emote in the current room
'   /nick <newnick>          change your nickname
'   /who  [<room>]           list users in a room
'   /list                    list all rooms on the server
'   /ignore [<nick>]         hide messages/DMs/files from a user
'   /unignore <nick>         stop ignoring a user
'   /quit                    disconnect
'   /help                    show this list
'   //text                   send a literal chat line that starts with '/'
' =============================================================================

#cmdline "-s gui -w all -gen gcc -O 2"
#Define VT_USE_NET
#Define VT_USE_TUI
#Define VT_USE_STRINGS
#Include Once "vt/vt.bi"
#Include Once "crt.bi"

' -----------------------------------------------------------------------------
' Protocol constants -- must match server.c / client.c
' -----------------------------------------------------------------------------
Const APP_NAME           = "kolhaam-network"
Const APP_VERSION        = "0.1.2"
Const KDF_TAG            = "KolHaAmNet-v1"
Const KDF_ITER           = 100000

Const MAX_NICK           = 32
Const MAX_ROOM           = 32
Const MAX_TEXT           = 1024
Const MAX_ROOMS_PER_USER = 10
Const MAX_IGNORED        = 64

Const AES_BLOCK          = 16
Const AES_ROUNDS         = 14

Const MAX_FILE_BYTES     = 10 * 1024 * 1024
Const MAX_FILE_HDR       = 1024
Const MAX_PAYLOAD        = MAX_FILE_BYTES + MAX_FILE_HDR
Const MAX_PLAINTEXT      = MAX_PAYLOAD + 1
Const MAX_FRAME          = 16 + MAX_PLAINTEXT + 16

Const PKT_HELLO = Asc("H")
Const PKT_MSG   = Asc("M")
Const PKT_EMOTE = Asc("O")
Const PKT_DM    = Asc("D")
Const PKT_FILE  = Asc("F")
Const PKT_WHO   = Asc("W")
Const PKT_LIST  = Asc("L")
Const PKT_NICK  = Asc("N")
Const PKT_JOIN  = Asc("J")
Const PKT_PART  = Asc("T")
Const PKT_SYS   = Asc("X")
Const PKT_ERR   = Asc("E")
Const PKT_PING  = Asc("P")
Const PKT_QUIT  = Asc("Q")

' Line kinds (for colour choice)
Const LINE_SYSTEM = 0
Const LINE_CHAT   = 1
Const LINE_EMOTE  = 2
Const LINE_DM     = 3
Const LINE_FILE   = 4

' -----------------------------------------------------------------------------
' SHA-256
' -----------------------------------------------------------------------------
Type sha256_ctx
    state(0 To 7)  As ULong
    bitlen         As ULongInt
    buf(0 To 63)   As UByte
    buflen         As Long
End Type

Static Shared SHA_K(0 To 63) As ULong = { _
    &h428a2f98u, &h71374491u, &hb5c0fbcfu, &he9b5dba5u, _
    &h3956c25bu, &h59f111f1u, &h923f82a4u, &hab1c5ed5u, _
    &hd807aa98u, &h12835b01u, &h243185beu, &h550c7dc3u, _
    &h72be5d74u, &h80deb1feu, &h9bdc06a7u, &hc19bf174u, _
    &he49b69c1u, &hefbe4786u, &h0fc19dc6u, &h240ca1ccu, _
    &h2de92c6fu, &h4a7484aau, &h5cb0a9dcu, &h76f988dau, _
    &h983e5152u, &ha831c66du, &hb00327c8u, &hbf597fc7u, _
    &hc6e00bf3u, &hd5a79147u, &h06ca6351u, &h14292967u, _
    &h27b70a85u, &h2e1b2138u, &h4d2c6dfcu, &h53380d13u, _
    &h650a7354u, &h766a0abbu, &h81c2c92eu, &h92722c85u, _
    &ha2bfe8a1u, &ha81a664bu, &hc24b8b70u, &hc76c51a3u, _
    &hd192e819u, &hd6990624u, &hf40e3585u, &h106aa070u, _
    &h19a4c116u, &h1e376c08u, &h2748774cu, &h34b0bcb5u, _
    &h391c0cb3u, &h4ed8aa4au, &h5b9cca4fu, &h682e6ff3u, _
    &h748f82eeu, &h78a5636fu, &h84c87814u, &h8cc70208u, _
    &h90befffau, &ha4506cebu, &hbef9a3f7u, &hc67178f2u }

Function rotr32(x As ULong, n As ULong) As ULong
    Return (x Shr n) Or (x Shl (32 - n))
End Function

Sub sha256_init(ByRef c As sha256_ctx)
    c.state(0) = &h6a09e667u : c.state(1) = &hbb67ae85u
    c.state(2) = &h3c6ef372u : c.state(3) = &ha54ff53au
    c.state(4) = &h510e527fu : c.state(5) = &h9b05688cu
    c.state(6) = &h1f83d9abu : c.state(7) = &h5be0cd19u
    c.bitlen   = 0
    c.buflen   = 0
End Sub

Sub sha256_compress(ByRef c As sha256_ctx)
    Dim w(0 To 63) As ULong
    Dim i  As Long
    Dim a  As ULong, b  As ULong, cv As ULong, d  As ULong
    Dim e  As ULong, f  As ULong, g  As ULong, h  As ULong
    Dim t1 As ULong, t2 As ULong
    Dim s0 As ULong, s1 As ULong
    Dim ch As ULong, mj As ULong

    For i = 0 To 15
        w(i) = (CULng(c.buf(i*4))     Shl 24) Or _
               (CULng(c.buf(i*4 + 1)) Shl 16) Or _
               (CULng(c.buf(i*4 + 2)) Shl  8) Or _
                CULng(c.buf(i*4 + 3))
    Next i
    For i = 16 To 63
        s0 = rotr32(w(i-15),  7) Xor rotr32(w(i-15), 18) Xor (w(i-15) Shr  3)
        s1 = rotr32(w(i- 2), 17) Xor rotr32(w(i- 2), 19) Xor (w(i- 2) Shr 10)
        w(i) = w(i-16) + s0 + w(i-7) + s1
    Next i

    a = c.state(0) : b = c.state(1) : cv = c.state(2) : d = c.state(3)
    e = c.state(4) : f = c.state(5) : g  = c.state(6) : h = c.state(7)

    For i = 0 To 63
        s1 = rotr32(e, 6) Xor rotr32(e, 11) Xor rotr32(e, 25)
        ch = (e And f) Xor ((Not e) And g)
        t1 = h + s1 + ch + SHA_K(i) + w(i)
        s0 = rotr32(a, 2) Xor rotr32(a, 13) Xor rotr32(a, 22)
        mj = (a And b) Xor (a And cv) Xor (b And cv)
        t2 = s0 + mj
        h = g : g = f : f = e
        e = d + t1
        d = cv : cv = b : b = a
        a = t1 + t2
    Next i

    c.state(0) += a : c.state(1) += b : c.state(2) += cv : c.state(3) += d
    c.state(4) += e : c.state(5) += f : c.state(6) += g  : c.state(7) += h
End Sub

Sub sha256_update(ByRef c As sha256_ctx, dat As UByte Ptr, n As Long)
    Dim i As Long
    For i = 0 To n - 1
        c.buf(c.buflen) = dat[i]
        c.buflen += 1
        If c.buflen = 64 Then
            sha256_compress(c)
            c.buflen = 0
        End If
    Next i
    c.bitlen += CULngInt(n) * 8
End Sub

Sub sha256_final(ByRef c As sha256_ctx, dst As UByte Ptr)
    Dim i  As Long
    Dim bl As ULongInt = c.bitlen
    c.buf(c.buflen) = &h80
    c.buflen += 1
    If c.buflen > 56 Then
        While c.buflen < 64
            c.buf(c.buflen) = 0
            c.buflen += 1
        Wend
        sha256_compress(c)
        c.buflen = 0
    End If
    While c.buflen < 56
        c.buf(c.buflen) = 0
        c.buflen += 1
    Wend
    For i = 7 To 0 Step -1
        c.buf(56 + (7 - i)) = CUByte((bl Shr (i * 8)) And &hFF)
    Next i
    sha256_compress(c)
    For i = 0 To 7
        dst[i*4]     = CUByte((c.state(i) Shr 24) And &hFF)
        dst[i*4 + 1] = CUByte((c.state(i) Shr 16) And &hFF)
        dst[i*4 + 2] = CUByte((c.state(i) Shr  8) And &hFF)
        dst[i*4 + 3] = CUByte( c.state(i)         And &hFF)
    Next i
End Sub

' -----------------------------------------------------------------------------
' AES-256-CBC + PKCS#7  (same numbers as client.c / client.py)
' -----------------------------------------------------------------------------
Static Shared AES_SBOX(0 To 255) As UByte = { _
    &h63,&h7c,&h77,&h7b,&hf2,&h6b,&h6f,&hc5,&h30,&h01,&h67,&h2b,&hfe,&hd7,&hab,&h76, _
    &hca,&h82,&hc9,&h7d,&hfa,&h59,&h47,&hf0,&had,&hd4,&ha2,&haf,&h9c,&ha4,&h72,&hc0, _
    &hb7,&hfd,&h93,&h26,&h36,&h3f,&hf7,&hcc,&h34,&ha5,&he5,&hf1,&h71,&hd8,&h31,&h15, _
    &h04,&hc7,&h23,&hc3,&h18,&h96,&h05,&h9a,&h07,&h12,&h80,&he2,&heb,&h27,&hb2,&h75, _
    &h09,&h83,&h2c,&h1a,&h1b,&h6e,&h5a,&ha0,&h52,&h3b,&hd6,&hb3,&h29,&he3,&h2f,&h84, _
    &h53,&hd1,&h00,&hed,&h20,&hfc,&hb1,&h5b,&h6a,&hcb,&hbe,&h39,&h4a,&h4c,&h58,&hcf, _
    &hd0,&hef,&haa,&hfb,&h43,&h4d,&h33,&h85,&h45,&hf9,&h02,&h7f,&h50,&h3c,&h9f,&ha8, _
    &h51,&ha3,&h40,&h8f,&h92,&h9d,&h38,&hf5,&hbc,&hb6,&hda,&h21,&h10,&hff,&hf3,&hd2, _
    &hcd,&h0c,&h13,&hec,&h5f,&h97,&h44,&h17,&hc4,&ha7,&h7e,&h3d,&h64,&h5d,&h19,&h73, _
    &h60,&h81,&h4f,&hdc,&h22,&h2a,&h90,&h88,&h46,&hee,&hb8,&h14,&hde,&h5e,&h0b,&hdb, _
    &he0,&h32,&h3a,&h0a,&h49,&h06,&h24,&h5c,&hc2,&hd3,&hac,&h62,&h91,&h95,&he4,&h79, _
    &he7,&hc8,&h37,&h6d,&h8d,&hd5,&h4e,&ha9,&h6c,&h56,&hf4,&hea,&h65,&h7a,&hae,&h08, _
    &hba,&h78,&h25,&h2e,&h1c,&ha6,&hb4,&hc6,&he8,&hdd,&h74,&h1f,&h4b,&hbd,&h8b,&h8a, _
    &h70,&h3e,&hb5,&h66,&h48,&h03,&hf6,&h0e,&h61,&h35,&h57,&hb9,&h86,&hc1,&h1d,&h9e, _
    &he1,&hf8,&h98,&h11,&h69,&hd9,&h8e,&h94,&h9b,&h1e,&h87,&he9,&hce,&h55,&h28,&hdf, _
    &h8c,&ha1,&h89,&h0d,&hbf,&he6,&h42,&h68,&h41,&h99,&h2d,&h0f,&hb0,&h54,&hbb,&h16 }

Static Shared AES_INVSBOX(0 To 255) As UByte = { _
    &h52,&h09,&h6a,&hd5,&h30,&h36,&ha5,&h38,&hbf,&h40,&ha3,&h9e,&h81,&hf3,&hd7,&hfb, _
    &h7c,&he3,&h39,&h82,&h9b,&h2f,&hff,&h87,&h34,&h8e,&h43,&h44,&hc4,&hde,&he9,&hcb, _
    &h54,&h7b,&h94,&h32,&ha6,&hc2,&h23,&h3d,&hee,&h4c,&h95,&h0b,&h42,&hfa,&hc3,&h4e, _
    &h08,&h2e,&ha1,&h66,&h28,&hd9,&h24,&hb2,&h76,&h5b,&ha2,&h49,&h6d,&h8b,&hd1,&h25, _
    &h72,&hf8,&hf6,&h64,&h86,&h68,&h98,&h16,&hd4,&ha4,&h5c,&hcc,&h5d,&h65,&hb6,&h92, _
    &h6c,&h70,&h48,&h50,&hfd,&hed,&hb9,&hda,&h5e,&h15,&h46,&h57,&ha7,&h8d,&h9d,&h84, _
    &h90,&hd8,&hab,&h00,&h8c,&hbc,&hd3,&h0a,&hf7,&he4,&h58,&h05,&hb8,&hb3,&h45,&h06, _
    &hd0,&h2c,&h1e,&h8f,&hca,&h3f,&h0f,&h02,&hc1,&haf,&hbd,&h03,&h01,&h13,&h8a,&h6b, _
    &h3a,&h91,&h11,&h41,&h4f,&h67,&hdc,&hea,&h97,&hf2,&hcf,&hce,&hf0,&hb4,&he6,&h73, _
    &h96,&hac,&h74,&h22,&he7,&had,&h35,&h85,&he2,&hf9,&h37,&he8,&h1c,&h75,&hdf,&h6e, _
    &h47,&hf1,&h1a,&h71,&h1d,&h29,&hc5,&h89,&h6f,&hb7,&h62,&h0e,&haa,&h18,&hbe,&h1b, _
    &hfc,&h56,&h3e,&h4b,&hc6,&hd2,&h79,&h20,&h9a,&hdb,&hc0,&hfe,&h78,&hcd,&h5a,&hf4, _
    &h1f,&hdd,&ha8,&h33,&h88,&h07,&hc7,&h31,&hb1,&h12,&h10,&h59,&h27,&h80,&hec,&h5f, _
    &h60,&h51,&h7f,&ha9,&h19,&hb5,&h4a,&h0d,&h2d,&he5,&h7a,&h9f,&h93,&hc9,&h9c,&hef, _
    &ha0,&he0,&h3b,&h4d,&hae,&h2a,&hf5,&hb0,&hc8,&heb,&hbb,&h3c,&h83,&h53,&h99,&h61, _
    &h17,&h2b,&h04,&h7e,&hba,&h77,&hd6,&h26,&he1,&h69,&h14,&h63,&h55,&h21,&h0c,&h7d }

Static Shared AES_RCON(0 To 10) As UByte = { _
    &h00,&h01,&h02,&h04,&h08,&h10,&h20,&h40,&h80,&h1b,&h36 }

Type aes_ctx
    rk(0 To (AES_ROUNDS + 1) * 16 - 1) As UByte
End Type

Function aes_xtime(x As UByte) As UByte
    Return CUByte(((CULng(x) Shl 1) Xor (((CULng(x) Shr 7) And 1) * &h1b)) And &hFF)
End Function

Function aes_gmul(xx As UByte, yy As UByte) As UByte
    Dim r As ULong = 0
    Dim x As ULong = xx
    Dim y As ULong = yy
    Dim i As Long
    For i = 0 To 7
        If (y And 1) Then r = r Xor x
        x = aes_xtime(CUByte(x And &hFF))
        y = y Shr 1
    Next i
    Return CUByte(r And &hFF)
End Function

Sub aes_key_expansion(ByRef ctx As aes_ctx, key As UByte Ptr)
    Dim i   As Long
    Dim t(0 To 3) As UByte
    Dim tmp As UByte
    For i = 0 To 31
        ctx.rk(i) = key[i]
    Next i
    For i = 8 To 4 * (AES_ROUNDS + 1) - 1
        t(0) = ctx.rk((i-1)*4    )
        t(1) = ctx.rk((i-1)*4 + 1)
        t(2) = ctx.rk((i-1)*4 + 2)
        t(3) = ctx.rk((i-1)*4 + 3)
        If (i Mod 8) = 0 Then
            tmp = t(0)
            t(0) = AES_SBOX(t(1))
            t(1) = AES_SBOX(t(2))
            t(2) = AES_SBOX(t(3))
            t(3) = AES_SBOX(tmp)
            t(0) = t(0) Xor AES_RCON(i \ 8)
        ElseIf (i Mod 8) = 4 Then
            t(0) = AES_SBOX(t(0))
            t(1) = AES_SBOX(t(1))
            t(2) = AES_SBOX(t(2))
            t(3) = AES_SBOX(t(3))
        End If
        ctx.rk(i*4    ) = ctx.rk((i-8)*4    ) Xor t(0)
        ctx.rk(i*4 + 1) = ctx.rk((i-8)*4 + 1) Xor t(1)
        ctx.rk(i*4 + 2) = ctx.rk((i-8)*4 + 2) Xor t(2)
        ctx.rk(i*4 + 3) = ctx.rk((i-8)*4 + 3) Xor t(3)
    Next i
End Sub

Sub aes_shift_rows(s As UByte Ptr)
    Dim t As UByte
    t = s[1] : s[1] = s[5] : s[5] = s[9]  : s[9]  = s[13] : s[13] = t
    t = s[2] : s[2] = s[10] : s[10] = t
    t = s[6] : s[6] = s[14] : s[14] = t
    t = s[3] : s[3] = s[15] : s[15] = s[11] : s[11] = s[7] : s[7] = t
End Sub

Sub aes_inv_shift_rows(s As UByte Ptr)
    Dim t As UByte
    t = s[13] : s[13] = s[9] : s[9] = s[5] : s[5] = s[1] : s[1] = t
    t = s[2]  : s[2]  = s[10] : s[10] = t
    t = s[6]  : s[6]  = s[14] : s[14] = t
    t = s[3]  : s[3]  = s[7] : s[7] = s[11] : s[11] = s[15] : s[15] = t
End Sub

Sub aes_mix_columns(s As UByte Ptr)
    Dim i  As Long
    Dim a0 As UByte, a1 As UByte, a2 As UByte, a3 As UByte, tt As UByte
    For i = 0 To 3
        a0 = s[i*4] : a1 = s[i*4 + 1] : a2 = s[i*4 + 2] : a3 = s[i*4 + 3]
        tt = a0 Xor a1 Xor a2 Xor a3
        s[i*4    ] = s[i*4    ] Xor tt Xor aes_xtime(a0 Xor a1)
        s[i*4 + 1] = s[i*4 + 1] Xor tt Xor aes_xtime(a1 Xor a2)
        s[i*4 + 2] = s[i*4 + 2] Xor tt Xor aes_xtime(a2 Xor a3)
        s[i*4 + 3] = s[i*4 + 3] Xor tt Xor aes_xtime(a3 Xor a0)
    Next i
End Sub

Sub aes_inv_mix_columns(s As UByte Ptr)
    Dim i  As Long
    Dim a0 As UByte, a1 As UByte, a2 As UByte, a3 As UByte
    For i = 0 To 3
        a0 = s[i*4] : a1 = s[i*4 + 1] : a2 = s[i*4 + 2] : a3 = s[i*4 + 3]
        s[i*4    ] = aes_gmul(a0, &h0e) Xor aes_gmul(a1, &h0b) Xor aes_gmul(a2, &h0d) Xor aes_gmul(a3, &h09)
        s[i*4 + 1] = aes_gmul(a0, &h09) Xor aes_gmul(a1, &h0e) Xor aes_gmul(a2, &h0b) Xor aes_gmul(a3, &h0d)
        s[i*4 + 2] = aes_gmul(a0, &h0d) Xor aes_gmul(a1, &h09) Xor aes_gmul(a2, &h0e) Xor aes_gmul(a3, &h0b)
        s[i*4 + 3] = aes_gmul(a0, &h0b) Xor aes_gmul(a1, &h0d) Xor aes_gmul(a2, &h09) Xor aes_gmul(a3, &h0e)
    Next i
End Sub

Sub aes_add_round_key(s As UByte Ptr, rk As UByte Ptr)
    Dim i As Long
    For i = 0 To 15
        s[i] = s[i] Xor rk[i]
    Next i
End Sub

Sub aes_encrypt_block(ByRef ctx As aes_ctx, blkin As UByte Ptr, blkout As UByte Ptr)
    Dim s(0 To 15) As UByte
    Dim r          As Long
    Dim i          As Long
    For i = 0 To 15
        s(i) = blkin[i]
    Next i
    aes_add_round_key(@s(0), @ctx.rk(0))
    For r = 1 To AES_ROUNDS - 1
        For i = 0 To 15
            s(i) = AES_SBOX(s(i))
        Next i
        aes_shift_rows(@s(0))
        aes_mix_columns(@s(0))
        aes_add_round_key(@s(0), @ctx.rk(r * 16))
    Next r
    For i = 0 To 15
        s(i) = AES_SBOX(s(i))
    Next i
    aes_shift_rows(@s(0))
    aes_add_round_key(@s(0), @ctx.rk(AES_ROUNDS * 16))
    For i = 0 To 15
        blkout[i] = s(i)
    Next i
End Sub

Sub aes_decrypt_block(ByRef ctx As aes_ctx, blkin As UByte Ptr, blkout As UByte Ptr)
    Dim s(0 To 15) As UByte
    Dim r          As Long
    Dim i          As Long
    For i = 0 To 15
        s(i) = blkin[i]
    Next i
    aes_add_round_key(@s(0), @ctx.rk(AES_ROUNDS * 16))
    For r = AES_ROUNDS - 1 To 1 Step -1
        aes_inv_shift_rows(@s(0))
        For i = 0 To 15
            s(i) = AES_INVSBOX(s(i))
        Next i
        aes_add_round_key(@s(0), @ctx.rk(r * 16))
        aes_inv_mix_columns(@s(0))
    Next r
    aes_inv_shift_rows(@s(0))
    For i = 0 To 15
        s(i) = AES_INVSBOX(s(i))
    Next i
    aes_add_round_key(@s(0), @ctx.rk(0))
    For i = 0 To 15
        blkout[i] = s(i)
    Next i
End Sub

' CBC encrypt with PKCS#7 padding. Returns number of ciphertext bytes.
' out buffer must be >= ((plen / 16) + 1) * 16 bytes.
Function aes_cbc_encrypt(ByRef ctx As aes_ctx, iv As UByte Ptr, _
                         plain As UByte Ptr, plen As Long, _
                         dst As UByte Ptr) As Long
    Dim blocks  As Long = plen \ 16
    Dim rem_    As Long = plen Mod 16
    Dim pad     As UByte = CUByte(16 - rem_)
    Dim prev(0 To 15) As UByte
    Dim blk (0 To 15) As UByte
    Dim i As Long, j As Long
    For i = 0 To 15
        prev(i) = iv[i]
    Next i
    For i = 0 To blocks - 1
        For j = 0 To 15
            blk(j) = plain[i*16 + j] Xor prev(j)
        Next j
        aes_encrypt_block(ctx, @blk(0), dst + i*16)
        For j = 0 To 15
            prev(j) = (dst + i*16)[j]
        Next j
    Next i
    ' final padded block
    For j = 0 To rem_ - 1
        blk(j) = plain[blocks*16 + j] Xor prev(j)
    Next j
    For j = rem_ To 15
        blk(j) = pad Xor prev(j)
    Next j
    aes_encrypt_block(ctx, @blk(0), dst + blocks*16)
    Return (blocks + 1) * 16
End Function

' CBC decrypt + PKCS#7 strip. Returns plaintext byte count, or -1 on bad pad.
Function aes_cbc_decrypt(ByRef ctx As aes_ctx, iv As UByte Ptr, _
                         ct As UByte Ptr, clen As Long, _
                         dst As UByte Ptr) As Long
    If clen = 0 OrElse (clen Mod 16) <> 0 Then Return -1
    Dim blocks As Long = clen \ 16
    Dim prev(0 To 15) As UByte
    Dim blk (0 To 15) As UByte
    Dim i As Long, j As Long
    Dim pad   As UByte
    For i = 0 To 15
        prev(i) = iv[i]
    Next i
    For i = 0 To blocks - 1
        aes_decrypt_block(ctx, ct + i*16, @blk(0))
        For j = 0 To 15
            dst[i*16 + j] = blk(j) Xor prev(j)
            prev(j) = (ct + i*16)[j]
        Next j
    Next i
    pad = dst[clen - 1]
    If pad < 1 OrElse pad > 16 Then Return -1
    For i = 0 To pad - 1
        If dst[clen - 1 - i] <> pad Then Return -1
    Next i
    Return clen - pad
End Function

' -----------------------------------------------------------------------------
' Random bytes -- IV must be unpredictable to keep CBC secure.
' Linux: /dev/urandom.  Windows: RtlGenRandom (SystemFunction036 in advapi32,
' same source the C reference client uses). Both fall back to a SHA-256 chain
' seeded from clock/pid in the unlikely event the OS source fails.
' -----------------------------------------------------------------------------
#ifdef __FB_WIN32__
    ' GetCurrentProcessId is already declared by windows.bi, which libvt's
    ' winsock2.bi pulls in transitively -- do NOT redeclare it here.
    Extern "Windows"
        Declare Function RtlGenRandom Lib "advapi32" Alias "SystemFunction036" ( _
            ByVal RandomBuffer As Any Ptr, _
            ByVal RandomBufferLength As ULong) As Byte
    End Extern
    #Inclib "advapi32"
#endif

Sub rand_bytes(buf As UByte Ptr, n As Long)
#ifdef __FB_WIN32__
    If RtlGenRandom(buf, CULng(n)) <> 0 Then Exit Sub
#else
    Dim f As FILE Ptr
    f = fopen("/dev/urandom", "rb")
    If f <> 0 Then
        If fread(buf, 1, n, f) = CULngInt(n) Then
            fclose(f)
            Exit Sub
        End If
        fclose(f)
    End If
#endif
    ' Fallback: chain SHA-256 of timer/pid into the buffer.
    Static state(0 To 31) As UByte
    Static seeded         As Byte = 0
    If seeded = 0 Then
        #ifdef __FB_WIN32__
            Dim pid As ULong = GetCurrentProcessId()
        #else
            Dim pid As ULong = getpid()
        #endif
        Dim seed As String = Str(Timer) & ":" & Str(pid) & ":" & _
                              Str(Time) & ":" & Str(Date)
        Dim c    As sha256_ctx
        sha256_init(c)
        sha256_update(c, Cast(UByte Ptr, StrPtr(seed)), Len(seed))
        sha256_final(c, @state(0))
        seeded = 1
    End If
    Dim c2  As sha256_ctx
    Dim ctr As ULongInt = 0
    Dim got As Long = 0
    Dim i   As Long
    Do While got < n
        sha256_init(c2)
        sha256_update(c2, @state(0), 32)
        sha256_update(c2, Cast(UByte Ptr, @ctr), 8)
        Dim outbuf(0 To 31) As UByte
        sha256_final(c2, @outbuf(0))
        Dim take As Long = 32
        If take > n - got Then take = n - got
        For i = 0 To take - 1
            buf[got + i] = outbuf(i)
        Next i
        got += take
        ctr += 1
    Loop
End Sub

' -----------------------------------------------------------------------------
' Key derivation:   key = SHA-256^100000( SHA-256(pw || tag), pw )
' -----------------------------------------------------------------------------
Sub derive_key(passphrase As String, key_out As UByte Ptr)
    Dim c   As sha256_ctx
    Dim buf(0 To 31) As UByte
    Dim i   As Long
    sha256_init(c)
    sha256_update(c, Cast(UByte Ptr, StrPtr(passphrase)), Len(passphrase))
    Dim tag As String = KDF_TAG
    sha256_update(c, Cast(UByte Ptr, StrPtr(tag)),         Len(tag))
    sha256_final(c, @buf(0))
    For i = 1 To KDF_ITER
        sha256_init(c)
        sha256_update(c, @buf(0), 32)
        sha256_update(c, Cast(UByte Ptr, StrPtr(passphrase)), Len(passphrase))
        sha256_final(c, @buf(0))
    Next i
    For i = 0 To 31
        key_out[i] = buf(i)
    Next i
End Sub

' -----------------------------------------------------------------------------
' Global client state
' -----------------------------------------------------------------------------
Dim Shared g_sock        As SOCKET
Dim Shared g_sock_valid  As Byte = 0
Dim Shared g_quit_flag   As Byte = 0
Dim Shared g_aes         As aes_ctx
Dim Shared g_nick        As String
Dim Shared g_recv_buf    As String         ' accumulated bytes from socket
Dim Shared g_log         As Long = 0       ' file number, 0 = closed

Dim Shared g_rooms(0 To MAX_ROOMS_PER_USER - 1) As String
Dim Shared g_nrooms      As Long = 0
Dim Shared g_current_room_idx As Long = -1

Dim Shared g_ignored(0 To MAX_IGNORED - 1) As String
Dim Shared g_nignored    As Long = 0

' History ring buffer (one entry per displayed line)
Const HISTORY_MAX = 1000
Type hist_line
    txt    As String
    fg     As UByte
End Type
Dim Shared g_hist(0 To HISTORY_MAX - 1) As hist_line
Dim Shared g_hist_head   As Long = 0
Dim Shared g_hist_count  As Long = 0
Dim Shared g_top_line    As Long = 0       ' scroll offset (0 = bottom)

' Screen layout
Const MIN_SCREEN_COLS = 60
Const MIN_SCREEN_ROWS = 20
Dim Shared g_cols        As Long = 100
Dim Shared g_rows        As Long = 40
Dim Shared g_chat_top    As Long = 2
Dim Shared g_chat_bot    As Long = 37
Dim Shared g_chat_rows   As Long = 36
Dim Shared g_row_input   As Long = 39
Dim Shared g_row_status  As Long = 40
Dim Shared g_chat_wide   As Long = 100

' Input line state
Dim Shared input_form(0 To 0) As vt_tui_form_item
Dim Shared input_focused      As Long = 0

' Dirty flags
Dim Shared df_hist    As Byte = 1
Dim Shared df_input   As Byte = 1

' Theme colours
Dim Shared col_bg     As UByte = VT_BLACK
Dim Shared col_body   As UByte = VT_LIGHT_GREY
Dim Shared col_self   As UByte = VT_BRIGHT_CYAN
Dim Shared col_other  As UByte = VT_BRIGHT_GREEN
Dim Shared col_sys    As UByte = VT_YELLOW
Dim Shared col_dm     As UByte = VT_BRIGHT_BLUE
Dim Shared col_emote  As UByte = VT_BRIGHT_MAGENTA
Dim Shared col_file   As UByte = VT_BRIGHT_MAGENTA
Dim Shared col_err    As UByte = VT_BRIGHT_RED
Dim Shared col_bar_fg As UByte = VT_WHITE
Dim Shared col_bar_bg As UByte = VT_BLUE
Dim Shared col_ts     As UByte = VT_DARK_GREY

' Forward declarations
Declare Sub do_disconnect(reason As String)
Declare Sub put_line(txt As String, kind As Long)
Declare Sub handle_input_line(ln As String)
Declare Sub dispatch_packet(t As UByte, p As String)

' -----------------------------------------------------------------------------
' Layout / resize
' -----------------------------------------------------------------------------
Sub screen_relayout()
    g_chat_top   = 2
    g_chat_bot   = g_rows - 3
    g_chat_rows  = g_rows - 4
    g_row_input  = g_rows - 1
    g_row_status = g_rows
    g_chat_wide  = g_cols
    If g_chat_rows < 1 Then g_chat_rows = 1
    df_hist = 1 : df_input = 1
End Sub

Sub check_resize()
    Dim nc As Long, nr As Long
    If vt_screeninfo(nc, nr) Then
        If nc >= MIN_SCREEN_COLS AndAlso nr >= MIN_SCREEN_ROWS Then
            If nc <> g_cols OrElse nr <> g_rows Then
                vt_width(nc, nr)
                g_cols = vt_cols()
                g_rows = vt_rows()
                screen_relayout()
            End If
        End If
    End If
End Sub

' -----------------------------------------------------------------------------
' Logging
' -----------------------------------------------------------------------------
Function sanitize_nick(nk As String) As String
    Dim res As String
    Dim i   As Long
    For i = 1 To Len(nk)
        Dim c As UByte = Asc(nk, i)
        If c < 32 OrElse c = 127 OrElse c = Asc("/") OrElse c = Asc("\") OrElse c = Asc(":") Then
            res &= "_"
        Else
            res &= Chr(c)
        End If
    Next i
    If Len(res) = 0 Then res = "anon"
    Return res
End Function

Sub log_close()
    If g_log <> 0 Then
        Close #g_log
        g_log = 0
    End If
End Sub

Sub log_open(nk As String)
    log_close()
    Dim safe As String = sanitize_nick(nk)
    Dim fn   As String = "kolhaam-net-" & safe & ".log"
    g_log = FreeFile
    If Open(fn For Append As #g_log) <> 0 Then
        g_log = 0
        put_line("Could not open log file " & fn & " - logging disabled.", LINE_SYSTEM)
        Exit Sub
    End If
    Print #g_log,
    Print #g_log, "========== " & APP_NAME & " " & APP_VERSION & " session " & _
                   Date & " " & Time & " as """ & nk & """ =========="
    put_line("Logging this session to ./" & fn, LINE_SYSTEM)
End Sub

Sub log_write(txt As String)
    If g_log = 0 Then Exit Sub
    Print #g_log, "[" & Date & " " & Time & "] " & txt
End Sub

' -----------------------------------------------------------------------------
' History ring + line display
' -----------------------------------------------------------------------------
Sub hist_push_raw(txt As String, fg As UByte)
    Dim slot As Long
    If g_hist_count < HISTORY_MAX Then
        slot = (g_hist_head + g_hist_count) Mod HISTORY_MAX
        g_hist(slot).txt = txt
        g_hist(slot).fg  = fg
        g_hist_count += 1
    Else
        g_hist(g_hist_head).txt = txt
        g_hist(g_hist_head).fg  = fg
        g_hist_head = (g_hist_head + 1) Mod HISTORY_MAX
    End If
    df_hist = 1
End Sub

' Simple word-wrap at g_chat_wide. Falls back to character split if a single
' word is longer than the line.
Sub hist_push(txt As String, fg As UByte)
    Dim w As Long = g_chat_wide
    If w < 10 Then w = 10
    Dim ts_pfx As String = "[" & Left(Time, 5) & "] "
    Dim ln     As String = ts_pfx & txt
    Do While Len(ln) > w
        Dim cut As Long = w
        Dim sp  As Long = InStrRev(Left(ln, w + 1), " ")
        If sp > Len(ts_pfx) AndAlso sp < w + 1 Then cut = sp - 1
        hist_push_raw(Left(ln, cut), fg)
        ln = Space(Len(ts_pfx)) & LTrim(Mid(ln, cut + 1))
    Loop
    If Len(ln) > 0 Then hist_push_raw(ln, fg)
End Sub

Sub put_line(txt As String, kind As Long)
    Dim fg As UByte
    Select Case kind
        Case LINE_CHAT   : fg = col_other
        Case LINE_EMOTE  : fg = col_emote
        Case LINE_DM     : fg = col_dm
        Case LINE_FILE   : fg = col_file
        Case Else        : fg = col_sys
    End Select
    hist_push(txt, fg)
    log_write(txt)
End Sub

' -----------------------------------------------------------------------------
' Drawing
' -----------------------------------------------------------------------------
Sub draw_titlebar()
    Dim cur As String = "(no room)"
    If g_current_room_idx >= 0 Then cur = g_rooms(g_current_room_idx)
    Dim t   As String = APP_NAME & " " & APP_VERSION & "  -  " & g_nick & "  @  " & cur
    vt_color(col_bar_fg, col_bar_bg)
    vt_locate(1, 1)
    vt_print(vt_str_pad_right(" " & t, g_cols, " "))
End Sub

Sub draw_status()
    Dim s As String
    Dim rooms_csv As String
    Dim i As Long
    For i = 0 To g_nrooms - 1
        If Len(rooms_csv) > 0 Then rooms_csv &= ","
        rooms_csv &= g_rooms(i)
    Next i
    If g_sock_valid Then
        s = " Rooms: " & rooms_csv & "   F1 help  F10 quit"
    Else
        s = " Not connected   F10 quit"
    End If
    If g_nignored > 0 Then
        s &= "  Ignoring(" & g_nignored & ")"
    End If
    If g_top_line > 0 Then
        s &= "  [scrolled up; PgDn/End to bottom]"
    End If
    vt_color(col_bar_fg, col_bar_bg)
    vt_locate(g_row_status, 1)
    vt_print(vt_str_pad_right(s, g_cols, " "))
End Sub

Sub draw_history()
    vt_tui_rect_fill(1, g_chat_top, g_cols, g_chat_rows, 32, col_body, col_bg)
    If g_hist_count = 0 Then Exit Sub
    Dim first As Long = g_hist_count - g_chat_rows - g_top_line
    If first < 0 Then first = 0
    Dim last  As Long = g_hist_count - 1 - g_top_line
    If last < 0 Then Exit Sub
    Dim row   As Long = g_chat_top
    Dim i     As Long
    For i = first To last
        If row > g_chat_bot Then Exit For
        Dim ri As Long = (g_hist_head + i) Mod HISTORY_MAX
        Dim ln As String = g_hist(ri).txt
        If Len(ln) > g_chat_wide Then ln = Left(ln, g_chat_wide)
        ' draw timestamp dimmer if present
        If Len(ln) >= 8 AndAlso Left(ln, 1) = "[" AndAlso Mid(ln, 7, 2) = "] " Then
            vt_color(col_ts, col_bg)
            vt_locate(row, 1)
            vt_print(Left(ln, 8))
            vt_color(g_hist(ri).fg, col_bg)
            vt_locate(row, 9)
            vt_print(Mid(ln, 9))
        Else
            vt_color(g_hist(ri).fg, col_bg)
            vt_locate(row, 1)
            vt_print(ln)
        End If
        row += 1
    Next i
End Sub

Sub draw_input()
    Dim prefix As String = g_nick & "> "
    If Len(g_nick) = 0 Then prefix = "> "
    vt_color(col_sys, col_bg)
    vt_locate(g_row_input - 1, 1)
    vt_print(String(g_cols, Chr(196)))
    vt_color(col_body, col_bg)
    vt_locate(g_row_input, 1)
    vt_print(prefix)
    input_form(0).x   = 1 + Len(prefix)
    input_form(0).y   = g_row_input
    input_form(0).wid = g_cols - Len(prefix)
    vt_tui_form_draw(input_form(), input_focused)
End Sub

Sub draw_ui()
    If df_hist = 0 AndAlso df_input = 0 Then Exit Sub
    If df_hist AndAlso df_input Then vt_cls(col_bg)
    If df_hist Then
        draw_history()
        df_hist = 0
    End If
    If df_input Then
        draw_titlebar()
        draw_status()
    End If
    draw_input()
    df_input = 0
End Sub

' -----------------------------------------------------------------------------
' Local room / ignore tracking
' -----------------------------------------------------------------------------
Function find_room_idx(r As String) As Long
    Dim i As Long
    For i = 0 To g_nrooms - 1
        If g_rooms(i) = r Then Return i
    Next i
    Return -1
End Function

Sub add_room_local(r As String)
    If find_room_idx(r) >= 0 Then
        g_current_room_idx = find_room_idx(r)
        Exit Sub
    End If
    If g_nrooms < MAX_ROOMS_PER_USER Then
        g_rooms(g_nrooms) = r
        g_current_room_idx = g_nrooms
        g_nrooms += 1
    End If
End Sub

Sub remove_room_local(r As String)
    Dim idx As Long = find_room_idx(r)
    If idx < 0 Then Exit Sub
    Dim i As Long
    For i = idx To g_nrooms - 2
        g_rooms(i) = g_rooms(i + 1)
    Next i
    g_nrooms -= 1
    If g_nrooms = 0 Then
        g_current_room_idx = -1
    ElseIf g_current_room_idx = idx Then
        g_current_room_idx = g_nrooms - 1
    ElseIf g_current_room_idx > idx Then
        g_current_room_idx -= 1
    End If
End Sub

Function get_current_room() As String
    If g_current_room_idx < 0 Then Return ""
    Return g_rooms(g_current_room_idx)
End Function

Function find_ignored(nk As String) As Long
    Dim i As Long
    For i = 0 To g_nignored - 1
        If g_ignored(i) = nk Then Return i
    Next i
    Return -1
End Function

Function is_ignored(nk As String) As Long
    Return IIf(find_ignored(nk) >= 0, 1, 0)
End Function

Function ignore_add(nk As String) As Long
    If find_ignored(nk) >= 0 Then Return 1   ' already
    If g_nignored >= MAX_IGNORED Then Return 2   ' full
    g_ignored(g_nignored) = nk
    g_nignored += 1
    Return 0
End Function

Function ignore_remove(nk As String) As Long
    Dim idx As Long = find_ignored(nk)
    If idx < 0 Then Return 0
    Dim i As Long
    For i = idx To g_nignored - 2
        g_ignored(i) = g_ignored(i + 1)
    Next i
    g_nignored -= 1
    Return 1
End Function

Function name_is_valid(s As String, maxlen As Long) As Long
    If Len(s) = 0 OrElse Len(s) >= maxlen Then Return 0
    Dim i As Long
    For i = 1 To Len(s)
        Dim c As UByte = Asc(s, i)
        If c <= 32 OrElse c = 127 OrElse c = Asc(":") OrElse c = Asc(",") Then Return 0
    Next i
    Return 1
End Function

' -----------------------------------------------------------------------------
' Wire I/O
' -----------------------------------------------------------------------------
Function send_all_bytes(buf As UByte Ptr, n As Long) As Long
    Dim sent As Long = 0
    Do While sent < n
        Dim k As Long = vt_net_send(g_sock, Cast(ZString Ptr, buf + sent), n - sent)
        If k <= 0 Then Return -1
        sent += k
    Loop
    Return 0
End Function

' Build, encrypt, and send one packet. Returns 0 on success.
Function send_packet(ptype As UByte, payload As UByte Ptr, plen As Long) As Long
    If g_sock_valid = 0 Then Return -1
    Dim pt_len   As Long = 1 + plen
    If pt_len > MAX_PLAINTEXT Then Return -1
    Dim ct_len   As Long = ((pt_len \ 16) + 1) * 16
    Dim framelen As Long = 16 + ct_len

    Dim pt  As UByte Ptr = Cast(UByte Ptr, Allocate(pt_len))
    Dim ct  As UByte Ptr = Cast(UByte Ptr, Allocate(ct_len))
    If pt = 0 OrElse ct = 0 Then
        If pt Then Deallocate(pt)
        If ct Then Deallocate(ct)
        Return -1
    End If
    Dim iv(0 To 15) As UByte
    Dim hdr(0 To 3) As UByte
    pt[0] = ptype
    If plen > 0 Then
        memcpy(pt + 1, payload, plen)
    End If
    rand_bytes(@iv(0), 16)
    aes_cbc_encrypt(g_aes, @iv(0), pt, pt_len, ct)
    Deallocate(pt)

    hdr(0) = CUByte((framelen Shr 24) And &hFF)
    hdr(1) = CUByte((framelen Shr 16) And &hFF)
    hdr(2) = CUByte((framelen Shr  8) And &hFF)
    hdr(3) = CUByte( framelen         And &hFF)

    Dim rc As Long = 0
    If send_all_bytes(@hdr(0), 4)      <> 0 Then rc = -1
    If rc = 0 AndAlso send_all_bytes(@iv(0), 16)      <> 0 Then rc = -1
    If rc = 0 AndAlso send_all_bytes(ct, ct_len)      <> 0 Then rc = -1
    Deallocate(ct)
    Return rc
End Function

' Drain the socket into g_recv_buf, then parse out complete frames.
Sub poll_recv()
    If g_sock_valid = 0 Then Exit Sub
    Dim tmp As ZString * 16385
    Dim n   As Long
    Do While vt_net_ready(g_sock, 0, 0) = 1
        n = vt_net_recv(g_sock, @tmp, 16384)
        If n <= 0 Then
            do_disconnect("Connection closed by server.")
            Exit Sub
        End If
        Dim chunk As String = Space(n)
        memcpy(StrPtr(chunk), @tmp, n)
        g_recv_buf &= chunk
        ' don't loop forever on a single tick if a flood arrives
        If Len(g_recv_buf) > 4 * 1024 * 1024 Then Exit Do
    Loop

    ' Parse complete frames out of g_recv_buf
    Do
        If Len(g_recv_buf) < 4 Then Exit Do
        Dim framelen As ULong = _
            (CULng(Asc(g_recv_buf, 1)) Shl 24) Or _
            (CULng(Asc(g_recv_buf, 2)) Shl 16) Or _
            (CULng(Asc(g_recv_buf, 3)) Shl  8) Or _
             CULng(Asc(g_recv_buf, 4))
        If framelen < 32 OrElse framelen > MAX_FRAME Then
            do_disconnect("Bad frame length from server.")
            Exit Sub
        End If
        If CULng(Len(g_recv_buf)) < 4 + framelen Then Exit Do

        Dim ct_len As Long = framelen - 16
        Dim ivPtr  As UByte Ptr = Cast(UByte Ptr, StrPtr(g_recv_buf)) + 4
        Dim ctPtr  As UByte Ptr = ivPtr + 16
        Dim pt     As UByte Ptr = Cast(UByte Ptr, Allocate(ct_len))
        If pt = 0 Then Exit Do
        Dim plen As Long = aes_cbc_decrypt(g_aes, ivPtr, ctPtr, ct_len, pt)
        If plen < 1 Then
            Deallocate(pt)
            do_disconnect("Decrypt failed (bad keyphrase?).")
            Exit Sub
        End If

        Dim ptype As UByte = pt[0]
        Dim payload_len As Long = plen - 1
        Dim payload As String = Space(payload_len)
        If payload_len > 0 Then memcpy(StrPtr(payload), pt + 1, payload_len)
        Deallocate(pt)

        ' Slice frame off recv buffer
        g_recv_buf = Mid(g_recv_buf, 5 + framelen)

        dispatch_packet(ptype, payload)
    Loop
End Sub

' -----------------------------------------------------------------------------
' Payload helpers
' -----------------------------------------------------------------------------
' Reads a length-prefixed string starting at 1-based offset `off`.
Function read_u8_string(p As String, ByRef off As Long, ByRef dst As String) As Long
    If off > Len(p) Then Return 0
    Dim n As Long = Asc(p, off)
    off += 1
    If off + n - 1 > Len(p) Then Return 0
    dst = Mid(p, off, n)
    off += n
    Return 1
End Function

Function read_be32(p As String, ByRef off As Long, ByRef dst As ULong) As Long
    If off + 3 > Len(p) Then Return 0
    dst = (CULng(Asc(p, off    )) Shl 24) Or _
          (CULng(Asc(p, off + 1)) Shl 16) Or _
          (CULng(Asc(p, off + 2)) Shl  8) Or _
           CULng(Asc(p, off + 3))
    off += 4
    Return 1
End Function

' -----------------------------------------------------------------------------
' Send helpers (build payloads, call send_packet)
' -----------------------------------------------------------------------------
Function send_string_payload(ptype As UByte, body As String) As Long
    If Len(body) = 0 Then
        Dim dummy As UByte = 0
        Return send_packet(ptype, @dummy, 0)
    End If
    Dim buf As UByte Ptr = Cast(UByte Ptr, Allocate(Len(body)))
    If buf = 0 Then Return -1
    memcpy(buf, StrPtr(body), Len(body))
    Dim r As Long = send_packet(ptype, buf, Len(body))
    Deallocate(buf)
    Return r
End Function

Function send_hello(nk As String, rm As String) As Long
    If Len(nk) > 255 OrElse Len(rm) > 255 Then Return -1
    Dim body As String
    body &= Chr(Len(nk)) & nk
    body &= Chr(Len(rm)) & rm
    Return send_string_payload(PKT_HELLO, body)
End Function

Function send_simple_string(ptype As UByte, s As String) As Long
    If Len(s) = 0 OrElse Len(s) > 255 Then Return -1
    Dim body As String = Chr(Len(s)) & s
    Return send_string_payload(ptype, body)
End Function

Function send_room_text(ptype As UByte, rm As String, txt As String) As Long
    If Len(rm) = 0 OrElse Len(rm) > 255 Then Return -1
    If Len(txt) = 0 OrElse Len(txt) > MAX_TEXT Then Return -1
    Dim body As String = Chr(Len(rm)) & rm & txt
    Return send_string_payload(ptype, body)
End Function

Function send_dm(recip As String, txt As String) As Long
    If Len(recip) = 0 OrElse Len(recip) > 255 Then Return -1
    If Len(txt) = 0 OrElse Len(txt) > MAX_TEXT Then Return -1
    Dim body As String = Chr(Len(recip)) & recip & txt
    Return send_string_payload(PKT_DM, body)
End Function

Function file_exists_fn(p As String) As Long
    Dim f As Long = FreeFile
    If Open(p For Input As #f) <> 0 Then Return 0
    Close #f
    Return 1
End Function

Function path_basename(p As String) As String
    Dim i As Long
    Dim last As Long = 0
    For i = 1 To Len(p)
        Dim c As UByte = Asc(p, i)
        If c = Asc("/") OrElse c = Asc("\") Then last = i
    Next i
    If last = 0 Then Return p
    Return Mid(p, last + 1)
End Function

Function path_is_absolute(p As String) As Long
    If Len(p) = 0 Then Return 0
    If Asc(p, 1) = Asc("/") Then Return 1
    If Len(p) >= 2 Then
        Dim c As UByte = Asc(p, 1)
        If ((c >= Asc("A") AndAlso c <= Asc("Z")) OrElse _
            (c >= Asc("a") AndAlso c <= Asc("z"))) AndAlso _
           Asc(p, 2) = Asc(":") Then Return 1
    End If
    Return 0
End Function

Function send_file_to(recip As String, abspath As String) As Long
    If Len(recip) = 0 OrElse Len(recip) > 255 Then
        put_line("Invalid recipient.", LINE_SYSTEM) : Return -1
    End If
    If path_is_absolute(abspath) = 0 Then
        put_line("File path must be absolute.", LINE_SYSTEM) : Return -1
    End If
    Dim bn As String = path_basename(abspath)
    If Len(bn) = 0 OrElse bn = "." OrElse bn = ".." OrElse Len(bn) > 255 Then
        put_line("Bad filename.", LINE_SYSTEM) : Return -1
    End If
    Dim f As Long = FreeFile
    If Open(abspath For Binary Access Read As #f) <> 0 Then
        put_line("Cannot open file: " & abspath, LINE_SYSTEM) : Return -1
    End If
    Dim sz As LongInt = Lof(f)
    If sz > MAX_FILE_BYTES Then
        Close #f
        put_line("File too large (> " & MAX_FILE_BYTES & " bytes).", LINE_SYSTEM) : Return -1
    End If
    Dim payload As String = Space(CLng(sz))
    If sz > 0 Then Get #f, , payload
    Close #f

    Dim body As String
    body &= Chr(Len(recip)) & recip
    body &= Chr(Len(bn))    & bn
    Dim fsz As ULong = CULng(Len(payload))
    body &= Chr((fsz Shr 24) And &hFF)
    body &= Chr((fsz Shr 16) And &hFF)
    body &= Chr((fsz Shr  8) And &hFF)
    body &= Chr( fsz         And &hFF)
    body &= payload

    Dim rc As Long = send_string_payload(PKT_FILE, body)
    If rc = 0 Then
        put_line("--> file to " & recip & ": """ & bn & """ (" & fsz & " bytes)", LINE_FILE)
    Else
        put_line("File send failed.", LINE_SYSTEM)
    End If
    Return rc
End Function

' -----------------------------------------------------------------------------
' Incoming packet handlers
' -----------------------------------------------------------------------------
Sub save_received_file(sender As String, fname As String, body As String)
    Dim bn As String = path_basename(fname)
    If Len(bn) = 0 OrElse bn = "." OrElse bn = ".." Then
        put_line("Bad filename from " & sender & ", ignored.", LINE_SYSTEM)
        Exit Sub
    End If
    Dim savepath As String = bn
    Dim idx      As Long = 1
    Do While file_exists_fn(savepath)
        If idx > 9999 Then
            put_line("Too many name collisions, dropping file.", LINE_SYSTEM)
            Exit Sub
        End If
        savepath = bn & "." & idx
        idx += 1
    Loop
    Dim f As Long = FreeFile
    If Open(savepath For Binary Access Write As #f) <> 0 Then
        put_line("Could not create file " & savepath, LINE_SYSTEM)
        Exit Sub
    End If
    If Len(body) > 0 Then Put #f, , body
    Close #f
    put_line("<-- file from " & sender & ": """ & fname & """ (" & Len(body) & _
             " bytes) saved as ./" & savepath, LINE_FILE)
End Sub

Sub on_pkt_msg(payload As String)
    Dim off  As Long = 1
    Dim room As String, sender As String
    If read_u8_string(payload, off, room)   = 0 Then Exit Sub
    If read_u8_string(payload, off, sender) = 0 Then Exit Sub
    If is_ignored(sender) Then Exit Sub
    Dim text As String = Mid(payload, off)
    If sender = g_nick Then
        put_line("[" & room & "] " & sender & ": " & text, LINE_SYSTEM)
    Else
        put_line("[" & room & "] " & sender & ": " & text, LINE_CHAT)
    End If
End Sub

Sub on_pkt_emote(payload As String)
    Dim off  As Long = 1
    Dim room As String, sender As String
    If read_u8_string(payload, off, room)   = 0 Then Exit Sub
    If read_u8_string(payload, off, sender) = 0 Then Exit Sub
    If is_ignored(sender) Then Exit Sub
    Dim text As String = Mid(payload, off)
    put_line("[" & room & "] * " & sender & " " & text & " *", LINE_EMOTE)
End Sub

Sub on_pkt_sys(payload As String)
    Dim off  As Long = 1
    Dim room As String
    If read_u8_string(payload, off, room) = 0 Then Exit Sub
    Dim text As String = Mid(payload, off)
    put_line("[" & room & "] " & text, LINE_SYSTEM)
End Sub

Sub on_pkt_err(payload As String)
    put_line("[server] " & payload, LINE_SYSTEM)
End Sub

Sub on_pkt_dm(payload As String)
    Dim off    As Long = 1
    Dim sender As String
    If read_u8_string(payload, off, sender) = 0 Then Exit Sub
    If is_ignored(sender) Then Exit Sub
    Dim text As String = Mid(payload, off)
    put_line("[DM from " & sender & "] " & text, LINE_DM)
End Sub

Sub on_pkt_file(payload As String)
    Dim off    As Long = 1
    Dim sender As String, fname As String
    If read_u8_string(payload, off, sender) = 0 Then Exit Sub
    If is_ignored(sender) Then Exit Sub
    If off > Len(payload) Then Exit Sub
    Dim fnl As Long = Asc(payload, off) : off += 1
    If fnl = 0 OrElse off + fnl - 1 > Len(payload) Then Exit Sub
    fname = Mid(payload, off, fnl) : off += fnl
    Dim fsz As ULong
    If read_be32(payload, off, fsz) = 0 Then Exit Sub
    If fsz > MAX_FILE_BYTES Then Exit Sub
    If off + CLng(fsz) - 1 <> Len(payload) Then Exit Sub
    Dim body As String = Mid(payload, off, CLng(fsz))
    save_received_file(sender, fname, body)
End Sub

Sub on_pkt_who(payload As String)
    Dim off  As Long = 1
    Dim room As String
    If read_u8_string(payload, off, room) = 0 Then Exit Sub
    If off > Len(payload) Then Exit Sub
    Dim count As Long = Asc(payload, off) : off += 1
    Dim names As String
    Dim i     As Long
    For i = 1 To count
        Dim nk As String
        If read_u8_string(payload, off, nk) = 0 Then Exit For
        If Len(names) > 0 Then names &= ", "
        names &= nk
    Next i
    put_line("[" & room & "] users (" & count & "): " & names, LINE_SYSTEM)
End Sub

Sub on_pkt_list(payload As String)
    Dim off    As Long = 1
    If off > Len(payload) Then Exit Sub
    Dim count  As Long = Asc(payload, off) : off += 1
    Dim ln_buf As String
    Dim i      As Long
    For i = 1 To count
        Dim rn As String
        If read_u8_string(payload, off, rn) = 0 Then Exit For
        If off + 1 > Len(payload) Then Exit For
        Dim nm As ULong = (CULng(Asc(payload, off)) Shl 8) Or CULng(Asc(payload, off + 1))
        off += 2
        If Len(ln_buf) > 0 Then ln_buf &= ", "
        ln_buf &= rn & "(" & nm & ")"
    Next i
    put_line("rooms (" & count & "): " & ln_buf, LINE_SYSTEM)
End Sub

Sub on_pkt_join(payload As String)
    Dim off  As Long = 1
    Dim room As String, who As String
    If read_u8_string(payload, off, room) = 0 Then Exit Sub
    If read_u8_string(payload, off, who)  = 0 Then Exit Sub
    If who = g_nick Then
        add_room_local(room)
        put_line("* you joined " & room & " *", LINE_SYSTEM)
    Else
        put_line("[" & room & "] * " & who & " joined *", LINE_SYSTEM)
    End If
End Sub

Sub on_pkt_part(payload As String)
    Dim off  As Long = 1
    Dim room As String, who As String
    If read_u8_string(payload, off, room) = 0 Then Exit Sub
    If read_u8_string(payload, off, who)  = 0 Then Exit Sub
    If who = g_nick Then
        remove_room_local(room)
        put_line("* you left " & room & " *", LINE_SYSTEM)
    Else
        put_line("[" & room & "] * " & who & " left *", LINE_SYSTEM)
    End If
End Sub

Sub on_pkt_nick(payload As String)
    Dim newnick As String = payload
    If Len(newnick) = 0 Then Exit Sub
    g_nick = newnick
    put_line("* you are now known as " & newnick & " *", LINE_SYSTEM)
    log_open(newnick)
End Sub

Sub dispatch_packet(t As UByte, p As String)
    Select Case t
        Case PKT_MSG   : on_pkt_msg(p)
        Case PKT_EMOTE : on_pkt_emote(p)
        Case PKT_SYS   : on_pkt_sys(p)
        Case PKT_ERR   : on_pkt_err(p)
        Case PKT_DM    : on_pkt_dm(p)
        Case PKT_FILE  : on_pkt_file(p)
        Case PKT_WHO   : on_pkt_who(p)
        Case PKT_LIST  : on_pkt_list(p)
        Case PKT_JOIN  : on_pkt_join(p)
        Case PKT_PART  : on_pkt_part(p)
        Case PKT_NICK  : on_pkt_nick(p)
        Case PKT_PING  : ' ignore
        Case Else      : ' ignore unknown types -- forward-compat
    End Select
End Sub

' -----------------------------------------------------------------------------
' Connect / disconnect
' -----------------------------------------------------------------------------
Sub do_disconnect(reason As String)
    If g_sock_valid Then
        vt_net_close(g_sock)
    End If
    g_sock_valid = 0
    g_recv_buf   = ""
    Dim i As Long
    For i = 0 To g_nrooms - 1 : g_rooms(i) = "" : Next i
    g_nrooms = 0
    g_current_room_idx = -1
    If Len(reason) > 0 Then put_line(reason, LINE_SYSTEM)
End Sub

Function do_connect(host As String, port As Long, passphrase As String, _
                    want_nick As String, want_room As String) As Long
    put_line("Connecting to " & host & ":" & port & " ...", LINE_SYSTEM)
    draw_ui() : vt_present()

    If vt_net_init() <> 0 Then
        put_line("Network init failed.", LINE_SYSTEM) : Return 0
    End If
    Dim ip As Long = vt_net_resolve(StrPtr(host))
    If ip = 0 Then
        put_line("DNS resolution failed for " & host, LINE_SYSTEM) : Return 0
    End If
    Dim sock As SOCKET = vt_net_open()
    If sock = INVALID_SOCKET Then
        put_line("Could not open socket.", LINE_SYSTEM) : Return 0
    End If
    If vt_net_connect(sock, ip, port) = 0 Then
        vt_net_close(sock)
        put_line("Could not connect to " & host & ":" & port, LINE_SYSTEM) : Return 0
    End If

    put_line("Deriving key (this takes a moment) ...", LINE_SYSTEM)
    draw_ui() : vt_present()
    Dim key(0 To 31) As UByte
    derive_key(passphrase, @key(0))
    aes_key_expansion(g_aes, @key(0))

    g_sock       = sock
    g_sock_valid = 1
    g_recv_buf   = ""
    vt_net_nonblocking(sock, 1)

    If send_hello(want_nick, want_room) <> 0 Then
        do_disconnect("Failed to send hello.")
        Return 0
    End If
    Return 1
End Function

' -----------------------------------------------------------------------------
' Command parsing
' -----------------------------------------------------------------------------
Sub show_help()
    put_line("Commands:", LINE_SYSTEM)
    put_line("  /join <room>             join a room (or switch to it)", LINE_SYSTEM)
    put_line("  /part [<room>]           leave a room (default: current)", LINE_SYSTEM)
    put_line("  /msg <nick> <text>       private message", LINE_SYSTEM)
    put_line("  /send <nick> <abs-path>  send a file (<= 10 MB)", LINE_SYSTEM)
    put_line("  /me <action>             emote in current room", LINE_SYSTEM)
    put_line("  /nick <newnick>          change your nickname", LINE_SYSTEM)
    put_line("  /who [<room>]            list users in a room", LINE_SYSTEM)
    put_line("  /list                    list all rooms on the server", LINE_SYSTEM)
    put_line("  /ignore [<nick>]         hide messages/DMs/files from a user", LINE_SYSTEM)
    put_line("  /unignore <nick>         stop ignoring a user", LINE_SYSTEM)
    put_line("  /quit                    disconnect", LINE_SYSTEM)
    put_line("  //text                   send a literal line starting with '/'", LINE_SYSTEM)
End Sub

Sub handle_input_line(ln As String)
    Dim s As String = Trim(ln)
    If Len(s) = 0 Then Exit Sub

    Dim is_cmd As Byte = 0
    If Left(s, 1) = "/" AndAlso Left(s, 2) <> "//" Then is_cmd = 1

    If is_cmd Then
        Dim sp     As Long = InStr(s, " ")
        Dim cmd    As String
        Dim rest   As String
        If sp > 0 Then
            cmd  = Mid(s, 1, sp - 1)
            rest = Trim(Mid(s, sp + 1))
        Else
            cmd  = s
            rest = ""
        End If
        Dim cl As String = LCase(cmd)

        Select Case cl
        Case "/quit"
            If g_sock_valid Then
                Dim dummy As UByte = 0
                send_packet(PKT_QUIT, @dummy, 0)
            End If
            do_disconnect("")
            g_quit_flag = 1

        Case "/help"
            show_help()

        Case "/list"
            If g_sock_valid = 0 Then
                put_line("Not connected.", LINE_SYSTEM) : Exit Sub
            End If
            Dim dummy As UByte = 0
            send_packet(PKT_LIST, @dummy, 0)

        Case "/who"
            Dim r As String = rest
            If Len(r) = 0 Then r = get_current_room()
            If Len(r) = 0 Then
                put_line("Not in any room.", LINE_SYSTEM) : Exit Sub
            End If
            send_simple_string(PKT_WHO, r)

        Case "/join"
            If Len(rest) = 0 Then
                put_line("Usage: /join <room>", LINE_SYSTEM) : Exit Sub
            End If
            If name_is_valid(rest, MAX_ROOM) = 0 Then
                put_line("Invalid room name.", LINE_SYSTEM) : Exit Sub
            End If
            Dim idx As Long = find_room_idx(rest)
            If idx >= 0 Then
                g_current_room_idx = idx
                put_line("* switched to room " & rest & " *", LINE_SYSTEM)
                df_input = 1
            Else
                send_simple_string(PKT_JOIN, rest)
            End If

        Case "/part"
            Dim r As String = rest
            If Len(r) = 0 Then r = get_current_room()
            If Len(r) = 0 Then
                put_line("Not in any room.", LINE_SYSTEM) : Exit Sub
            End If
            send_simple_string(PKT_PART, r)

        Case "/nick"
            If Len(rest) = 0 Then
                put_line("Usage: /nick <newnick>", LINE_SYSTEM) : Exit Sub
            End If
            If name_is_valid(rest, MAX_NICK) = 0 Then
                put_line("Invalid nickname.", LINE_SYSTEM) : Exit Sub
            End If
            send_simple_string(PKT_NICK, rest)

        Case "/me"
            If Len(rest) = 0 Then
                put_line("Usage: /me <action>", LINE_SYSTEM) : Exit Sub
            End If
            Dim room As String = get_current_room()
            If Len(room) = 0 Then
                put_line("Not in any room.", LINE_SYSTEM) : Exit Sub
            End If
            send_room_text(PKT_EMOTE, room, rest)

        Case "/msg"
            Dim sp2 As Long = InStr(rest, " ")
            If sp2 = 0 OrElse Len(Trim(Mid(rest, sp2 + 1))) = 0 Then
                put_line("Usage: /msg <nick> <text>", LINE_SYSTEM) : Exit Sub
            End If
            Dim toNick As String = Mid(rest, 1, sp2 - 1)
            Dim text   As String = Trim(Mid(rest, sp2 + 1))
            If send_dm(toNick, text) = 0 Then
                put_line("[DM to " & toNick & "] " & text, LINE_DM)
            End If

        Case "/send"
            Dim sp3 As Long = InStr(rest, " ")
            If sp3 = 0 OrElse Len(Trim(Mid(rest, sp3 + 1))) = 0 Then
                put_line("Usage: /send <nick> <absolute-path>", LINE_SYSTEM) : Exit Sub
            End If
            Dim toNick As String = Mid(rest, 1, sp3 - 1)
            Dim path   As String = Trim(Mid(rest, sp3 + 1))
            send_file_to(toNick, path)

        Case "/ignore"
            If Len(rest) = 0 Then
                If g_nignored = 0 Then
                    put_line("No users ignored.", LINE_SYSTEM)
                Else
                    Dim ln_out As String = "Ignoring (" & g_nignored & "): "
                    Dim i As Long
                    For i = 0 To g_nignored - 1
                        If i > 0 Then ln_out &= ", "
                        ln_out &= g_ignored(i)
                    Next i
                    put_line(ln_out, LINE_SYSTEM)
                End If
            Else
                If name_is_valid(rest, MAX_NICK) = 0 Then
                    put_line("Invalid nickname.", LINE_SYSTEM) : Exit Sub
                End If
                If rest = g_nick Then
                    put_line("You cannot ignore yourself.", LINE_SYSTEM) : Exit Sub
                End If
                Select Case ignore_add(rest)
                Case 0 : put_line("* ignoring " & rest & " *", LINE_SYSTEM)
                Case 1 : put_line("* already ignoring " & rest & " *", LINE_SYSTEM)
                Case 2 : put_line("Ignore list is full (max " & MAX_IGNORED & ").", LINE_SYSTEM)
                End Select
            End If

        Case "/unignore"
            If Len(rest) = 0 Then
                put_line("Usage: /unignore <nick>", LINE_SYSTEM) : Exit Sub
            End If
            If ignore_remove(rest) Then
                put_line("* no longer ignoring " & rest & " *", LINE_SYSTEM)
            Else
                put_line("* " & rest & " was not ignored *", LINE_SYSTEM)
            End If

        Case Else
            put_line("Unknown command: " & cmd & "  (try /help)", LINE_SYSTEM)
        End Select
        Exit Sub
    End If

    ' Regular chat line (with possible // prefix)
    Dim text As String = s
    If Left(s, 2) = "//" Then text = Mid(s, 2)
    Dim room As String = get_current_room()
    If Len(room) = 0 Then
        put_line("Not in any room; /join one first.", LINE_SYSTEM)
        Exit Sub
    End If
    If g_sock_valid = 0 Then
        put_line("Not connected.", LINE_SYSTEM) : Exit Sub
    End If
    send_room_text(PKT_MSG, room, text)
End Sub

' -----------------------------------------------------------------------------
' Close callback
' -----------------------------------------------------------------------------
Function on_close() As Byte
    g_quit_flag = 1
    Return 1
End Function

' =============================================================================
' Main
' =============================================================================
' Walk the raw command line, peel off option flags, leave positionals in args().
Dim args(0 To 5) As String
Dim narg     As Long = 0
Dim big_font As Byte = 0
Dim ci       As Long = 0
Do
    Dim a As String = Command(ci)
    If Len(a) = 0 Then Exit Do
    If ci = 0 Then
        args(narg) = a : narg += 1   ' argv[0]: program name
    ElseIf a = "--big" OrElse a = "-b" Then
        big_font = 1
    ElseIf a = "--small" OrElse a = "-s" Then
        big_font = 0
    Else
        If narg <= 5 Then args(narg) = a
        narg += 1
    End If
    ci += 1
Loop

Dim host       As String
Dim port       As Long
Dim passphrase As String
Dim want_nick  As String
Dim want_room  As String

' Decide whether the args look ok. Don't print anything yet -- under -s gui
' on Windows there is no stdout to print to, so any usage message has to be
' shown in the vt window after vt_screen is up.
Dim usage_err As String
If narg < 4 OrElse narg > 6 Then
    usage_err = "Usage:  khn-client-fb [--big] <server> <port> <keyphrase> [<nickname>] [<room>]" & Chr(10) & _
                Chr(10) & _
                "Pass """" for nickname or room to let the server pick one." & Chr(10) & _
                "--big (or -b) uses the 16x24 font; default is 8x16."
Else
    host       = args(1)
    port       = ValInt(args(2))
    passphrase = args(3)
    If narg >= 5 Then want_nick = args(4)
    If narg >= 6 Then want_room = args(5)
    If port <= 0 OrElse port > 65535 Then
        usage_err = "Port out of range (must be 1..65535)."
    ElseIf Len(passphrase) = 0 Then
        usage_err = "Keyphrase cannot be empty."
    End If
End If

vt_title(APP_NAME & " " & APP_VERSION & " (FreeBASIC)")
Dim fnt_w As Long = IIf(big_font, 16, 8)
Dim fnt_h As Long = IIf(big_font, 24, 16)
If vt_screen(VT_SCREENPARAM(g_cols, g_rows, fnt_w, fnt_h), VT_WINDOWED) <> 0 Then End 1

' Bad command line: show the usage in the window and wait for a keypress
' before exiting. (Print to stdout doesn't reach the user under -s gui.)
If Len(usage_err) > 0 Then
    vt_cls(VT_BLACK)
    vt_color(VT_YELLOW, VT_BLACK)
    vt_locate(2, 2)
    Dim ue_lines() As String
    Dim ue_n       As Long = vt_str_split(usage_err, Chr(10), ue_lines())
    Dim ue_i       As Long
    For ue_i = 0 To ue_n - 1
        vt_locate(2 + ue_i, 2)
        vt_print(ue_lines(ue_i))
    Next ue_i
    vt_color(VT_LIGHT_GREY, VT_BLACK)
    vt_locate(vt_rows() - 1, 2)
    vt_print("Press any key to exit.")
    vt_present()
    Do
        Dim ue_k As ULong = vt_inkey()
        If ue_k <> 0 Then Exit Do
        vt_sleep(50)
    Loop
    vt_shutdown()
    End 2
End If
g_cols = vt_cols()
g_rows = vt_rows()
screen_relayout()
vt_screen_minimum(MIN_SCREEN_COLS, MIN_SCREEN_ROWS)
vt_scroll_enable(0)
vt_mouse(1)
vt_locate(,,,95)
vt_on_close(@on_close)
vt_copypaste(VT_ENABLED)

vt_tui_theme(col_body, col_bg, _
             VT_WHITE, VT_BLUE, _
             col_bar_fg, col_bar_bg, _
             VT_BLACK, VT_LIGHT_GREY, _
             VT_BLACK, VT_LIGHT_GREY, _
             col_body, col_bg)

input_form(0).kind    = VT_FORM_INPUT
input_form(0).max_len = MAX_TEXT
input_form(0).val     = ""
input_form(0).cpos    = 0

g_nick = want_nick

put_line(APP_NAME & " " & APP_VERSION & " - FreeBASIC client", LINE_SYSTEM)
put_line("Server:  " & host & ":" & port, LINE_SYSTEM)
If Len(want_nick) > 0 Then put_line("Nick:    " & want_nick, LINE_SYSTEM)
If Len(want_room) > 0 Then put_line("Room:    " & want_room, LINE_SYSTEM)
put_line("Type /help for commands.", LINE_SYSTEM)
draw_ui() : vt_present()

If do_connect(host, port, passphrase, want_nick, want_room) = 0 Then
    draw_ui() : vt_present()
    vt_sleep(2000)
    vt_shutdown()
    End 1
End If

' Wait synchronously for the HELLO ack (or ERR) so we know our nick/room.
Dim hello_deadline As Double = Timer + 5.0
Do
    If g_sock_valid = 0 Then Exit Do
    If Timer > hello_deadline Then
        do_disconnect("No HELLO ack from server (bad keyphrase?).")
        Exit Do
    End If
    If vt_net_ready(g_sock, 0, 100) = 1 Then
        Dim tmp As ZString * 16385
        Dim n   As Long = vt_net_recv(g_sock, @tmp, 16384)
        If n <= 0 Then
            do_disconnect("Server hung up during handshake (bad keyphrase?).")
            Exit Do
        End If
        Dim chunk As String = Space(n)
        memcpy(StrPtr(chunk), @tmp, n)
        g_recv_buf &= chunk
    End If
    If Len(g_recv_buf) >= 4 Then
        Dim framelen As ULong = _
            (CULng(Asc(g_recv_buf, 1)) Shl 24) Or _
            (CULng(Asc(g_recv_buf, 2)) Shl 16) Or _
            (CULng(Asc(g_recv_buf, 3)) Shl  8) Or _
             CULng(Asc(g_recv_buf, 4))
        If framelen < 32 OrElse framelen > MAX_FRAME Then
            do_disconnect("Bad frame length from server (bad keyphrase?).")
            Exit Do
        End If
        If CULng(Len(g_recv_buf)) >= 4 + framelen Then
            Dim ct_len As Long = framelen - 16
            Dim pt As UByte Ptr = Cast(UByte Ptr, Allocate(ct_len))
            Dim plen As Long = aes_cbc_decrypt(g_aes, _
                Cast(UByte Ptr, StrPtr(g_recv_buf)) + 4, _
                Cast(UByte Ptr, StrPtr(g_recv_buf)) + 20, _
                ct_len, pt)
            If plen < 1 Then
                Deallocate(pt)
                do_disconnect("Decrypt failed (bad keyphrase?).")
                Exit Do
            End If
            Dim ptype As UByte = pt[0]
            Dim payload_len As Long = plen - 1
            Dim payload As String = Space(payload_len)
            If payload_len > 0 Then memcpy(StrPtr(payload), pt + 1, payload_len)
            Deallocate(pt)
            g_recv_buf = Mid(g_recv_buf, 5 + framelen)

            If ptype = PKT_HELLO Then
                Dim off As Long = 1
                Dim nk  As String, rm As String
                read_u8_string(payload, off, nk)
                read_u8_string(payload, off, rm)
                g_nick = nk
                add_room_local(rm)
                put_line("Connected as """ & nk & """ in room """ & rm & """.", LINE_SYSTEM)
                log_open(nk)
                Exit Do
            ElseIf ptype = PKT_ERR Then
                put_line("Server rejected: " & payload, LINE_SYSTEM)
                do_disconnect("")
                Exit Do
            Else
                dispatch_packet(ptype, payload)
            End If
        End If
    End If
Loop

' -----------------------------------------------------------------------------
' Event loop
' -----------------------------------------------------------------------------
Dim k        As ULong
Dim prev_val As String

Do
    k = vt_inkey()
    If k <> 0 Then df_input = 1
    check_resize()

    Select Case VT_SCAN(k)
    Case VT_KEY_F1
        show_help()
    Case VT_KEY_F10
        If g_sock_valid Then
            Dim dummy As UByte = 0
            send_packet(PKT_QUIT, @dummy, 0)
        End If
        do_disconnect("")
        g_quit_flag = 1
    Case VT_KEY_PGUP
        Dim max_scr As Long = g_hist_count - g_chat_rows
        If max_scr > 0 AndAlso g_top_line < max_scr Then
            g_top_line += 3
            If g_top_line > max_scr Then g_top_line = max_scr
            df_hist = 1
        End If
    Case VT_KEY_PGDN
        If g_top_line > 3 Then
            g_top_line -= 3
        Else
            g_top_line = 0
        End If
        df_hist = 1
    Case VT_KEY_END
        If g_top_line <> 0 Then
            g_top_line = 0
            df_hist = 1
        End If
        prev_val = input_form(0).val
        vt_tui_form_handle(input_form(), input_focused, k, VT_FORM_NO_ESC)
        If input_form(0).val <> prev_val Then df_input = 1
    Case VT_KEY_ENTER
        If Len(input_form(0).val) > 0 Then
            Dim ln As String = input_form(0).val
            input_form(0).val      = ""
            input_form(0).cpos     = 0
            input_form(0).view_off = 0
            handle_input_line(ln)
            g_top_line = 0
            df_input = 1
        End If
    Case Else
        prev_val = input_form(0).val
        vt_tui_form_handle(input_form(), input_focused, k, VT_FORM_NO_ESC)
        If input_form(0).val <> prev_val Then df_input = 1
    End Select

    Dim mx As Long, my As Long, mb As Long, whl As Long
    vt_getmouse(@mx, @my, @mb, @whl)
    If whl <> 0 Then
        df_hist = 1
        If whl > 0 Then
            Dim max_scr As Long = g_hist_count - g_chat_rows
            If max_scr > 0 AndAlso g_top_line < max_scr Then
                g_top_line += whl
                If g_top_line > max_scr Then g_top_line = max_scr
            End If
        Else
            g_top_line += whl
            If g_top_line < 0 Then g_top_line = 0
        End If
    End If

    poll_recv()

    draw_ui()
    vt_sleep(16)
Loop Until g_quit_flag

If g_sock_valid Then
    Dim dummy As UByte = 0
    send_packet(PKT_QUIT, @dummy, 0)
    vt_net_close(g_sock)
End If
vt_net_shutdown()
log_close()
vt_shutdown()
