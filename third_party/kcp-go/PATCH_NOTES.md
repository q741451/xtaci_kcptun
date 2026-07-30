# Vendored copy of github.com/xtaci/kcp-go v5.2.8+incompatible

This is the real v5.2.8 release source (`fec.go`, `kcp.go`,
`readloop_generic.go`, `snmp.go`, `updater.go` are byte-identical to upstream;
`crypt.go`, `entropy.go` and `sess.go` carry the small changes below; test
files and README images were dropped since they're not needed to build). `go.mod` was added because Go modules requires
a `replace` target to be a real module.

## Change 1: the cipher suite moved to `crypt/`

`crypt.go` and `entropy.go` were moved verbatim into subpackage `crypt` so the
cipher suite can be linked on its own. kcptun's `udptun` binaries need
`BlockCrypt` and nothing else; importing `kcp` for it would pull in
reedsolomon, gopacket-free but still ~0.9MB of FEC and KCP state machine they
never execute.

Three mechanical edits came with the move: the `package` line; a local
`mtuLimit` constant (it lived in `sess.go`, and `NewSimpleXORBlockCrypt` sizes
its key table with it -- it must stay 1500 or `-crypt xor` changes on the
wire); and `NewNonceAES128`, since `sess.go` previously built the unexported
`nonceAES128` directly. `crypt_alias.go` re-exports every name under its
original `kcp.` path, so kcp's own API is unchanged.

## Change 2: `readloop_linux.go`

Upstream v5.2.8's Linux read loop (`UDPSession.readLoop` / `Listener.monitor`)
unconditionally wraps the connection in `golang.org/x/net/ipv4.NewPacketConn`
for batched recvmmsg-based I/O. That helper does an unchecked
`c.(net.Conn)` type assertion internally
(`golang.org/x/net/internal/socket.NewConn`), and even after that assertion
succeeds it only recognizes `*net.TCPConn`/`*net.UDPConn`/`*net.IPConn` via a
concrete type switch -- anything else, including kcptun's `rawtcp.Conn` (see
`../../rawtcp`), either panics (if it doesn't satisfy `net.Conn`) or silently
stops receiving on the first `ReadBatch` call (if it does, since the type
switch's default case still fails and monitor()/readLoop() just returns).

Fixed by porting exactly the guard upstream itself added in v5.4.x: check
`_, ok := conn.(*net.UDPConn)` before taking the batched fast path, and fall
back to a plain `ReadFrom` loop (identical to the `!linux` build's version in
`readloop_generic.go`, just inlined under a different name so both can
coexist in one `linux`-tagged file) otherwise.

Nothing else changed. In particular the read-loop fix deliberately does NOT pull in the
unrelated changes that shipped between v5.2.8 and v5.4.x (e.g. a real
flow-control off-by-one fix in `kcp.go`'s receive-window accounting, and a
renumbering of `KCP.Recv`'s internal error codes) -- keeping this frozen
kcptun branch's UDP-mode behavior identical to the actual 2019-04-28 release
was judged more valuable than picking up incidental fixes. Revisit that
trade-off if it ever matters.
