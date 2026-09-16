#!/usr/bin/env python3
"""One-shot publisher input; not part of either runtime or final fix branch."""
from pathlib import Path
import sys

root = Path(sys.argv[1])
backport = len(sys.argv) > 2 and sys.argv[2] == 'backport'

def replace(path, old, new):
    path = root / path
    text = path.read_text()
    assert text.count(old) == 1, (path, old[:80], text.count(old))
    path.write_text(text.replace(old, new))

replace('net/netmon/state.go', '\tvar regular4, regular6, linklocal4, ula6 []netip.Addr\n', '''\treturn localAddresses(ifaces)
}

// localAddresses separates enumeration from policy so topology changes can be
// tested without modifying the host's network interfaces.
func localAddresses(ifaces []Interface) (regular, loopback []netip.Addr, err error) {
\tvar regular4, regular6, linklocal4, ula6 []netip.Addr
''')
replace('net/netmon/state.go', '\t\tif !isUp(stdIf) || isProblematicInterface(stdIf) {', '\t\tif stdIf == nil || !isUp(stdIf) || isProblematicInterface(stdIf) || isTailscaleInterface(stdIf.Name, nil) {')
replace('net/netmon/state.go', '\t\tifcIsLoopback := isLoopback(stdIf)\n', '''\t\tifcIsLoopback := isLoopback(stdIf)
\t\t// RFC 6598 addresses can belong to the underlay (for example, campus
\t\t// Wi-Fi or an ISP). Permit them on Ethernet-like interfaces, including
\t\t// bridges/veths, but keep filtering them on unclassified L3 tunnels.
\t\t// A range check alone cannot identify a Tailscale interface.
\t\tallowCGNAT := stdIf.Flags&net.FlagBroadcast != 0 &&
\t\t\tstdIf.Flags&(net.FlagLoopback|net.FlagPointToPoint) == 0
''')
replace('net/netmon/state.go', '''\t\t\t\t// TODO(apenwarr): don't special case cgNAT.
\t\t\t\t// In the general wireguard case, it might
\t\t\t\t// very well be something we can route to
\t\t\t\t// directly, because both nodes are
\t\t\t\t// behind the same CGNAT router.
\t\t\t\tif tsaddr.IsTailscaleIP(ip) {''', '''\t\t\t\t// Never advertise Tailscale's IPv6 ULA, or CGNAT addresses on
\t\t\t\t// loopback/point-to-point/unknown non-broadcast interfaces.
\t\t\t\tif tsaddr.IsTailscaleIP(ip) && (!ip.Is4() || !allowCGNAT) {''')
replace('net/netmon/state.go', '''\tif err == nil {
\t\t// If we've been told the Tailscale interface name, use that.
\t\treturn name == tsIfName
\t}''', '''\tif err == nil && name == tsIfName {
\t\treturn true
\t}
\t// A registered custom name does not make other Tailscale interfaces
\t// safe underlays. Keep the conventional-name/address checks below.''')
replace('net/netmon/interfaces.go', 'func SetTailscaleInterfaceProps(ifName string, ifIndex int) {\n', '''func SetTailscaleInterfaceProps(ifName string, ifIndex int) {
\t// An embedding application releases these process-global properties when
\t// its endpoint closes. Clearing must not depend on OS enumeration working.
\tif ifName == "" {
\t\ttsIfProps.set("", 0)
\t\treturn
\t}
''')
f = root / 'util/linuxfw/iptables_runner.go'
s = f.read_text()
start = s.index('func (i *iptablesRunner) AddMagicsockPortRule(')
end = s.index('\n// DelMagicsockPortRule', start)
part = s[start:end]
assert part.count('ipt.Append("filter", "ts-input", args...)') == 1
part = part.replace('if err := ipt.Append("filter", "ts-input", args...);', '''// Encrypted transport must reach magicsock before the CGNAT spoofing
\t// drop. Only this UDP destination port is exempt; other CGNAT traffic
\t// still traverses the existing INPUT and FORWARD protections.
\tif err := ipt.Insert("filter", "ts-input", 1, args...);''')
f.write_text((s[:start]+part+s[end:]).replace('// to Append() and Delete().', '// to Insert() and Delete().'))
replace('util/linuxfw/nftables_runner.go', '''\trule := createAcceptOnPortRule(table, chain, port)
\t_ = conn.AddRule(rule)''', '''\trule := createAcceptOnPortRule(table, chain, port)
\t// Prepend the transport-only exception before CGNAT drop/return rules.
\t// Do not remove or broaden the spoofing protections for other traffic.
\t_ = conn.InsertRule(rule)''')

(root / 'net/netmon/local_addresses_cgnat_test.go').write_text(r'''// Copyright (c) Tailscale Inc & contributors
// SPDX-License-Identifier: BSD-3-Clause

package netmon

import (
 "net"
 "net/netip"
 "reflect"
 "testing"
)

func cgnatTestInterface(name string, flags net.Flags, addresses ...string) Interface {
 addrs := make([]net.Addr, 0, len(addresses))
 for _, address := range addresses {
  p := netip.MustParsePrefix(address)
  addrs = append(addrs, &net.IPNet{IP: p.Addr().AsSlice(), Mask: net.CIDRMask(p.Bits(), p.Addr().BitLen())})
 }
 return Interface{Interface: &net.Interface{Name: name, Flags: flags}, AltAddrs: addrs}
}

func TestLocalAddressesCGNATUnderlay(t *testing.T) {
 oldName, _ := TailscaleInterfaceName()
 oldIndex, _ := TailscaleInterfaceIndex()
 t.Cleanup(func() { SetTailscaleInterfaceProps(oldName, oldIndex) })
 SetTailscaleInterfaceProps("custom-tap", 42)
 up := net.FlagUp
 lan := up | net.FlagBroadcast | net.FlagMulticast
 cases := []struct { name string; iface Interface; want []netip.Addr }{
  {"wifi", cgnatTestInterface("en0", lan, "100.65.10.7/16"), []netip.Addr{netip.MustParseAddr("100.65.10.7")}},
  {"ethernet", cgnatTestInterface("eth0", lan, "100.64.10.8/24"), []netip.Addr{netip.MustParseAddr("100.64.10.8")}},
  {"bridge", cgnatTestInterface("br0", lan, "100.64.11.8/24"), []netip.Addr{netip.MustParseAddr("100.64.11.8")}},
  {"renamed-tun", cgnatTestInterface("overlay0", up|net.FlagPointToPoint, "100.100.10.1/32"), nil},
  {"wireguard", cgnatTestInterface("wg0", up, "100.100.10.1/32"), nil},
  {"utun", cgnatTestInterface("utun101", up|net.FlagPointToPoint, "100.100.10.1/32", "fd7a:115c:a1e0::1/128"), nil},
  {"registered-tap", cgnatTestInterface("custom-tap", lan, "100.100.10.1/32", "192.168.99.1/24"), nil},
  {"other-tailscale", cgnatTestInterface("tailscale0", lan, "100.100.10.1/32"), nil},
  {"tailscale-ula", cgnatTestInterface("en0", lan, "fd7a:115c:a1e0::1/128"), nil},
  {"down", cgnatTestInterface("en0", net.FlagBroadcast, "100.65.10.7/16"), nil},
  {"loopback-cgnat", cgnatTestInterface("lo0", up|net.FlagLoopback, "100.65.10.7/32"), nil},
  {"problematic-overlay", cgnatTestInterface("zt0", lan, "100.65.10.7/16"), nil},
  {"nil-interface", Interface{}, nil},
 }
 for _, tt := range cases {
  t.Run(tt.name, func(t *testing.T) {
   got, _, err := localAddresses([]Interface{tt.iface})
   if err != nil { t.Fatal(err) }
   if !reflect.DeepEqual(got, tt.want) { t.Fatalf("got %v, want %v", got, tt.want) }
  })
 }
}

func TestLocalAddressesCGNATHandover(t *testing.T) {
 lan := net.FlagUp|net.FlagBroadcast
 for _, address := range []string{"100.65.10.7/16", "100.64.11.8/24"} {
  got, _, err := localAddresses([]Interface{
   cgnatTestInterface("en0", lan, address),
   cgnatTestInterface("utun101", net.FlagUp|net.FlagPointToPoint, "100.100.10.1/32"),
  })
  want := netip.MustParsePrefix(address).Addr()
  if err != nil || len(got) != 1 || got[0] != want { t.Fatalf("handover to %s: got %v, err %v", address, got, err) }
 }
}

func TestLocalAddressesPreservesFallbacks(t *testing.T) {
 lan := net.FlagUp|net.FlagBroadcast
 regular, loopback, err := localAddresses([]Interface{
  cgnatTestInterface("eth0", lan, "192.168.1.5/24", "2001:db8::1/64", "2001:db8::2/64", "2001:db8::3/64", "fe80::1/64"),
  cgnatTestInterface("lo", net.FlagUp|net.FlagLoopback, "127.0.0.1/8"),
 })
 if err != nil || len(regular) != 3 || len(loopback) != 1 { t.Fatalf("regular=%v loopback=%v err=%v", regular, loopback, err) }
 regular, _, err = localAddresses([]Interface{cgnatTestInterface("eth0", lan, "169.254.1.2/16", "fd00::1/64", "fe80::1/64")})
 if err != nil || len(regular) != 2 { t.Fatalf("fallback=%v err=%v", regular, err) }
}

func TestClearTailscaleInterfaceProps(t *testing.T) {
 oldName, _ := TailscaleInterfaceName()
 oldIndex, _ := TailscaleInterfaceIndex()
 t.Cleanup(func() { SetTailscaleInterfaceProps(oldName, oldIndex) })
 SetTailscaleInterfaceProps("custom-tun", 42)
 SetTailscaleInterfaceProps("", 0)
 if name, err := TailscaleInterfaceName(); err == nil || name != "" { t.Fatalf("name not cleared: %q, %v", name, err) }
 if index, err := TailscaleInterfaceIndex(); err == nil || index != 0 { t.Fatalf("index not cleared: %d, %v", index, err) }
}
''')
(root / 'util/linuxfw/magicsock_cgnat_test.go').write_text(r'''// Copyright (c) Tailscale Inc & contributors
// SPDX-License-Identifier: BSD-3-Clause

//go:build linux

package linuxfw

import (
 "fmt"
 "slices"
 "testing"
 "github.com/google/nftables"
 "github.com/mdlayher/netlink"
 "golang.org/x/sys/unix"
)

type cgnatRecordingIPTables struct { iptablesInterface; rules [][]string }
func (r *cgnatRecordingIPTables) Insert(table, chain string, pos int, args ...string) error {
 if table != "filter" || chain != "ts-input" || pos < 1 || pos > len(r.rules)+1 { return fmt.Errorf("bad insertion: %s/%s/%d", table, chain, pos) }
 r.rules = slices.Insert(r.rules, pos-1, slices.Clone(args)); return nil
}
func (r *cgnatRecordingIPTables) Append(table, chain string, args ...string) error {
 r.rules = append(r.rules, slices.Clone(args)); return nil
}
func (r *cgnatRecordingIPTables) Delete(table, chain string, args ...string) error {
 for i, rule := range r.rules { if slices.Equal(rule, args) { r.rules = slices.Delete(r.rules, i, i+1); return nil } }
 return fmt.Errorf("rule not found")
}
func TestMagicsockCGNATIPTablesOrderAndCleanup(t *testing.T) {
 for _, network := range []string{"udp4", "udp6"} {
  t.Run(network, func(t *testing.T) {
   drop := []string{"!", "-i", "tailscale0", "-s", "100.64.0.0/10", "-j", "DROP"}
   recorder := &cgnatRecordingIPTables{rules: [][]string{slices.Clone(drop)}}
   r := &iptablesRunner{ipt4: recorder, ipt6: recorder}
   for _, port := range []uint16{41641, 41642} {
    if err := r.AddMagicsockPortRule(port, network); err != nil { t.Fatal(err) }
    if !slices.Equal(recorder.rules[0], buildMagicsockPortRule(port)) { t.Fatal("transport exception is behind CGNAT drop") }
    if !slices.Equal(recorder.rules[1], drop) { t.Fatal("CGNAT spoofing protection changed") }
    if err := r.DelMagicsockPortRule(port, network); err != nil { t.Fatal(err) }
    if len(recorder.rules) != 1 || !slices.Equal(recorder.rules[0], drop) { t.Fatal("cleanup changed unrelated rules") }
   }
   if err := r.AddMagicsockPortRule(41641, "tcp4"); err == nil { t.Fatal("accepted unsupported transport") }
  })
 }
}
func TestMagicsockCGNATNFTablesPrepend(t *testing.T) {
 for _, family := range []nftables.TableFamily{nftables.TableFamilyIPv4, nftables.TableFamilyIPv6} {
  rules := 0
  conn, err := nftables.New(nftables.WithTestDial(func(messages []netlink.Message) ([]netlink.Message, error) {
   for _, msg := range messages {
    if uint16(msg.Header.Type) != uint16(unix.NFNL_SUBSYS_NFTABLES<<8|unix.NFT_MSG_NEWRULE) { continue }
    rules++
    if msg.Header.Flags&netlink.HeaderFlags(unix.NLM_F_APPEND) != 0 { t.Error("transport exception was appended, not prepended") }
   }
   return nil, nil
  }))
  if err != nil { t.Fatal(err) }
  table := &nftables.Table{Name: "filter", Family: family}
  chain := &nftables.Chain{Name: "ts-input", Table: table}
  if err := addAcceptOnPortRule(conn, table, chain, 41641); err != nil { t.Fatal(err) }
  if rules != 1 { t.Fatalf("wrote %d transport rules, want 1", rules) }
 }
}
''')
integration = r'''// Copyright (c) Tailscale Inc & contributors
// SPDX-License-Identifier: BSD-3-Clause

//go:build linux && cgnat_integration && !ts_omit_iptables

package linuxfw

import (
 "bytes"
 "fmt"
 "net"
 "os"
 "os/exec"
 "strconv"
 "testing"
 "time"
)

// Run only inside the two disposable namespaces made by the CI harness. This
// exercises real kernel packet filtering, not a source-text/order assertion.
func TestCGNATTransportKernel(t *testing.T) {
 mode := os.Getenv("TS_CGNAT_TEST_FIREWALL")
 if mode == "" { t.Skip("requires isolated cgnat-host/cgnat-peer namespaces") }
 if os.Geteuid() != 0 { t.Fatal("requires root in disposable namespace") }
 if _, err := net.InterfaceByName("cghost"); err != nil { t.Fatal("refusing to change firewall outside test namespace") }
 var runner NetfilterRunner
 var err error
 switch mode {
 case "iptables": runner, err = newIPTablesRunner(t.Logf)
 case "nftables": runner, err = newNfTablesRunner(t.Logf)
 default: t.Fatalf("unsupported test firewall %q", mode)
 }
 if err != nil { t.Fatal(err) }
 must := func(err error) { t.Helper(); if err != nil { t.Fatal(err) } }
 must(runner.AddChains())
 t.Cleanup(func() {
  if err := runner.DelHooks(t.Logf); err != nil { t.Error(err) }
  if err := runner.DelChains(); err != nil { t.Error(err) }
 })
 must(runner.AddHooks())
 must(runner.AddBase("tailscale0"))
 must(runner.AddExternalCGNATRules(CGNATModeDrop, "tailscale0"))
 listen := func(port int) *net.UDPConn {
  c, err := net.ListenUDP("udp4", &net.UDPAddr{IP: net.ParseIP("100.64.50.2"), Port: port})
  must(err); t.Cleanup(func() { c.Close() }); return c
 }
 first, second := listen(41641), listen(41642)
 probe := func(c *net.UDPConn, accepted bool) {
  t.Helper()
  code := `import socket,sys
s=socket.socket(socket.AF_INET,socket.SOCK_DGRAM)
s.bind(("100.64.50.1",0)); s.settimeout(1)
s.sendto(b"cgnat-regression",("100.64.50.2",int(sys.argv[1])))
try: ok=s.recv(128)==b"cgnat-regression"
except socket.timeout: ok=False
sys.exit(0 if ok==(sys.argv[2]=="true") else 1)`
  cmd := exec.Command("ip", "netns", "exec", "cgnat-peer", "python3", "-c", code, strconv.Itoa(c.LocalAddr().(*net.UDPAddr).Port), strconv.FormatBool(accepted))
  var output bytes.Buffer; cmd.Stdout=&output; cmd.Stderr=&output
  must(c.SetReadDeadline(time.Now().Add(1500*time.Millisecond)))
  must(cmd.Start())
  buf := make([]byte,128)
  n, peer, readErr := c.ReadFromUDP(buf)
  if readErr == nil { _, err = c.WriteToUDP(buf[:n],peer); must(err) }
  commandErr := cmd.Wait()
  if accepted != (readErr==nil) { t.Fatalf("accepted=%v, read=%v",accepted,readErr) }
  if readErr != nil { if ne,ok:=readErr.(net.Error); !ok || !ne.Timeout() { t.Fatal(readErr) } }
  if commandErr != nil { t.Fatalf("peer probe: %v: %s",commandErr,output.String()) }
  t.Logf("%s UDP/%d accepted=%v",mode,c.LocalAddr().(*net.UDPAddr).Port,accepted)
 }
 probe(first,false)
 must(runner.AddMagicsockPortRule(41641,"udp4"))
 probe(first,true)
 probe(second,false)
 tcp,err:=net.Listen("tcp4","100.64.50.2:41641"); must(err); defer tcp.Close()
 code:=`import socket,sys
s=socket.socket(); s.settimeout(0.5)
sys.exit(1 if s.connect_ex(("100.64.50.2",41641))==0 else 0)`
 if out,err:=exec.Command("ip","netns","exec","cgnat-peer","python3","-c",code).CombinedOutput(); err!=nil { t.Fatal(fmt.Errorf("non-UDP spoof protection: %w: %s",err,out)) }
 must(runner.DelMagicsockPortRule(41641,"udp4"))
 must(runner.AddMagicsockPortRule(41642,"udp4"))
 probe(first,false)
 probe(second,true)
 must(runner.DelMagicsockPortRule(41642,"udp4"))
 probe(second,false)
}
'''
if backport:
    integration = integration.replace(' must(runner.AddExternalCGNATRules(CGNATModeDrop, "tailscale0"))\n', '')
(root / 'util/linuxfw/magicsock_cgnat_integration_test.go').write_text(integration)
(root / 'CGNAT_DIRECT_UDP.md').write_text('''# Direct UDP over an overlapping RFC 6598 underlay

This fork advertises CGNAT IPv4 addresses from up, broadcast-capable Ethernet-like
interfaces (Wi-Fi, Ethernet, bridges and veths). It excludes registered/conventional
Tailscale interfaces, loopback, point-to-point and unclassified non-broadcast
CGNAT interfaces, and the Tailscale IPv6 ULA. Addresses are re-enumerated rather
than cached, so DHCP changes do not require hard-coded endpoint addresses.

Both Linux firewall implementations put the existing magicsock UDP destination
port exception before CGNAT drop/return rules. Other UDP ports, TCP and forwarded
traffic retain their existing protections. This does not disable netfilter or
add a blanket CGNAT allow. The UDP listener still authenticates transport packets.

For a sing-box system endpoint, use the matching sing-box integration and a fixed
`listen_port` when a host firewall needs a stable destination port. The Linux
standalone peer needs this discovery/firewall fix too. Updating only the Mac
cannot make an unadvertised/filtered peer reachable.

A campus AP/controller can still block station-to-station UDP. Passing these
regression tests is not proof of reachability on that physical network. Confirm
both peers advertise their current underlay addresses and that native Tailscale
ping reports a direct physical address:port rather than DERP. Packet captures
must distinguish no packet reaching an interface from a local firewall drop.

The kernel test is deliberately opt-in (`cgnat_integration` build tag), requires
root and a fixture interface, and is run only in disposable network namespaces.
It verifies UDP round trips, rejects a different UDP port and TCP on the same
port, then verifies port replacement and cleanup with iptables and nftables.
''')
