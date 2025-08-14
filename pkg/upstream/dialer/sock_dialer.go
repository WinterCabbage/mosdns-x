/*
 * Copyright (C) 2020-2022, IrineSistiana
 *
 * This file is part of mosdns.
 *
 * mosdns is free software: you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation, either version 3 of the License, or
 * (at your option) any later version.
 *
 * mosdns is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program.  If not, see <https://www.gnu.org/licenses/>.
 */

package dialer

import (
	"context"
	"encoding/binary"
	"fmt"
	"net"
	"net/netip"
)

type SocksDialer struct {
	dialer *net.Dialer
	addr   *SocksAddr
}

func newSocksDialer(dialer *net.Dialer, addr string) (*SocksDialer, error) {
	sAddr, err := ParseSocksAddr(addr)
	if err != nil {
		return nil, err
	}
	return &SocksDialer{dialer: dialer, addr: sAddr}, nil
}

func (d *SocksDialer) DialContext(ctx context.Context, network, addr string) (net.Conn, error) {
	if network != "tcp" && network != "udp" {
		return nil, fmt.Errorf("unsupported network type: %s", network)
	}
	conn, err := d.dialer.DialContext(ctx, "tcp", d.addr.String())
	if err != nil {
		return nil, fmt.Errorf("dial faile: %v", err)
	}
	negoReq := []byte{Version5, 1, MethodNoAuth}
	_, err = conn.Write(negoReq)
	if err != nil {
		return nil, fmt.Errorf("send negotiation request failed: %v", err)
	}
	negoRes := make([]byte, 2)
	n, err := conn.Read(negoRes)
	if err != nil {
		return nil, fmt.Errorf("receive negotiation response failed: %v", err)
	}
	if n < 2 {
		return nil, fmt.Errorf("negotiation response too short")
	}
	if negoRes[0] != 5 {
		return nil, fmt.Errorf("unsupported negotiation response version: %v", negoReq[0])
	}
	var reqType string
	var cmd byte
	if network == "tcp" {
		reqType = "connect"
		cmd = CMDCONNECT
	} else {
		reqType = "associate"
		cmd = CMDASSOCIATE
	}
	sAddr, err := ParseSocksAddr(addr)
	if err != nil {
		return nil, fmt.Errorf("parse socks addr failed: %v", err)
	}
	authReq := append([]byte{Version5, cmd, Reversed}, sAddr.Slice()...)
	_, err = conn.Write(authReq)
	if err != nil {
		return nil, fmt.Errorf("send %s request failed: %v", reqType, err)
	}
	authRes := make([]byte, 4)
	n, err = conn.Read(authRes)
	if err != nil {
		return nil, fmt.Errorf("receive %s response failed: %v", reqType, err)
	}
	if n < 4 {
		return nil, fmt.Errorf("%s response too short", reqType)
	}
	if authRes[0] != Version5 {
		return nil, fmt.Errorf("unsupported %s response version: %v", reqType, negoReq[0])
	}
	if authRes[1] != AuthSuccessed {
		return nil, fmt.Errorf("%s failed: %s", reqType, handleAssociateStatus(authRes[1]))
	}
	if authRes[2] != Reversed {
		return nil, fmt.Errorf("invalid %s response reserved byte: %v", reqType, authRes[2])
	}
	var bindAddr SocksAddr
	switch authRes[3] {
	case TypeIPv4:
		addr := make([]byte, 4)
		n, err = conn.Read(addr)
		if err != nil {
			return nil, fmt.Errorf("parse ipv4 bind address failed: %v", err)
		}
		if n < 4 {
			return nil, fmt.Errorf("parse ipv4 bind address failed: bind address too short")
		}
		if addr, ok := netip.AddrFromSlice(addr); ok {
			bindAddr.SetAddr(addr)
		} else {
			return nil, fmt.Errorf("parse ipv4 bind address failed: invalid ipv4 address")
		}
	case TypeFqdn:
		addrLen := make([]byte, 1)
		n, err = conn.Read(addrLen)
		if err != nil {
			return nil, fmt.Errorf("parse fqdn bind address length failed: %v", err)
		}
		if n == 0 {
			return nil, fmt.Errorf("parse fqdn bind address failed: length is zero")
		}
		addr := make([]byte, addrLen[0])
		n, err = conn.Read(addr)
		if err != nil {
			return nil, fmt.Errorf("parse fqdn bind address failed: %v", err)
		}
		if n < int(addrLen[0]) {
			return nil, fmt.Errorf("parse fqdn bind address failed: bind address too short")
		}
		bindAddr.SetFqdn(string(addr))
	case TypeIPv6:
		addr := make([]byte, 16)
		n, err = conn.Read(addr)
		if err != nil {
			return nil, fmt.Errorf("parse ipv6 bind address failed: %v", err)
		}
		if n < 16 {
			return nil, fmt.Errorf("parse ipv6 bind address failed: bind address too short")
		}
		if addr, ok := netip.AddrFromSlice(addr); ok {
			bindAddr.SetAddr(addr)
		} else {
			return nil, fmt.Errorf("parse ipv6 bind address failed: invalid ipv6 address")
		}
	default:
		return nil, fmt.Errorf("unsupported bind address type: %v", authRes[3])
	}
	rawPort := make([]byte, 2)
	n, err = conn.Read(rawPort)
	if err != nil {
		return nil, fmt.Errorf("parse bind port failed: %v", err)
	}
	if n < 2 {
		return nil, fmt.Errorf("parse bind port failed: bind port too short")
	}
	bindAddr.SetPort(binary.BigEndian.Uint16(rawPort))
	if network == "tcp" {
		return conn, nil
	}
	c, err := d.dialer.DialContext(context.Background(), "udp", bindAddr.String())
	if err != nil {
		return nil, err
	}
	pc, isPC := c.(net.PacketConn)
	if !isPC {
		return nil, fmt.Errorf("not a packet conn")
	}
	uc, isUC := pc.(*net.UDPConn)
	if !isUC {
		return nil, fmt.Errorf("not a udp conn")
	}
	spc := &SocksPacketConn{
		conn:  conn,
		inner: uc,
		cache: make([]byte, 65535),
	}
	if !sAddr.addr.IsUnspecified() && sAddr.port != 0 {
		spc.dest = sAddr
	}
	return spc, nil
}

func handleAssociateStatus(status byte) string {
	switch status {
	case 1:
		return "associate failed: general socks server failure"
	case 2:
		return "connection not allowed by ruleset"
	case 3:
		return "network unreachable"
	case 4:
		return "host unreachable"
	case 5:
		return "connection refused"
	case 6:
		return "ttl expired"
	case 7:
		return "command not supported"
	case 8:
		return "address type not supported"
	case 9:
		return "host unreachable"
	default:
		return "unassigned"
	}
}
