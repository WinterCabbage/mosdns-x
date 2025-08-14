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
	"encoding/binary"
	"fmt"
	"net"
	"net/netip"
	"strconv"
	"strings"
)

const Version5 = 5

const (
	MethodNoAuth   = 0
	MethodUserPass = 2
)

const AuthSuccessed = 0

const Reversed = 0

const Nofragment = 0

const (
	TypeIPv4 = 1
	TypeFqdn = 3
	TypeIPv6 = 4
)

const (
	CMDCONNECT   = 1
	CMDBIND      = 2
	CMDASSOCIATE = 3
)

type SocksAddr struct {
	addr netip.Addr
	fqdn string
	port uint16
}

func ParseSocksAddr(s string) (*SocksAddr, error) {
	if addrPort, err := netip.ParseAddrPort(s); err == nil {
		if addrPort.Addr().Is4In6() {
			return &SocksAddr{addr: addrPort.Addr().Unmap(), port: addrPort.Port()}, nil
		} else {
			return &SocksAddr{addr: addrPort.Addr(), port: addrPort.Port()}, nil
		}
	} else if !strings.Contains(s, ":") {
		return nil, fmt.Errorf("invalid socksaddr")
	} else {
		addrPort := strings.SplitN(s, ":", 2)
		addr := addrPort[0]
		if len([]byte(addr)) > 255 {
			return nil, fmt.Errorf("address too long")
		}
		port, err := strconv.Atoi(addrPort[1])
		if err != nil || port < 0 || port > 65535 {
			return nil, fmt.Errorf("invalid port")
		}
		return &SocksAddr{fqdn: addr, port: uint16(port)}, nil
	}
}

func SocksAddrFromFqdnPort(fqdn string, port uint16) *SocksAddr {
	return &SocksAddr{fqdn: fqdn, port: port}
}

func SocksAddrFromAddrPort(addrPort netip.AddrPort) *SocksAddr {
	return &SocksAddr{addr: addrPort.Addr(), port: addrPort.Port()}
}

func (s *SocksAddr) SetAddr(addr netip.Addr) {
	if addr.Is4In6() {
		s.addr = addr.Unmap()
	} else {
		s.addr = addr
	}
}

func (s *SocksAddr) SetFqdn(fqdn string) {
	s.fqdn = fqdn
}

func (s *SocksAddr) SetPort(port uint16) {
	s.port = port
}

func (s *SocksAddr) String() string {
	if len(s.fqdn) > 0 {
		return fmt.Sprintf("%s:%d", s.fqdn, s.port)
	} else {
		return fmt.Sprintf("%v:%d", s.addr, s.port)
	}
}

func (s *SocksAddr) Slice() []byte {
	var slice []byte
	if len(s.fqdn) > 0 {
		fqdn := []byte(s.fqdn)
		slice = append([]byte{TypeFqdn, byte(len(fqdn))}, fqdn...)
	} else if s.addr.Is4() {
		slice = append([]byte{TypeIPv4}, s.addr.AsSlice()...)
	} else {
		slice = append([]byte{TypeIPv6}, s.addr.AsSlice()...)
	}
	return binary.BigEndian.AppendUint16(slice, s.port)
}

func (s *SocksAddr) NetAddr() net.Addr {
	if len(s.fqdn) == 0 {
		return net.UDPAddrFromAddrPort(netip.AddrPortFrom(s.addr, s.port))
	} else {
		addr := UDPFqdnAddr(s.String())
		return &addr
	}
}

func (s *SocksAddr) UDPAddr() (*net.UDPAddr, error) {
	if len(s.fqdn) == 0 {
		return net.UDPAddrFromAddrPort(netip.AddrPortFrom(s.addr, s.port)), nil
	} else {
		return nil, fmt.Errorf("cannot convert fqdn socksaddr to an *net.UDPConn")
	}
}

type UDPFqdnAddr string

func (f *UDPFqdnAddr) Network() string {
	return "udp"
}

func (f UDPFqdnAddr) String() string {
	return string(f)
}
