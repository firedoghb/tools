package main

import (
	"bytes"
	"encoding/binary"
	"flag"
	"fmt"
	"math/rand"
	"net"
	"os"

	"golang.org/x/sys/unix"
)

type iphdr struct {
	vhl   uint8
	tos   uint8
	iplen uint16
	id    uint16
	off   uint16
	ttl   uint8
	proto uint8
	csum  uint16
	src   [4]byte
	dst   [4]byte
}

type udphdr struct {
	src  uint16
	dst  uint16
	ulen uint16
	csum uint16
}

// pseudo header used for checksum calculation
type pseudohdr struct {
	ipsrc   [4]byte
	ipdst   [4]byte
	zero    uint8
	ipproto uint8
	plen    uint16
}

func checksum(buf []byte) uint16 {
	sum := uint32(0)

	for ; len(buf) >= 2; buf = buf[2:] {
		sum += uint32(buf[0])<<8 | uint32(buf[1])
	}
	if len(buf) > 0 {
		sum += uint32(buf[0]) << 8
	}
	for sum > 0xffff {
		sum = (sum >> 16) + (sum & 0xffff)
	}
	csum := ^uint16(sum)
	/*
	 * From RFC 768:
	 * If the computed checksum is zero, it is transmitted as all ones (the
	 * equivalent in one's complement arithmetic). An all zero transmitted
	 * checksum value means that the transmitter generated no checksum (for
	 * debugging or for higher level protocols that don't care).
	 */
	if csum == 0 {
		csum = 0xffff
	}
	return csum
}

func (h *iphdr) checksum() {
	h.csum = 0
	var b bytes.Buffer
	binary.Write(&b, binary.BigEndian, h)
	h.csum = checksum(b.Bytes())
}

func (u *udphdr) checksum(ip *iphdr, payload []byte) {
	u.csum = 0
	phdr := pseudohdr{
		ipsrc:   ip.src,
		ipdst:   ip.dst,
		zero:    0,
		ipproto: ip.proto,
		plen:    u.ulen,
	}
	var b bytes.Buffer
	binary.Write(&b, binary.BigEndian, &phdr)
	binary.Write(&b, binary.BigEndian, u)
	binary.Write(&b, binary.BigEndian, &payload)
	u.csum = checksum(b.Bytes())
}

func main() {
	ipdststr := "127.0.0.1"
	ipsrcstr := ""
	senddata := "123"
	packNum := 1
	flag.StringVar(&ipdststr, "ipdst", ipdststr, "IPv4 destination address")
	flag.StringVar(&ipsrcstr, "ipsrc", ipsrcstr, "IPv4 source address")
	flag.StringVar(&senddata, "data", senddata, "udp data to send")
	flag.IntVar(&packNum, "num", packNum, "send package")
	flag.Parse()

	ipdst := net.ParseIP(ipdststr)
	if ipdst == nil {
		fmt.Fprintf(os.Stderr, "invalid destination IP: %v\n", ipdst)
		os.Exit(1)
	}

	fd, err := unix.Socket(unix.AF_INET, unix.SOCK_RAW, unix.IPPROTO_RAW)

	if err != nil || fd < 0 {
		fmt.Fprintf(os.Stdout, "error creating a raw socket: %v\n", err)
		os.Exit(1)
	}

	err = unix.SetsockoptInt(fd, unix.IPPROTO_IP, unix.IP_HDRINCL, 1)
	if err != nil {
		fmt.Fprintf(os.Stderr, "error enabling IP_HDRINCL: %v\n", err)
		unix.Close(fd)
		os.Exit(1)
	}
	ip := iphdr{
		vhl:   0x45,
		tos:   0,
		id:    0, // the kernel overwrites id if it is zero
		off:   0,
		ttl:   64,
		proto: unix.IPPROTO_UDP,
	}

	copy(ip.dst[:], ipdst.To4())
	var ipsrc net.IP
	if ipsrcstr != "" {
		ipsrc = net.ParseIP(ipsrcstr)
		copy(ip.src[:], ipsrc.To4())
	}

	for i := 0; i < packNum; i++ {
		if ipsrcstr == "" {
			ipsrc := make([]byte, 4)
			binary.LittleEndian.PutUint32(ipsrc, rand.Uint32())
			copy(ip.src[:], ipsrc)
		}

		udp := udphdr{
			src: uint16(rand.Intn(65535)),
			dst: uint16(rand.Intn(65535)),
		}

		addr := unix.SockaddrInet4{}

		payload := []byte(senddata)
		udplen := 8 + len(payload)
		totallen := 20 + udplen
		if totallen > 0xffff {
			fmt.Fprintf(os.Stderr, "message is too large to fit into a packet: %v > %v\n", totallen, 0xffff)
			continue
		}

		ip.iplen = uint16(totallen)
		ip.checksum()

		udp.ulen = uint16(udplen)
		udp.checksum(&ip, payload)

		var b bytes.Buffer
		err = binary.Write(&b, binary.BigEndian, &ip)
		if err != nil {
			fmt.Fprintf(os.Stderr, "error encoding the ip header: %v\n", err)
			continue
		}
		err = binary.Write(&b, binary.BigEndian, &udp)
		if err != nil {
			fmt.Fprintf(os.Stderr, "error encoding the udp header: %v\n", err)
			continue
		}
		err = binary.Write(&b, binary.BigEndian, &payload)
		if err != nil {
			fmt.Fprintf(os.Stderr, "error encoding the payload: %v\n", err)
			continue
		}
		bb := b.Bytes()

		err = unix.Sendto(fd, bb, 0, &addr)
		if err != nil {
			fmt.Fprintf(os.Stderr, "error sending the packet: %v\n", err)
			continue
		}
		fmt.Printf("%v bytes were sent\n", len(bb))
	}

	err = unix.Close(fd)
	if err != nil {
		fmt.Fprintf(os.Stderr, "error closing the socket: %v\n", err)
		os.Exit(1)
	}
}
