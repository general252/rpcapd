package main

import (
	"bufio"
	"bytes"
	"encoding/binary"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log"
	"net"
	"sync"
	"time"

	"github.com/google/gopacket/pcap"
)

const (
	RPCAP_VERSION     = 0x00
	RPCAP_MIN_VERSION = 0
	RPCAP_MAX_VERSION = 0

	RPCAP_BYTE_ORDER_MAGIC         = 0xa1b2c3d4
	RPCAP_BYTE_ORDER_MAGIC_SWAPPED = 0xd4c3b2a1
)

const (
	RPCAP_STARTCAPREQ_FLAG_PROMISC    = 0x00000001 /* Enables promiscuous mode (default: disabled) */
	RPCAP_STARTCAPREQ_FLAG_DGRAM      = 0x00000002 /* Use a datagram (i.e. UDP) connection for the data stream (default: use TCP)*/
	RPCAP_STARTCAPREQ_FLAG_SERVEROPEN = 0x00000004 /* The server has to open the data connection toward the client */
	RPCAP_STARTCAPREQ_FLAG_INBOUND    = 0x00000008 /* Capture only inbound packets (take care: the flag has no effect with promiscuous enabled) */
	RPCAP_STARTCAPREQ_FLAG_OUTBOUND   = 0x00000010 /* Capture only outbound packets (take care: the flag has no effect with promiscuous enabled) */

	RPCAP_UPDATEFILTER_BPF = 1 /* This code tells us that the filter is encoded with the BPF/NPF syntax */
)

const (
	RPCAP_MSG_ERROR           = 0x01
	RPCAP_MSG_FINDALLIF_REQ   = 0x02
	RPCAP_MSG_OPEN_REQ        = 0x03
	RPCAP_MSG_STARTCAP_REQ    = 0x04
	RPCAP_MSG_UPDATEFLT_REQ   = 0x05
	RPCAP_MSG_CLOSE           = 0x06
	RPCAP_MSG_PACKET          = 0x07
	RPCAP_MSG_AUTH_REQ        = 0x08
	RPCAP_MSG_STATS_REQ       = 0x09
	RPCAP_MSG_ENDCAP_REQ      = 0x0A
	RPCAP_MSG_SETSAMPLING_REQ = 0x0B

	RPCAP_MSG_IS_REPLY          = 0x80
	RPCAP_MSG_FINDALLIF_REPLY   = RPCAP_MSG_FINDALLIF_REQ | RPCAP_MSG_IS_REPLY
	RPCAP_MSG_OPEN_REPLY        = RPCAP_MSG_OPEN_REQ | RPCAP_MSG_IS_REPLY
	RPCAP_MSG_STARTCAP_REPLY    = RPCAP_MSG_STARTCAP_REQ | RPCAP_MSG_IS_REPLY
	RPCAP_MSG_UPDATEFLT_REPLY   = RPCAP_MSG_UPDATEFLT_REQ | RPCAP_MSG_IS_REPLY
	RPCAP_MSG_AUTH_REPLY        = RPCAP_MSG_AUTH_REQ | RPCAP_MSG_IS_REPLY
	RPCAP_MSG_STATS_REPLY       = RPCAP_MSG_STATS_REQ | RPCAP_MSG_IS_REPLY
	RPCAP_MSG_ENDCAP_REPLY      = RPCAP_MSG_ENDCAP_REQ | RPCAP_MSG_IS_REPLY
	RPCAP_MSG_SETSAMPLING_REPLY = RPCAP_MSG_SETSAMPLING_REQ | RPCAP_MSG_IS_REPLY
)

type rpcapHeader struct {
	Ver   uint8  /* RPCAP version number */
	Type  uint8  /* RPCAP message type (error, findalldevs, ...) */
	Value uint16 /* Message-dependent value (not always used) */
	PLen  uint32 /* Length of the payload of this RPCAP message */
}

func (h *rpcapHeader) Read(r io.Reader) error {
	buf := make([]byte, 8)
	if _, err := io.ReadFull(r, buf); err != nil {
		return err
	}
	h.Ver = buf[0]
	h.Type = buf[1]
	h.Value = binary.BigEndian.Uint16(buf[2:4])
	h.PLen = binary.BigEndian.Uint32(buf[4:8])

	log.Printf("rpcapHeader %v", h.Type)
	return nil
}

func (h *rpcapHeader) Write(w io.Writer) error {
	buf := make([]byte, 8)
	buf[0] = h.Ver
	buf[1] = h.Type
	binary.BigEndian.PutUint16(buf[2:4], h.Value)
	binary.BigEndian.PutUint32(buf[4:8], h.PLen)
	_, err := w.Write(buf)
	return err
}

type rpcapAuthReply struct {
	MinVers        uint8   /* Minimum version supported */
	MaxVers        uint8   /* Maximum version supported */
	Pad            [2]byte /* Pad to 4-byte boundary **/
	ByteOrderMagic uint32  /* RPCAP_BYTE_ORDER_MAGIC, in server byte order */
}

func (h *rpcapAuthReply) Read(r io.Reader) error {
	buf := make([]byte, 8)
	if _, err := io.ReadFull(r, buf); err != nil {
		return err
	}
	h.MinVers = buf[0]
	h.MaxVers = buf[1]
	h.Pad = [2]byte(buf[2:4])
	h.ByteOrderMagic = binary.BigEndian.Uint32(buf[4:8])
	return nil
}

func (h *rpcapAuthReply) Write(w io.Writer) error {
	buf := make([]byte, 8)
	buf[0] = h.MinVers
	buf[1] = h.MaxVers
	copy(buf[2:4], h.Pad[:])
	binary.BigEndian.PutUint32(buf[4:8], h.ByteOrderMagic)

	_, err := w.Write(buf)
	return err
}

type rpcapFindAllDevsIf struct {
	NameLen uint16 /* Length of the interface name */
	DescLen uint16 /* Length of the interface description */
	Flags   uint32 /* Interface flags */
	NAddr   uint16 /* Number of addresses */
	Dummy   uint16 /* Must be zero */
}

func (tis *rpcapFindAllDevsIf) Write(w io.Writer) error {
	buf := make([]byte, 12)

	binary.BigEndian.PutUint16(buf[0:2], tis.NameLen)
	binary.BigEndian.PutUint16(buf[2:4], tis.DescLen)
	binary.BigEndian.PutUint32(buf[4:8], tis.Flags)
	binary.BigEndian.PutUint16(buf[8:10], tis.NAddr)
	binary.BigEndian.PutUint16(buf[10:12], tis.Dummy)

	_, err := w.Write(buf)
	return err
}

type rpcapOpenReply struct {
	LinkType int32 /* Link type */
	TzOff    int32 /* Timezone offset - not used by newer clients */
}

func (h *rpcapOpenReply) Write(w io.Writer) error {
	buf := make([]byte, 8)

	binary.BigEndian.PutUint32(buf[0:4], uint32(h.LinkType))
	binary.BigEndian.PutUint32(buf[4:8], uint32(h.TzOff))
	_, err := w.Write(buf)
	return err
}

type rpcapStartCapReq struct {
	SnapLen     uint32 /* Length of the snapshot (number of bytes to capture for each packet) */
	ReadTimeout uint32 /* Read timeout in milliseconds */
	Flags       uint16 /* Flags (see RPCAP_STARTCAPREQ_FLAG_xxx) */
	PortData    uint16 /* Network port on which the client is waiting at (if 'serveropen') */
}

func (h *rpcapStartCapReq) Read(r io.Reader) error {
	buf := make([]byte, 12)
	if _, err := io.ReadFull(r, buf); err != nil {
		return err
	}

	h.SnapLen = binary.BigEndian.Uint32(buf[0:4])
	h.ReadTimeout = binary.BigEndian.Uint32(buf[4:8])
	h.Flags = binary.BigEndian.Uint16(buf[8:10])
	h.PortData = binary.BigEndian.Uint16(buf[10:12])

	return nil
}

/* Format of the reply message that devoted to start a remote capture (startcap reply command) */
type rpcapStartCapReply struct {
	BufSize  int32  /* Size of the user buffer allocated by WinPcap; it can be different from the one we chose */
	PortData uint16 /* Network port on which the server is waiting at (passive mode only) */
	Dummy    uint16 /* Must be zero */
}

func (h *rpcapStartCapReply) Write(w io.Writer) error {
	buf := make([]byte, 8)

	binary.BigEndian.PutUint32(buf[0:4], uint32(h.BufSize))
	binary.BigEndian.PutUint16(buf[4:6], h.PortData)
	binary.BigEndian.PutUint16(buf[6:8], h.Dummy)

	_, err := w.Write(buf)
	return err
}

type rpcapFilter struct {
	FilterType uint16 /* type of the filter transferred (BPF instructions, ...) */
	Dummy      uint16 /* Must be zero */
	NItems     uint32 /* Number of items contained into the filter (e.g. BPF instructions for BPF filters) */
}

func (h *rpcapFilter) Read(r io.Reader) error {
	buf := make([]byte, 8)
	if _, err := io.ReadFull(r, buf); err != nil {
		return err
	}

	h.FilterType = binary.BigEndian.Uint16(buf[0:2])
	h.Dummy = binary.BigEndian.Uint16(buf[2:4])
	h.NItems = binary.BigEndian.Uint32(buf[4:8])

	return nil
}

type rpcapFilterBpfInSn struct {
	Code uint16 /* opcode of the instruction */
	JT   uint8  /* relative offset to jump to in case of 'true' */
	JF   uint8  /* relative offset to jump to in case of 'false' */
	K    uint32 /* instruction-dependent value */
}

func (h *rpcapFilterBpfInSn) Read(r io.Reader) error {
	buf := make([]byte, 8)
	if _, err := io.ReadFull(r, buf); err != nil {
		return err
	}

	h.Code = binary.BigEndian.Uint16(buf[0:2])
	h.JT = buf[2]
	h.JF = buf[3]
	h.K = binary.BigEndian.Uint32(buf[4:8])

	return nil
}

type rpcapSockAddr struct {
	Family uint16         /* Address family */
	Data   [128 - 2]uint8 /* Data */
}

type rpcapPktHdr struct {
	/*
	 * This protocol needs to be updated with a new version before
	 * 2038-01-19 03:14:07 UTC.
	 */
	TimestampSec  uint32 /* 'struct timeval' compatible, it represents the 'tv_sec' field */
	TimestampUSec uint32 /* 'struct timeval' compatible, it represents the 'tv_usec' field */
	CapLen        uint32 /* Length of portion present in the capture */
	Len           uint32 /* Real length of this packet (off wire) */
	NPkt          uint32 /* Ordinal number of the packet (i.e. the first one captured has '1', the second one '2', etc) */
}

func (h *rpcapPktHdr) Write(w io.Writer) error {
	buf := make([]byte, 20)

	binary.BigEndian.PutUint32(buf[0:4], h.TimestampSec)
	binary.BigEndian.PutUint32(buf[4:8], h.TimestampUSec)
	binary.BigEndian.PutUint32(buf[8:12], h.CapLen)
	binary.BigEndian.PutUint32(buf[12:16], h.Len)
	binary.BigEndian.PutUint32(buf[16:20], h.NPkt)

	_, err := w.Write(buf)
	return err
}

type rpcapStats struct {
	IfRecv   uint32 /* Packets received by the kernel filter (i.e. pcap_stats.ps_recv) */
	IfDrop   uint32 /* Packets dropped by the network interface (e.g. not enough buffers) (i.e. pcap_stats.ps_ifdrop) */
	KRnlDrop uint32 /* Packets dropped by the kernel filter (i.e. pcap_stats.ps_drop) */
	SvrCapt  uint32 /* Packets captured by the RPCAP daemon and sent on the network */
}

func (h *rpcapStats) Write(w io.Writer) error {
	buf := make([]byte, 16)

	binary.BigEndian.PutUint32(buf[0:4], h.IfRecv)
	binary.BigEndian.PutUint32(buf[4:8], h.IfDrop)
	binary.BigEndian.PutUint32(buf[8:12], h.KRnlDrop)
	binary.BigEndian.PutUint32(buf[12:16], h.SvrCapt)

	_, err := w.Write(buf)
	return err
}

type IMessage interface {
	Write(w io.Writer) error
}

type Session struct {
	conn      net.Conn
	ifaceName string

	sendMutex sync.Mutex

	handle  *pcap.Handle
	totCapt uint32
}

func NewSession(conn net.Conn) *Session {
	return &Session{conn: conn}
}

func (ctx *Session) Loop() {
	defer func() {
		_ = ctx.conn.Close()
	}()

	br := bufio.NewReader(ctx.conn)

	var header rpcapHeader
	if err := header.Read(br); err != nil {
		log.Printf("read header error: %v", err)
		return
	}
	if header.Type != RPCAP_MSG_AUTH_REQ {
		log.Printf("unexpected header type %d", header.Type)
		return
	}

	if header.PLen > 0 {
		cred := make([]byte, header.PLen)
		if _, err := io.ReadFull(br, cred); err != nil {
			log.Printf("read cred error: %v", err)
			ctx.ReplyError(err)
			return
		}
	}

	_ = ctx.Reply([]IMessage{
		&rpcapHeader{
			Ver:   RPCAP_VERSION,
			Type:  RPCAP_MSG_AUTH_REPLY,
			Value: 0,
			PLen:  8,
		},
		&rpcapAuthReply{
			MinVers:        RPCAP_MIN_VERSION,
			MaxVers:        RPCAP_MAX_VERSION,
			Pad:            [2]byte{},
			ByteOrderMagic: RPCAP_BYTE_ORDER_MAGIC,
		},
	}, nil)

	// 2. 命令循环
	for {
		h := rpcapHeader{}
		if err := h.Read(br); err != nil {
			log.Printf("read header error: %v", err)
			return
		}

		switch h.Type {
		case RPCAP_MSG_FINDALLIF_REQ:
			log.Println("find all if")
			ctx.handleFindAllIf()
		case RPCAP_MSG_OPEN_REQ:
			log.Println("open")
			var iface = make([]byte, h.PLen)
			_, _ = br.Read(iface)
			ctx.handleOpen(string(iface))
		case RPCAP_MSG_CLOSE:
			log.Println("close")
			ctx.ifaceName = ""
		case RPCAP_MSG_STARTCAP_REQ:
			log.Println("start capture")
			_ = ctx.handleStartCapture(br)
		case RPCAP_MSG_ENDCAP_REQ:
			log.Println("end capture")
			ctx.handleEndCapture()
		case RPCAP_MSG_UPDATEFLT_REQ:
			log.Println("update filter")
			_ = ctx.handleSetBPFFilter(br)
		case RPCAP_MSG_STATS_REQ:
			log.Println("stats")
			ctx.handleStats()
		default:
			log.Println("unsupported msg")
			ctx.ReplyError(fmt.Errorf("unsupported msg %d", h.Type))
			return
		}
	}
}

func (ctx *Session) Reply(msgs []IMessage, data []byte) error {
	var buffer bytes.Buffer
	for _, msg := range msgs {
		_ = msg.Write(&buffer)
	}

	if len(data) > 0 {
		_, _ = buffer.Write(data)
	}

	_, err := ctx.conn.Write(buffer.Bytes())
	if err != nil {
		log.Printf("write error: %v", err)
	}

	return err
}

func (ctx *Session) ReplyError(err error) {
	var data = []byte(err.Error())

	_ = ctx.Reply(
		[]IMessage{
			&rpcapHeader{
				Ver:   RPCAP_VERSION,
				Type:  RPCAP_MSG_ERROR,
				Value: 0,
				PLen:  uint32(len(data))},
		},
		data,
	)
}

func (ctx *Session) handleFindAllIf() {
	// List all devices
	devs, err := pcap.FindAllDevs()
	if err != nil {
		ctx.ReplyError(err)
		return
	}

	buf := bytes.NewBuffer(make([]byte, 0, 1024))
	for _, d := range devs {
		/**/
		_ = len(d.Description) + len(d.Name) + 12
		var dev rpcapFindAllDevsIf
		dev.NameLen = uint16(len(d.Name))
		dev.DescLen = uint16(len(d.Description))
		dev.Flags = d.Flags
		dev.NAddr = 0 // uint16(len(d.Addresses))
		dev.Dummy = 0
		_ = dev.Write(buf)

		_, _ = buf.Write([]byte(d.Name))
		_, _ = buf.Write([]byte(d.Description))

		for _, addr := range d.Addresses {
			log.Println(addr)
			// buf.Write()
		}
	}

	replyHeader := rpcapHeader{
		Ver:   RPCAP_VERSION,
		Type:  RPCAP_MSG_FINDALLIF_REPLY,
		Value: uint16(len(devs)),
		PLen:  uint32(buf.Len()),
	}

	_ = ctx.Reply([]IMessage{&replyHeader}, buf.Bytes())
}

func (ctx *Session) handleOpen(iface string) {

	h, err := pcap.OpenLive(iface, 1500, false, time.Second)
	if err != nil {
		ctx.ReplyError(err)
		return
	} else {
		defer h.Close()
	}

	ctx.ifaceName = iface

	_ = ctx.Reply(
		[]IMessage{
			&rpcapHeader{
				Ver:   RPCAP_VERSION,
				Type:  RPCAP_MSG_OPEN_REPLY,
				Value: 0,
				PLen:  8,
			},
			&rpcapOpenReply{
				LinkType: int32(h.LinkType()),
				TzOff:    0,
			},
		},
		nil,
	)
}

func (ctx *Session) readFilter(br io.Reader) ([]pcap.BPFInstruction, error) {
	var pcapFilter rpcapFilter
	if err := pcapFilter.Read(br); err != nil {
		log.Printf("read rpcapFilter fail: %v", err)
		return nil, err
	} else {
		log.Printf("read rpcapFilter: %v", pcapFilter.NItems)
	}

	var bfInSns []pcap.BPFInstruction
	for i := 0; i < int(pcapFilter.NItems); i++ {
		var h3 rpcapFilterBpfInSn
		if err := h3.Read(br); err != nil {
			log.Printf("read rpcapFilterBpfInSn fail: %v", err)
			return nil, err
		} else {
			log.Printf("read rpcapFilterBpfInSn: %v", i)
		}
		bfInSns = append(bfInSns, pcap.BPFInstruction{
			Code: h3.Code,
			Jt:   h3.JT,
			Jf:   h3.JF,
			K:    h3.K,
		})
	}

	return bfInSns, nil
}

func (ctx *Session) handleStartCapture(br io.Reader) error {
	var startCapReq rpcapStartCapReq
	if err := startCapReq.Read(br); err != nil {
		log.Printf("read rpcapStartCapReq fail: %v", err)
		return err
	}

	bfInSns, err := ctx.readFilter(br)
	if err != nil {
		log.Printf("read filter fail: %v", err)
		return err
	}

	var promisc = false
	if startCapReq.Flags&RPCAP_STARTCAPREQ_FLAG_PROMISC > 0 {
		promisc = true
	}

	log.Printf("start capture: %s, promisc: %v", ctx.ifaceName, promisc)
	handle, err := pcap.OpenLive(ctx.ifaceName,
		int32(startCapReq.SnapLen),
		promisc,
		time.Millisecond*time.Duration(startCapReq.ReadTimeout),
	)
	if err != nil {
		log.Printf("OpenLive: %v", err)
		return err
	} else {
		log.Println("OpenLive success")
	}

	ctx.handle = handle

	if len(bfInSns) > 0 {
		data, _ := json.Marshal(bfInSns)
		log.Printf("set bpf filter: %v", string(data))
		err = handle.SetBPFInstructionFilter(bfInSns)
		log.Printf("set bpf filter %v", err)
	}

	// 数据监听
	ln, err := net.ListenTCP("tcp4", &net.TCPAddr{
		Port: 0,
	})
	if err != nil {
		log.Printf("net.Listen: %v", err)
		ctx.ReplyError(err)
		return err
	}
	defer func() {
		_ = ln.Close()
	}()

	addr := ln.Addr().(*net.TCPAddr)
	log.Printf("Listen success: %v", addr)

	_ = ctx.Reply([]IMessage{
		&rpcapHeader{
			Ver:   RPCAP_VERSION,
			Type:  RPCAP_MSG_STARTCAP_REPLY,
			Value: 0,
			PLen:  8,
		},
		&rpcapStartCapReply{
			BufSize:  256000, // int32(handle.BufSize()), // 256000,
			PortData: uint16(addr.Port),
			Dummy:    0,
		},
	}, nil)

	// 接受数据连接
	dataConn, err := ln.Accept()
	if err != nil {
		log.Println(err)
		return err
	}

	conn := dataConn.(*net.TCPConn)
	_ = conn.SetWriteBuffer(512000)

	go func() {
		ctx.streamPackets(conn)
	}()

	return nil
}

func (ctx *Session) streamPackets(dataConn *net.TCPConn) {

	defer func() {
		_ = dataConn.Close()

		if h := ctx.handle; h != nil {
			h.Close()
			ctx.handle = nil
		}
	}()

	go func() {
		buffer := make([]byte, 256)
		for {
			_, err := dataConn.Read(buffer)
			if err != nil {
				break
			}
		}
	}()

	h := ctx.handle
	if h == nil {
		log.Println("handle is nil")
		return
	}

	log.Printf("local: %v  remote: %v SnapLen: %v", dataConn.LocalAddr(), dataConn.RemoteAddr(), h.SnapLen())

	for {
		data, ci, err := h.ReadPacketData()
		if err != nil {
			if errors.Is(err, pcap.NextErrorTimeoutExpired) {
				continue
			}

			log.Printf("ReadPacketData: %v", err)
			break
		}
		if ci.CaptureLength != len(data) {
			log.Println("CaptureLength != len(data)")
			continue
		}

		//log.Println(ci.Timestamp, ci.CaptureLength, len(data), ctx.totCapt)

		var buffer bytes.Buffer

		var replyHeader = rpcapHeader{
			Ver:   RPCAP_VERSION,
			Type:  RPCAP_MSG_PACKET,
			Value: 0,
			PLen:  20 + uint32(ci.CaptureLength),
		}
		err = replyHeader.Write(&buffer)
		if err != nil {
			log.Println(err)
			break
		}

		ctx.totCapt++
		var pktHdr = rpcapPktHdr{
			TimestampSec:  uint32(ci.Timestamp.Unix()),
			TimestampUSec: uint32(ci.Timestamp.Nanosecond() / 1000),
			CapLen:        uint32(ci.CaptureLength),
			Len:           uint32(ci.Length),
			NPkt:          ctx.totCapt,
		}
		err = pktHdr.Write(&buffer)
		if err != nil {
			log.Println(err)
			break
		}

		buffer.Write(data)

		out := buffer.Bytes()
		// log.Printf("%v.%v %v %v\n%v", pktHdr.TimestampSec, pktHdr.TimestampUSec, ci.CaptureLength, len(out), hex.Dump(out))
		if n, err := dataConn.Write(out); err != nil {
			log.Println(err)
			break
		} else if n != len(out) {
			log.Println("write fail")
			break
		}
	}
}

func (ctx *Session) handleSetBPFFilter(br io.Reader) error {
	bfInSns, err := ctx.readFilter(br)
	if err != nil {
		log.Printf("read filter fail: %v", err)
		return err
	}

	if len(bfInSns) == 0 {
		log.Println("filter is empty")
		return nil
	}

	for i := 0; i < 10; i++ {
		if ctx.handle != nil {
			break
		}
		time.Sleep(time.Millisecond * 100)
	}

	h := ctx.handle
	if h == nil {
		log.Println("handle is nil")
		return nil
	}

	log.Println("set filter:", len(bfInSns))
	err = h.SetBPFInstructionFilter(bfInSns)
	if err != nil {
		log.Printf("set filter fail: %v", err)
		ctx.ReplyError(err)
	}

	_ = ctx.Reply([]IMessage{
		&rpcapHeader{
			Ver:   RPCAP_VERSION,
			Type:  RPCAP_MSG_UPDATEFLT_REPLY,
			Value: 0,
			PLen:  0,
		},
	}, nil)

	return nil
}

func (ctx *Session) handleStats() {
	stats, err := ctx.handle.Stats()
	if err != nil {
		ctx.ReplyError(err)
		return
	}

	_ = ctx.Reply([]IMessage{
		&rpcapHeader{Ver: RPCAP_VERSION, Type: RPCAP_MSG_STATS_REPLY, Value: 0, PLen: uint32(16)},
		&rpcapStats{
			IfRecv:   uint32(stats.PacketsReceived),
			IfDrop:   uint32(stats.PacketsDropped),
			KRnlDrop: uint32(stats.PacketsIfDropped),
			SvrCapt:  ctx.totCapt,
		},
	}, nil)
}

func (ctx *Session) handleEndCapture() {
	if h := ctx.handle; h != nil {
		h.Close()
	}

	_ = ctx.Reply([]IMessage{
		&rpcapHeader{Ver: RPCAP_VERSION, Type: RPCAP_MSG_ENDCAP_REPLY, Value: 0, PLen: 0},
	}, nil)
}

func (ctx *Session) handleCloseLive() {

}

func main() {
	log.SetFlags(log.LstdFlags | log.Lshortfile)

	listen, err := net.ListenTCP("tcp4", &net.TCPAddr{
		Port: 2002,
	})
	if err != nil {
		log.Printf("listen failed: %v", err)
		return
	}
	log.Printf("rpcapd listening on %v", listen.Addr())

	for {
		conn, err := listen.Accept()
		if err != nil {
			log.Printf("accept error: %v", err)
			continue
		}

		session := NewSession(conn)
		go session.Loop()
	}
}
