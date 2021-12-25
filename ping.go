// Package ping is a simple but powerful ICMP echo (ping) library.
//
// Here is a very simple example that sends and receives three packets:
//
//	pinger, err := ping.NewPinger("www.google.com")
//	if err != nil {
//		panic(err)
//	}
//	pinger.Count = 3
//	err = pinger.Run() // blocks until finished
//	if err != nil {
//		panic(err)
//	}
//	stats := pinger.Statistics() // get send/receive/rtt stats
//
// Here is an example that emulates the traditional UNIX ping command:
//
//	pinger, err := ping.NewPinger("www.google.com")
//	if err != nil {
//		panic(err)
//	}
//	// Listen for Ctrl-C.
//	c := make(chan os.Signal, 1)
//	signal.Notify(c, os.Interrupt)
//	go func() {
//		for _ = range c {
//			pinger.Stop()
//		}
//	}()
//	pinger.OnRecv = func(pkt *ping.Packet) {
//		fmt.Printf("%d bytes from %s: icmp_seq=%d time=%v\n",
//			pkt.Nbytes, pkt.IPAddr, pkt.Seq, pkt.Rtt)
//	}
//	pinger.OnFinish = func(stats *ping.Statistics) {
//		fmt.Printf("\n--- %s ping statistics ---\n", stats.Addr)
//		fmt.Printf("%d packets transmitted, %d packets received, %v%% packet loss\n",
//			stats.PacketsSent, stats.PacketsRecv, stats.PacketLoss)
//		fmt.Printf("round-trip min/avg/max/stddev = %v/%v/%v/%v\n",
//			stats.MinRtt, stats.AvgRtt, stats.MaxRtt, stats.StdDevRtt)
//	}
//	fmt.Printf("PING %s (%s):\n", pinger.Addr(), pinger.IPAddr())
//	err = pinger.Run()
//	if err != nil {
//		panic(err)
//	}
//
// It sends ICMP Echo Request packet(s) and waits for an Echo Reply in response.
// If it receives a response, it calls the OnRecv callback. When it's finished,
// it calls the OnFinish callback.
//
// For a full ping example, see "cmd/ping/ping.go".
//
package ping

import (
	"math"
	"math/rand"
	"net"
	"sync"
	"sync/atomic"
	"syscall"
	"time"

	"github.com/google/uuid"
	"golang.org/x/net/icmp"
	"golang.org/x/net/ipv4"
	"golang.org/x/net/ipv6"
)

const (
	timeSliceLength  = 8
	trackerLength    = len(uuid.UUID{})
	protocolICMP     = 1
	protocolIPv6ICMP = 58
)

var (
	ipv4Proto = map[string]string{"icmp": "ip4:icmp", "udp": "udp4"}
	ipv6Proto = map[string]string{"icmp": "ip6:ipv6-icmp", "udp": "udp6"}
)

func Default(logger Logger) Pinger {
	p := New(logger)
	p.RecvRun()
	go p.StartCheck()
	return p
}

type Pinger interface {
	Send(pp PingIP)
}

// New returns a new Pinger struct pointer.
func New(logger Logger) *pingeserver {
	// r := rand.New(rand.NewSource(getSeed()))
	firstUUID := uuid.New()
	var firstSequence = map[uuid.UUID]map[int]struct{}{}
	firstSequence[firstUUID] = make(map[int]struct{})
	return &pingeserver{
		// Count:      -1,
		// Interval: time.Second,
		// RecordRtts: true,
		Size: timeSliceLength + trackerLength,
		// Timeout: time.Duration(math.MaxInt64),
		// addr: addr,
		done: make(chan interface{}),
		// id:                r.Intn(math.MaxUint16),
		// trackerUUIDs:      []uuid.UUID{firstUUID},
		// ipaddr:            nil,
		ipv4: true,
		// network:           "ip",
		protocol: "icmp",
		// awaitingSequences: firstSequence,
		TTL:    64,
		logger: logger,
		Task:   make(map[int]pingIPCache, 0),
	}
}

// NewPinger returns a new Pinger and resolves the address.
// func NewPinger(addr string) *Pinger {
// 	return New(addr)
// }

type pingIPCache struct {
	p PingIP
	t time.Time
}

// pingeserver represents a packet sender/receiver.
type pingeserver struct {
	Task  map[int]pingIPCache
	RWMtx sync.RWMutex
	conn  packetConn

	// Size of packet being sent
	Size int

	// Source is the source IP address
	Source string

	// Channel and mutex used to communicate when the Pinger should stop between goroutines.
	done chan interface{}
	lock sync.Mutex

	ipv4     bool
	protocol string

	logger Logger
	TTL    int
}

type packet struct {
	bytes  []byte
	nbytes int
	ttl    int
}

// Packet represents a received and processed ICMP echo packet.
type Packet struct {
	// Rtt is the round-trip time it took to ping.
	Rtt time.Duration

	// Addr is the string address of the host being pinged.
	Addr string

	// Seq is the ICMP sequence number.
	Seq int

	// ID is the ICMP identifier.
	ID int
}

// RecvRun runs the pinger. This is a blocking function that will exit when it's
// done. If Count or Interval are not specified, it will run continuously until
// it is interrupted.
func (p *pingeserver) RecvRun() {
	var conn packetConn
	var err error
	if p.Size < timeSliceLength+trackerLength {
		p.logger.Errorf("size %d is less than minimum required size %d", p.Size, timeSliceLength+trackerLength)
	}
	if err != nil {
		p.logger.Errorf("RecvRun Err[%v]", err)
	}
	if conn, err = p.listen(); err != nil {
		p.logger.Errorf("RecvRun Err[%v]", err)
	}
	// defer conn.Close()
	conn.SetTTL(p.TTL)
	if err := conn.SetFlagTTL(); err != nil {
		p.logger.Errorf("run Err[%v]", err)
		return
	}
	// defer p.finish()
	p.conn = conn
	go p.recvICMP()
}

func (p *pingeserver) Stop() {
	p.lock.Lock()
	defer p.lock.Unlock()

	open := true
	select {
	case _, open = <-p.done:
	default:
	}

	if open {
		close(p.done)
	}
}

func (p *pingeserver) recvICMP() {
	defer func() {
		p.Stop()
	}()
	for {
		select {
		case <-p.done:
			return
		default:
			bytes := make([]byte, p.getMessageLength())
			var n, ttl int
			var err error
			n, ttl, _, err = p.conn.ReadFrom(bytes)
			if err != nil {
				p.logger.Errorf("Recv Err[%v]", err)
			}
			go p.processPacket(&packet{bytes: bytes, nbytes: n, ttl: ttl})
		}
	}
}

type RecvPakcet struct {
	ID         int
	Seq        int
	Data       []byte
	ReceivedAt time.Time
}

func (p *pingeserver) processPacket(recv *packet) {
	receivedAt := time.Now()
	var proto int
	if p.ipv4 {
		proto = protocolICMP
	} else {
		proto = protocolIPv6ICMP
	}

	var m *icmp.Message
	var err error
	if m, err = icmp.ParseMessage(proto, recv.bytes); err != nil {
		p.logger.Errorf("error parsing icmp message: %w", err)
		return
	}
	if m.Type != ipv4.ICMPTypeEchoReply && m.Type != ipv6.ICMPTypeEchoReply {
		// Not an echo reply, ignore it
		return
	}
	switch pkt := m.Body.(type) {
	case *icmp.Echo:
		p.RWMtx.RLock()
		task, ok := p.Task[pkt.ID]
		p.RWMtx.RUnlock()
		if !ok {
			return
		}
		func() {
			defer func() {
				if r := recover(); r != nil {
					p.logger.Errorf("Task[%v] Panic[%v]", pkt.ID, r)
				}
			}()
			task.p.RecvBackHook(RecvPakcet{
				ID:         pkt.ID,
				Seq:        pkt.Seq,
				Data:       pkt.Data,
				ReceivedAt: receivedAt,
			})
		}()

	default:
		p.logger.Errorf("invalid ICMP echo reply; type: '%T', '%v'", pkt, pkt)
	}
	return
}

func (p *pingeserver) Send(pp PingIP) {
	p.RWMtx.Lock()
	p.Task[pp.ID()] = pingIPCache{
		p: pp,
		t: time.Now(),
	}
	p.RWMtx.Unlock()
	p.sendICMP(pp)
}

var (
	TaskTimeOut    = 20 * time.Second
	TaskCheckRound = 1 * time.Minute
)

func (p *pingeserver) StartCheck() {
	ticker := time.NewTicker(TaskCheckRound)
	defer ticker.Stop()
	for {
		select {
		case <-p.done:
			return
		case <-ticker.C:
			now := time.Now()
			l := make([]int, 0, len(p.Task)/3)
			p.RWMtx.RLock()
			for k, n := range p.Task {
				if now.Sub(n.t) > TaskTimeOut {
					l = append(l, k)
				}
			}
			p.RWMtx.RUnlock()
			if len(l) != 0 {
				p.RWMtx.Lock()
				for _, n := range l {
					delete(p.Task, n)
				}
				p.RWMtx.Unlock()
			}
		}
	}
}

func (p *pingeserver) sendICMP(pp PingIP) {
	msgBytes, dst := pp.SendPrexHook()
	// panic(fmt.Sprint("send: ", msgBytes, dst))
	for {
		if _, err := p.conn.WriteTo(msgBytes, dst); err != nil {
			if neterr, ok := err.(*net.OpError); ok {
				if neterr.Err == syscall.ENOBUFS {
					continue
				}
			}
			p.logger.Errorf("sendICMP Err[%v]", err)
			return
		}
		pp.SendBackHook()
		return
	}
}

func (p *pingeserver) listen() (packetConn, error) {
	var (
		conn packetConn
		err  error
	)

	if p.ipv4 {
		var c icmpv4Conn
		c.c, err = icmp.ListenPacket(ipv4Proto[p.protocol], p.Source)
		conn = &c
	} else {
		var c icmpV6Conn
		c.c, err = icmp.ListenPacket(ipv6Proto[p.protocol], p.Source)
		conn = &c
	}
	if err != nil {
		p.Stop()
		return nil, err
	}
	return conn, nil
}

func bytesToTime(b []byte) time.Time {
	var nsec int64
	for i := uint8(0); i < 8; i++ {
		nsec += int64(b[i]) << ((7 - i) * 8)
	}
	return time.Unix(nsec/1000000000, nsec%1000000000)
}

func isIPv4(ip net.IP) bool {
	return len(ip.To4()) == net.IPv4len
}

func timeToBytes(t time.Time) []byte {
	nsec := t.UnixNano()
	b := make([]byte, 8)
	for i := uint8(0); i < 8; i++ {
		b[i] = byte((nsec >> ((7 - i) * 8)) & 0xff)
	}
	return b
}

var seed int64 = time.Now().UnixNano()

// getSeed returns a goroutine-safe unique seed
func getSeed() int64 {
	return atomic.AddInt64(&seed, 1)
}

type Statistics struct {
	// PacketsRecv is the number of packets received.
	PacketsRecv int

	// PacketsSent is the number of packets sent.
	PacketsSent int

	// PacketsRecvDuplicates is the number of duplicate responses there were to a sent packet.
	PacketsRecvDuplicates int

	// PacketLoss is the percentage of packets lost.
	PacketLoss float64

	// IPAddr is the address of the host being pinged.
	IPAddr *net.IPAddr

	// Addr is the string address of the host being pinged.
	Addr string

	// Rtts is all of the round-trip times sent via this pinger.
	Rtts []time.Duration

	// MinRtt is the minimum round-trip time sent via this pinger.
	MinRtt time.Duration

	// MaxRtt is the maximum round-trip time sent via this pinger.
	MaxRtt time.Duration

	// AvgRtt is the average round-trip time sent via this pinger.
	AvgRtt time.Duration

	// StdDevRtt is the standard deviation of the round-trip times sent via
	// this pinger.
	StdDevRtt time.Duration
}

type PingIP interface {
	ID() int
	SendPrexHook() (b []byte, dst net.Addr)
	SendBackHook()
	RecvBackHook(RecvPakcet)
}

type PingIPTask struct {
	r        *rand.Rand
	id       int
	sequence int
	ipaddr   *net.IPAddr
	// interrupted.
	Count   int
	addr    string
	network string
	// Debug runs in debug mode
	// Debug bool

	// Number of packets sent
	PacketsSent int

	// Number of packets received
	PacketsRecv int

	// Number of duplicate packets received
	PacketsRecvDuplicates int

	// Round trip time statistics
	minRtt    time.Duration
	maxRtt    time.Duration
	avgRtt    time.Duration
	stdDevRtt time.Duration
	stddevm2  time.Duration
	statsMu   sync.RWMutex

	// If true, keep a record of rtts of all received packets.
	// Set to false to avoid memory bloat for long running pings.
	RecordRtts bool

	// rtts is all of the Rtts
	rtts     []time.Duration
	Interval time.Duration
	Timeout  time.Duration
	protocol string
	logger   Logger
	// awaitingSequences map[uuid.UUID]map[int]struct{}
	recvCh chan struct{}
	rstCh  chan *Statistics
}

func (p *PingIPTask) New(addr string, count int, logger Logger) {
	if p.r == nil {
		p.r = rand.New(rand.NewSource(getSeed()))
	}

	// firstUUID := uuid.New()
	// var firstSequence = map[uuid.UUID]map[int]struct{}{}
	// firstSequence[firstUUID] = make(map[int]struct{})
	if len(addr) == 0 {
		logger.Errorf("addr cannot be empty")
		return
	}
	ipaddr, err := net.ResolveIPAddr("ip", addr)
	if err != nil {
		logger.Errorf(err.Error())
		return
	}
	p.Count = count
	p.Interval = 500 * time.Millisecond
	p.RecordRtts = true
	p.Timeout = 10 * time.Second
	p.addr = addr
	// done:              make(chan interface{}),
	p.id = p.r.Intn(math.MaxUint16)
	// trackerUUIDs:      []uuid.UUID{firstUUID},
	p.ipaddr = ipaddr
	// ipv4:              false,
	p.network = "ip"
	p.protocol = "icmp"
	p.logger = logger
	p.recvCh = make(chan struct{}, count)
	p.rstCh = make(chan *Statistics, 1)
	p.rtts = make([]time.Duration, 0, count)
}

func (p *PingIPTask) Reset() {
	p.id = 0
	p.sequence = 0
	p.ipaddr = nil
	// interrupted.
	p.Count = 0
	p.addr = ""
	p.network = ""
	// Debug runs in debug mode
	// Debug bool

	// Number of packets sent
	p.PacketsSent = 0

	// Number of packets received
	p.PacketsRecv = 0

	// Number of duplicate packets received
	p.PacketsRecvDuplicates = 0

	// Round trip time statistics
	p.minRtt = 0
	p.maxRtt = 0
	p.avgRtt = 0
	p.stdDevRtt = 0
	p.stddevm2 = 0
	// p.statsMu   =sync.RWMutex

	// If true, keep a record of rtts of all received packets.
	// Set to false to avoid memory bloat for long running pings.
	p.RecordRtts = false

	// rtts is all of the Rtts
	p.rtts = nil
	p.Interval = 0
	p.Timeout = 0
	p.protocol = ""
	p.logger = nil
	// awaitingSequences map[uuid.UUID]map[int]struct{}
	p.recvCh = nil
	p.rstCh = nil
}

func (p *PingIPTask) Start(pinger Pinger) {
	go func() {
		for i := 0; i < p.Count; i++ {
			go pinger.Send(p)
			time.Sleep(p.Interval)
		}
		t := time.NewTimer(p.Timeout)
		var c int
		defer t.Stop()
		for {
			select {
			case <-t.C:
				p.rstCh <- p.Statistics()
				return
			case <-p.recvCh:
				c++
				if c >= p.Count {
					p.rstCh <- p.Statistics()
					return
				}
			}
		}
	}()
}

func (p *PingIPTask) ID() int {
	return p.id
}

func (p *PingIPTask) ICMPRequestType() icmp.Type {
	return ipv4.ICMPTypeEcho
}

func (p *PingIPTask) SendPrexHook() ([]byte, net.Addr) {
	var dst net.Addr = p.ipaddr
	if p.protocol == "udp" {
		dst = &net.UDPAddr{IP: p.ipaddr.IP, Zone: p.ipaddr.Zone}
	}
	// currentUUID := p.getCurrentTrackerUUID()
	// uuidEncoded, err := currentUUID.MarshalBinary()
	// if err != nil {
	// 	return fmt.Errorf("unable to marshal UUID binary: %w", err)
	// }
	// t := append(timeToBytes(time.Now()), uuidEncoded...)
	t := timeToBytes(time.Now())
	// if remainSize := p.Size - timeSliceLength - trackerLength; remainSize > 0 {
	// 	t = append(t, bytes.Repeat([]byte{1}, remainSize)...)
	// }

	body := &icmp.Echo{
		ID:   p.id,
		Seq:  p.sequence,
		Data: t,
	}

	msg := &icmp.Message{
		Type: p.ICMPRequestType(),
		Code: 0,
		Body: body,
	}

	msgBytes, err := msg.Marshal(nil)
	if err != nil {
		p.logger.Errorf("msgBytes Err[%v]", err)
	}
	return msgBytes, dst
}

func (p *PingIPTask) SendBackHook() {
	// handler := p.OnSend
	// if handler != nil {
	// 	outPkt := &Packet{
	// 		Nbytes: len(msgBytes),
	// 		IPAddr: p.ipaddr,
	// 		Addr:   p.addr,
	// 		Seq:    p.sequence,
	// 		ID:     p.id,
	// 	}
	// 	handler(outPkt)
	// }
	// mark this sequence as in-flight
	// p.awaitingSequences[currentUUID][p.sequence] = struct{}{}
	p.PacketsSent++
	p.sequence++
	if p.sequence > 65535 {
		// newUUID := uuid.New()
		// p.trackerUUIDs = append(p.trackerUUIDs, newUUID)
		// p.awaitingSequences[newUUID] = make(map[int]struct{})
		p.sequence = 0
	}
	// break
}

func (p *PingIPTask) RecvBackHook(r RecvPakcet) {

	// if !p.matchID(pkt.ID) {
	// 	return nil
	// }

	if len(r.Data) < timeSliceLength+trackerLength {
		p.logger.Errorf("insufficient data received; got: %d %v",
			len(r.Data), r.Data)
	}

	// pktUUID, err := p.getPacketUUID(pkt.Data)
	// if err != nil || pktUUID == nil {
	// 	return err
	// }

	timestamp := bytesToTime(r.Data[:timeSliceLength])
	p.updateStatistics(&Packet{
		// Nbytes: recv.nbytes,
		// IPAddr: p.ipaddr,
		Addr: p.addr,
		// Ttl:    recv.ttl,
		ID:  p.id,
		Seq: r.Seq,
		Rtt: r.ReceivedAt.Sub(timestamp),
	})
	p.recvCh <- struct{}{}
}

func (p *PingIPTask) Rst() *Statistics {
	return <-p.rstCh
}

// func (p *pingIP) Reset() {

// }

func (p *PingIPTask) updateStatistics(pkt *Packet) {
	p.statsMu.Lock()
	defer p.statsMu.Unlock()

	p.PacketsRecv++
	if p.RecordRtts {
		p.rtts = append(p.rtts, pkt.Rtt)
	}

	if p.PacketsRecv == 1 || pkt.Rtt < p.minRtt {
		p.minRtt = pkt.Rtt
	}

	if pkt.Rtt > p.maxRtt {
		p.maxRtt = pkt.Rtt
	}

	pktCount := time.Duration(p.PacketsRecv)
	delta := pkt.Rtt - p.avgRtt
	p.avgRtt += delta / pktCount
	delta2 := pkt.Rtt - p.avgRtt
	p.stddevm2 += delta * delta2

	p.stdDevRtt = time.Duration(math.Sqrt(float64(p.stddevm2 / pktCount)))
}

func (p *PingIPTask) Statistics() *Statistics {
	p.statsMu.RLock()
	defer p.statsMu.RUnlock()
	sent := p.PacketsSent
	loss := float64(sent-p.PacketsRecv) / float64(sent) * 100
	s := Statistics{
		PacketsSent:           sent,
		PacketsRecv:           p.PacketsRecv,
		PacketsRecvDuplicates: p.PacketsRecvDuplicates,
		PacketLoss:            loss,
		Rtts:                  p.rtts,
		Addr:                  p.addr,
		IPAddr:                p.ipaddr,
		MaxRtt:                p.maxRtt,
		MinRtt:                p.minRtt,
		AvgRtt:                p.avgRtt,
		StdDevRtt:             p.stdDevRtt,
	}
	return &s
}

// func NewPingIPByPool() *pingIP {

// }

// type pool struct {
// 	topic  string
// 	ppFree sync.Pool
// }

// func newPool(topic string) *pool {
// 	return &pool{
// 		topic: topic,
// 		ppFree: sync.Pool{
// 			New: func() interface{} { return &pingIP{} },
// 		},
// 	}
// }

// func (p *pool) getMsg(b []byte) *pingIP {
// 	return p.ppFree.Get().(*pingIP)
// }

// func (p *pool) putMsg(pd *pingIP) {
// 	p.ppFree.Put(pd)
// }
