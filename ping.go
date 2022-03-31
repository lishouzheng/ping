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
	"fmt"
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
	ipv4Proto = map[string]func() string{
		// icmp协议号为1
		"icmp": func() string { return "ip4:icmp" },
		"udp":  func() string { return "udp4" }}
	ipv6Proto = map[string]string{"icmp": "ip6:ipv6-icmp", "udp": "udp6"}
)
var (
	// 负责错误处理回调
	ErrorInf ErrorCallback
)

type ErrorCallback interface {
	F(err error)
}

func init() {
	// 全局rand自带锁
	rand.Seed(time.Now().Unix())
}

func NewPinger(logger Logger) Pinger {
	p := New(logger)
	p.RecvRun()
	return p
}

func Default(logger Logger) Pinger {
	return NewPinger(logger)
}

type Pinger interface {
	Send(pp PingIP)
	AddTask(pp PingIP)
	CloseTask(pp PingIP)
	Stop()
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
		// r := rand.New(rand.NewSource(getSeed()))

		// ipaddr:            nil,
		ipv4: true,
		// network:           "ip",
		protocol: "icmp",
		TTL:      64,
		logger:   logger,
		Task:     make(map[uuid.UUID]pingIPCache, 0),
	}
}

// NewPinger returns a new Pinger and resolves the address.
// func NewPinger(addr string) *Pinger {
// 	return New(addr)
// }

type pingIPCache struct {
	p PingIP
}

// pingeserver represents a packet sender/receiver.
type pingeserver struct {
	TaskID [math.MaxUint16 + 1]int64
	Task   map[uuid.UUID]pingIPCache
	RWMtx  sync.RWMutex
	conn   packetConn

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
		return
	}
	if err != nil {
		p.logger.Errorf("RecvRun Err[%v]", err)
		return
	}
	if conn, err = p.listen(); err != nil {
		p.logger.Errorf("RecvRun Err[%v]", err)
		return
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
	p.conn.Close()
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
				continue
			}
			go p.processPacket(&packet{bytes: bytes, nbytes: n, ttl: ttl})
		}
	}
}

type RecvPakcet struct {
	ID         int
	Seq        int
	PktUUID    *uuid.UUID
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
		// fmt.Println("start...", p.Task)
		// for i, n := range p.TaskID {
		// 	if n > 0 {
		// 		fmt.Println(i, n)
		// 	}
		// }
		// fmt.Println("end, ", pkt.ID)
		// 先检查ID, 减少解析; 优化性能

		f := atomic.LoadInt64(&p.TaskID[pkt.ID])
		if f <= 0 {
			return
		}
		// 开始解析
		if len(pkt.Data) < timeSliceLength+trackerLength {
			return
		}
		pktUUID, err := p.getPacketUUID(pkt.Data)
		if err != nil {
			p.logger.Errorf("processPacket[%v][%v]", err, pktUUID)
			return
		}
		// 分流
		p.RWMtx.RLock()
		task, ok := p.Task[*pktUUID]
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
				PktUUID:    pktUUID,
				Data:       pkt.Data,
				ReceivedAt: receivedAt,
			})
		}()

	default:
		p.logger.Errorf("invalid ICMP echo reply; type: '%T', '%v'", pkt, pkt)
	}
	return
}

// getPacketUUID scans the tracking slice for matches.
func (p *pingeserver) getPacketUUID(pkt []byte) (*uuid.UUID, error) {
	var packetUUID uuid.UUID
	err := packetUUID.UnmarshalBinary(pkt[timeSliceLength : timeSliceLength+trackerLength])
	if err != nil {
		return nil, fmt.Errorf("error decoding tracking UUID: %w", err)
	}
	return &packetUUID, nil
}

func (p *pingeserver) AddTask(pp PingIP) {
	atomic.AddInt64(&p.TaskID[pp.ID()], 1)
	p.RWMtx.Lock()
	defer p.RWMtx.Unlock()
	p.Task[pp.UUID()] = pingIPCache{
		p: pp,
	}

}

func (p *pingeserver) Send(pp PingIP) {
	p.sendICMP(pp)
}

func (p *pingeserver) CloseTask(pp PingIP) {
	atomic.AddInt64(&p.TaskID[pp.ID()], -1)
	p.RWMtx.Lock()
	defer p.RWMtx.Unlock()
	if _, ok := p.Task[pp.UUID()]; ok {
		delete(p.Task, pp.UUID())
	}
}

// var (
// 	TaskTimeOut    = 20 * time.Second
// 	TaskCheckRound = 1 * time.Minute
// )

// func (p *pingeserver) StartCheck() {
// 	ticker := time.NewTicker(TaskCheckRound)
// 	defer ticker.Stop()
// 	for {
// 		select {
// 		case <-p.done:
// 			return
// 		case <-ticker.C:
// 			now := time.Now()
// 			l := make([]int, 0, len(p.Task)/3)
// 			p.RWMtx.RLock()
// 			for k, n := range p.Task {
// 				if now.Sub(n.t) > TaskTimeOut {
// 					l = append(l, k)
// 				}
// 			}
// 			p.RWMtx.RUnlock()
// 			if len(l) != 0 {
// 				p.RWMtx.Lock()
// 				for _, n := range l {
// 					delete(p.Task, n)
// 				}
// 				p.RWMtx.Unlock()
// 			}
// 		}
// 	}
// }

func (p *pingeserver) sendICMP(pp PingIP) {
	msgBytes, dst := pp.SendPrexHook()
	if dst == nil {
		return
	}
	// panic(fmt.Sprint("send: ", msgBytes, dst))
	for {
		if _, err := p.conn.WriteTo(msgBytes, dst); err != nil {
			if neterr, ok := err.(*net.OpError); ok {
				if neterr.Err == syscall.ENOBUFS {
					continue
				}
			}
			p.logger.Errorf("sendICMP Err[%v]", err)
			if handler := ErrorInf; handler != nil {
				handler.F(err)
			}
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
		var c icmpv4Conn = icmpv4Conn{logger: p.logger}
		c.c, err = icmp.ListenPacket(ipv4Proto[p.protocol](), p.Source)
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
	UUID() uuid.UUID
	ID() int
	SendPrexHook() (b []byte, dst net.Addr)
	SendBackHook()
	RecvBackHook(RecvPakcet)
}

type PingIPTask struct {
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
	statsMu   *sync.RWMutex

	// If true, keep a record of rtts of all received packets.
	// Set to false to avoid memory bloat for long running pings.
	RecordRtts bool

	// rtts is all of the Rtts
	rtts     []time.Duration
	Interval time.Duration
	Timeout  time.Duration
	protocol string
	logger   Logger
	rstCh    chan *Statistics
	recvCh   chan struct{}
	pinger   Pinger
	Size     int
	// 不用重置
	mtx               *sync.Mutex
	trackerUUID       uuid.UUID
	awaitingSequences map[int]struct{}
}

func (p *PingIPTask) New(addr string, count int, logger Logger, pinger Pinger) {
	if len(addr) == 0 {
		logger.Errorf("addr cannot be empty")
		return
	}
	ipaddr, err := net.ResolveIPAddr("ip", addr)
	if err != nil {
		logger.Errorf(err.Error())
		return
	}
	p.trackerUUID = uuid.New()
	p.awaitingSequences = make(map[int]struct{}, 0)
	p.Count = count
	p.Interval = 500 * time.Millisecond
	p.RecordRtts = true
	p.Timeout = 10 * time.Second
	p.addr = addr
	// done:              make(chan interface{}),
	p.id = rand.Intn(math.MaxUint16)
	// trackerUUIDs:      []uuid.UUID{firstUUID},
	p.ipaddr = ipaddr
	// ipv4:              false,
	p.network = "ip"
	p.protocol = "icmp"
	p.logger = logger
	p.rstCh = make(chan *Statistics, 1)
	p.rtts = make([]time.Duration, 0, count)
	p.recvCh = make(chan struct{}, count)
	p.pinger = pinger
	p.Size = timeSliceLength + trackerLength
}

// 共28个字段, 其中重置28个
// mtx和rwmtx也要重置
func (p *PingIPTask) Reset() {
	p.trackerUUID = uuid.Nil
	p.awaitingSequences = nil
	p.Size = 0
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
	p.rstCh = nil
	p.recvCh = nil
	p.pinger = nil
	p.mtx = &sync.Mutex{}
	p.statsMu = &sync.RWMutex{}
}

func (p *PingIPTask) Start() {
	go func() {
		defer func() {
			// 不需要后续处理, 自会接收超时
			if r := recover(); r != nil {
				if p.logger != nil {
					p.logger.Errorf("PingIPTask Err[%v]", r)
				} else {
					fmt.Printf("PingIPTask Err[%v]\n", r)
				}
				if handler := ErrorInf; handler != nil {
					handler.F(fmt.Errorf("%v", r))
				}
			}
		}()
		p.pinger.AddTask(p)
		for i := 0; i < p.Count; i++ {
			// 这里不需要并发, 就是要间隔发送
			p.pinger.Send(p)
			time.Sleep(p.Interval)
		}
	}()
	go func() {
		t := time.NewTimer(p.Timeout)
		defer t.Stop()
		recvCh := p.recvCh
		for {
			select {
			case <-recvCh:
				if p.PacketsRecv >= p.Count {
					p.pinger.CloseTask(p)
					p.rstCh <- p.Statistics()
					return
				}
			case <-t.C:
				p.pinger.CloseTask(p)
				p.rstCh <- p.Statistics()
				return
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

func (p *PingIPTask) UUID() uuid.UUID {
	return p.trackerUUID
}

func (p *PingIPTask) SendPrexHook() ([]byte, net.Addr) {
	var dst net.Addr = p.ipaddr
	if p.protocol == "udp" {
		dst = &net.UDPAddr{IP: p.ipaddr.IP, Zone: p.ipaddr.Zone}
	}
	uuidEncoded, err := p.trackerUUID.MarshalBinary()
	if err != nil {
		p.logger.Errorf("unable to marshal UUID binary: %w", err)
		return nil, nil
	}
	t := append(timeToBytes(time.Now()), uuidEncoded...)

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
		return nil, nil
	}
	return msgBytes, dst
}

func (p *PingIPTask) SendBackHook() {
	defer func() {
		if r := recover(); r != nil {
			p.logger.Errorf("SendBackHook Err[%v]", r)
		}
	}()
	p.PacketsSent++
	p.sequence++

	if p.sequence > 65535 {
		mtx := p.mtx
		p.trackerUUID = uuid.New()
		mtx.Lock()
		p.awaitingSequences = make(map[int]struct{})
		mtx.Unlock()
		p.sequence = 0
	}
}

// RecvBackHook return true, close
func (p *PingIPTask) RecvBackHook(r RecvPakcet) {
	if r.ID != p.id {
		return
	}
	defer func() {
		if r := recover(); r != nil {
			p.logger.Errorf("RecvBackHook Err[%v]", r)
		}
	}()
	mtx := p.mtx
	mtx.Lock()
	_, ok := p.awaitingSequences[r.Seq]
	if ok {
		mtx.Unlock()
		return
	}
	p.awaitingSequences[r.Seq] = struct{}{}
	mtx.Unlock()
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
	// nil chan会阻塞
	select {
	case p.recvCh <- struct{}{}:
	default:
	}
}

func (p *PingIPTask) Rst() *Statistics {
	return <-p.rstCh
}

// func (p *pingIP) Reset() {

// }

func (p *PingIPTask) updateStatistics(pkt *Packet) {
	statsMu := p.statsMu
	statsMu.Lock()
	defer statsMu.Unlock()
	defer func() {
		if r := recover(); r != nil {
			p.logger.Errorf("updateStatistics Err[%v]", r)
		}
	}()
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
	statsMu := p.statsMu
	statsMu.RLock()
	defer statsMu.RUnlock()
	defer func() {
		if r := recover(); r != nil {
			p.logger.Errorf("Statistics Err[%v]", r)
		}
	}()
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
