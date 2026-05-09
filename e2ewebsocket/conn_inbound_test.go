package e2ewebsocket

import (
	"fmt"
	"testing"

	im_parser "github.com/qs3c/e2e-secure-ws/e2ewebsocket/im_parser"
)

type fakeInboundMsgData struct {
	sendID      string
	recvID      string
	clientMsgID string
	serverMsgID string
	seq         int64
	content     []byte
	ex          string
}

func (f *fakeInboundMsgData) GetSendID() string         { return f.sendID }
func (f *fakeInboundMsgData) GetRecvID() string         { return f.recvID }
func (f *fakeInboundMsgData) GetContent() []byte        { return f.content }
func (f *fakeInboundMsgData) SetContent(content []byte) { f.content = content }
func (f *fakeInboundMsgData) GetEx() string             { return f.ex }
func (f *fakeInboundMsgData) SetEx(ex string)           { f.ex = ex }
func (f *fakeInboundMsgData) GetClientMsgID() string    { return f.clientMsgID }
func (f *fakeInboundMsgData) GetServerMsgID() string    { return f.serverMsgID }
func (f *fakeInboundMsgData) GetSeq() int64             { return f.seq }

var _ im_parser.MsgData = (*fakeInboundMsgData)(nil)

type fakeRecoveryParser struct{}

func (fakeRecoveryParser) ConstructMsgData(sendID, recvID string, msg []byte) im_parser.MsgData {
	return &fakeInboundMsgData{sendID: sendID, recvID: recvID, content: msg}
}

func (fakeRecoveryParser) MsgDataToBytesWriteBound(msgData im_parser.MsgData) ([]byte, error) {
	return msgData.GetContent(), nil
}

func (fakeRecoveryParser) BytesToMsgDataWriteBound(data []byte) (im_parser.MsgData, error) {
	return nil, im_parser.ErrBypassSecureWS
}

func (fakeRecoveryParser) MsgDataToBytesReadBound(msgData im_parser.MsgData) ([]byte, error) {
	ref := "unknown"
	if meta, ok := msgData.(messageMetaProvider); ok {
		ref = fmt.Sprintf("%d", meta.GetSeq())
	}
	return []byte(ref + ":" + string(msgData.GetContent())), nil
}

func (fakeRecoveryParser) BytesToMsgDataReadBound(data []byte) (im_parser.MsgData, error) {
	return nil, im_parser.ErrBypassSecureWS
}

func TestInboundPeerIDUsesRecvIDForSenderSyncCopy(t *testing.T) {
	conn := &Conn{hostId: "alice"}
	msg := &fakeInboundMsgData{sendID: "alice", recvID: "bob"}
	if got := conn.inboundPeerID(msg); got != "bob" {
		t.Fatalf("inboundPeerID() = %q, want %q", got, "bob")
	}
}

func TestShouldDropSecureSelfEcho(t *testing.T) {
	conn := &Conn{hostId: "alice"}

	if !conn.shouldDropSecureSelfEcho(&fakeInboundMsgData{sendID: "alice", recvID: "bob"}) {
		t.Fatal("expected secure sender echo to be dropped")
	}
	if conn.shouldDropSecureSelfEcho(&fakeInboundMsgData{sendID: "bob", recvID: "alice"}) {
		t.Fatal("expected peer message to be processed")
	}
	if conn.shouldDropSecureSelfEcho(&fakeInboundMsgData{sendID: "alice", recvID: "alice"}) {
		t.Fatal("expected self-chat message not to be classified as sender echo")
	}
}

func TestPlaintextHelloRecordDetected(t *testing.T) {
	conn := &Conn{hostId: "alice", config: defaultConfig()}
	session := NewSession(getSessionID("alice", "bob"), "bob", conn)
	hello, err := session.makeHello()
	if err != nil {
		t.Fatalf("makeHello() error = %v", err)
	}
	helloBytes, err := hello.marshal()
	if err != nil {
		t.Fatalf("hello.marshal() error = %v", err)
	}

	record := append([]byte{byte(recordTypeHandshake)}, helloBytes...)
	if !isPlaintextHelloRecord(record) {
		t.Fatal("expected plaintext hello record to be detected")
	}

	badRecord := append([]byte{byte(recordTypeHandshake)}, []byte{0, 1, 2, 3}...)
	if isPlaintextHelloRecord(badRecord) {
		t.Fatal("expected malformed handshake record not to be detected as hello")
	}
}

func TestRecoveryRestoresLostMessageBeforeBufferedLaterSeq(t *testing.T) {
	sessionID := getSessionID("alice", "bob")
	conn := &Conn{
		hostId:   "alice",
		msgChan:  make(chan readMsgItem, 4),
		imParser: fakeRecoveryParser{},
	}
	conn.initRecovery()
	session := NewSession(sessionID, "bob", conn)

	lost := &fakeInboundMsgData{
		sendID:      "bob",
		recvID:      "alice",
		clientMsgID: "m1",
		seq:         10,
		content:     []byte("old-cipher"),
	}
	later := &fakeInboundMsgData{
		sendID:      "bob",
		recvID:      "alice",
		clientMsgID: "m2",
		seq:         11,
		content:     []byte("two"),
	}

	conn.recovery.mu.Lock()
	state := conn.reorderStateLocked(sessionID)
	state.lost[messageRefKey(conn.messageRef(lost))] = lostInboundMsg{
		ref:     conn.messageRef(lost),
		peerID:  "bob",
		msgType: 2,
		msgData: lost,
	}
	conn.recovery.mu.Unlock()

	conn.deliverApplication(sessionID, conn.messageRef(later), readMsgItem{
		sessionId: sessionID,
		remoteId:  "bob",
		msgType:   2,
		msg:       []byte("11:two"),
	})

	select {
	case item := <-conn.msgChan:
		t.Fatalf("expected later message to be buffered, got %q", string(item.msg))
	default:
	}

	conn.handleRetransmit(session, "bob", []secureControlMsgPayload{
		{Ref: conn.messageRef(lost), Content: []byte("one")},
	})

	first := <-conn.msgChan
	if string(first.msg) != "10:one" {
		t.Fatalf("first delivered msg = %q, want %q", string(first.msg), "10:one")
	}
	second := <-conn.msgChan
	if string(second.msg) != "11:two" {
		t.Fatalf("second delivered msg = %q, want %q", string(second.msg), "11:two")
	}
}

func TestRecoveryBuffersOutOfOrderRetransmit(t *testing.T) {
	sessionID := getSessionID("alice", "bob")
	conn := &Conn{
		hostId:   "alice",
		msgChan:  make(chan readMsgItem, 4),
		imParser: fakeRecoveryParser{},
	}
	conn.initRecovery()
	session := NewSession(sessionID, "bob", conn)

	firstLost := &fakeInboundMsgData{sendID: "bob", recvID: "alice", clientMsgID: "m1", seq: 10}
	secondLost := &fakeInboundMsgData{sendID: "bob", recvID: "alice", clientMsgID: "m2", seq: 11}

	conn.recovery.mu.Lock()
	state := conn.reorderStateLocked(sessionID)
	state.lost[messageRefKey(conn.messageRef(firstLost))] = lostInboundMsg{
		ref:     conn.messageRef(firstLost),
		peerID:  "bob",
		msgType: 2,
		msgData: firstLost,
	}
	state.lost[messageRefKey(conn.messageRef(secondLost))] = lostInboundMsg{
		ref:     conn.messageRef(secondLost),
		peerID:  "bob",
		msgType: 2,
		msgData: secondLost,
	}
	conn.recovery.mu.Unlock()

	conn.handleRetransmit(session, "bob", []secureControlMsgPayload{
		{Ref: conn.messageRef(secondLost), Content: []byte("two")},
	})

	select {
	case item := <-conn.msgChan:
		t.Fatalf("expected seq 11 retransmit to wait for seq 10, got %q", string(item.msg))
	default:
	}

	conn.handleRetransmit(session, "bob", []secureControlMsgPayload{
		{Ref: conn.messageRef(firstLost), Content: []byte("one")},
	})

	first := <-conn.msgChan
	if string(first.msg) != "10:one" {
		t.Fatalf("first delivered msg = %q, want %q", string(first.msg), "10:one")
	}
	second := <-conn.msgChan
	if string(second.msg) != "11:two" {
		t.Fatalf("second delivered msg = %q, want %q", string(second.msg), "11:two")
	}
}
