//go:build sm2mlkem

package e2ewebsocket

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/gorilla/websocket"
	"github.com/openimsdk/protocol/sdkws"
	openimmarshal "github.com/qs3c/e2e-secure-ws/e2ewebsocket/im_parser/openim_marshal"
	"github.com/qs3c/e2e-secure-ws/encoder"
	"google.golang.org/protobuf/proto"
)

func TestE2E_SM2MLKEMHandshakeAndMessage(t *testing.T) {
	keyStorePath := t.TempDir()
	aliceID := "1111111111"
	bobID := "2222222222"
	setupKeyStore(t, keyStorePath, aliceID)
	setupKeyStore(t, keyStorePath, bobID)

	ms := newMockServer()
	s := httptest.NewServer(http.HandlerFunc(ms.handler))
	defer s.Close()
	wsURL := "ws" + strings.TrimPrefix(s.URL, "http")

	mockComp := &MockCompressor{}
	parser := openimmarshal.NewOpenIMParser(encoder.NewGobEncoder(), mockComp)
	newConn := func(hostID string) *Conn {
		conn, err := NewSecureConn(&Config{
			KeyStorePath:   keyStorePath,
			EnableSM2MLKEM: true,
			Compressor:     mockComp,
			Encoder:        encoder.NewGobEncoder(),
		}, parser)
		if err != nil {
			t.Fatalf("[%s] NewSecureConn failed: %v", hostID, err)
		}
		if _, err := conn.DialAndSetUserId(wsURL+"?uid="+hostID, hostID, nil); err != nil {
			t.Fatalf("[%s] Dial failed: %v", hostID, err)
		}
		return conn
	}

	alice := newConn(aliceID)
	defer alice.Close()
	bob := newConn(bobID)
	defer bob.Close()
	time.Sleep(50 * time.Millisecond)

	payload := makeAppMsg(t, aliceID, bobID, []byte("hello sm2mlkem"))
	if err := alice.WriteMessage(websocket.BinaryMessage, payload); err != nil {
		t.Fatalf("Alice WriteMessage failed: %v", err)
	}

	_, msg, err := bob.ReadMessage()
	if err != nil {
		t.Fatalf("Bob ReadMessage failed: %v", err)
	}
	var recvResp Resp
	if err := encoder.NewGobEncoder().Decode(msg, &recvResp); err != nil {
		t.Fatal(err)
	}
	var pushMsg sdkws.PushMessages
	if err := proto.Unmarshal(recvResp.Data, &pushMsg); err != nil {
		t.Fatal(err)
	}
	var got string
	for _, pull := range pushMsg.Msgs {
		for _, m := range pull.Msgs {
			got = string(m.Content)
		}
	}
	if got != "hello sm2mlkem" {
		t.Fatalf("Bob received %q, want %q", got, "hello sm2mlkem")
	}
}
