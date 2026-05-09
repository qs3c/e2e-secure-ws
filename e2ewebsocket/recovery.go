package e2ewebsocket

import (
	"encoding/json"
	"fmt"
	"log"
	"sort"
	"sync"
	"time"

	im_parser "github.com/qs3c/e2e-secure-ws/e2ewebsocket/im_parser"
)

const (
	secureControlLostRequest = "lost_request"
	secureControlRetransmit  = "retransmit"

	maxSendCacheEntries   = 256
	lostRetransmitTimeout = 6 * time.Second
)

type messageMetaProvider interface {
	GetClientMsgID() string
	GetServerMsgID() string
	GetSeq() int64
}

type secureMessageRef struct {
	SendID      string `json:"sendID,omitempty"`
	RecvID      string `json:"recvID,omitempty"`
	ClientMsgID string `json:"clientMsgID,omitempty"`
	ServerMsgID string `json:"serverMsgID,omitempty"`
	Seq         int64  `json:"seq,omitempty"`
}

type secureControlFrame struct {
	Type     string                    `json:"type"`
	Messages []secureControlMsgPayload `json:"messages,omitempty"`
}

type secureControlMsgPayload struct {
	Ref     secureMessageRef `json:"ref"`
	Content []byte           `json:"content,omitempty"`
}

type cachedOutboundMsg struct {
	ref     secureMessageRef
	content []byte
}

type lostInboundMsg struct {
	ref       secureMessageRef
	peerID    string
	msgType   int
	msgData   im_parser.MsgData
	createdAt time.Time
}

type pendingInboundMsg struct {
	ref  secureMessageRef
	item readMsgItem
}

type reorderState struct {
	lost    map[string]lostInboundMsg
	pending map[string]pendingInboundMsg
}

type recoveryState struct {
	mu sync.Mutex

	sendCache      map[string]cachedOutboundMsg
	sendCacheOrder []string

	reorder map[SessionID]*reorderState
}

func (c *Conn) initRecovery() {
	if c.recovery.sendCache == nil {
		c.recovery.sendCache = make(map[string]cachedOutboundMsg)
	}
	if c.recovery.reorder == nil {
		c.recovery.reorder = make(map[SessionID]*reorderState)
	}
}

func (c *Conn) cacheOutboundMessage(msgData im_parser.MsgData) {
	ref := c.messageRef(msgData)
	if ref.ClientMsgID == "" && ref.ServerMsgID == "" && ref.Seq == 0 {
		return
	}

	entry := cachedOutboundMsg{
		ref:     ref,
		content: append([]byte(nil), msgData.GetContent()...),
	}

	c.recovery.mu.Lock()
	defer c.recovery.mu.Unlock()

	if c.recovery.sendCache == nil {
		c.initRecovery()
	}

	key := messageRefKey(ref)
	if key == "" {
		return
	}
	if _, exists := c.recovery.sendCache[key]; !exists {
		c.recovery.sendCacheOrder = append(c.recovery.sendCacheOrder, key)
	}
	c.recovery.sendCache[key] = entry

	for len(c.recovery.sendCacheOrder) > maxSendCacheEntries {
		oldest := c.recovery.sendCacheOrder[0]
		c.recovery.sendCacheOrder = c.recovery.sendCacheOrder[1:]
		delete(c.recovery.sendCache, oldest)
	}
}

func (c *Conn) markLostInbound(session *Session, peerID string, msgType int, msgData im_parser.MsgData, reason string) {
	if session == nil || msgData == nil {
		return
	}

	ref := c.messageRef(msgData)
	if ref.ClientMsgID == "" && ref.ServerMsgID == "" && ref.Seq == 0 {
		log.Printf("secure recovery cannot mark lost message without identity for session %s: %s", session.id, reason)
		return
	}

	key := messageRefKey(ref)
	if key == "" {
		return
	}

	c.recovery.mu.Lock()
	if c.recovery.reorder == nil {
		c.initRecovery()
	}
	state := c.reorderStateLocked(session.id)
	if _, exists := state.lost[key]; !exists {
		state.lost[key] = lostInboundMsg{
			ref:       ref,
			peerID:    peerID,
			msgType:   msgType,
			msgData:   msgData,
			createdAt: time.Now(),
		}
	}
	c.recovery.mu.Unlock()

	log.Printf("secure recovery marked lost message session=%s key=%s seq=%d reason=%s", session.id, key, ref.Seq, reason)
	go c.requestLostAfterHandshake(session, ref)
	go c.expireLostInbound(session.id, key, ref.Seq)
}

func (c *Conn) requestLostAfterHandshake(session *Session, ref secureMessageRef) {
	if session == nil {
		return
	}
	if !session.isHandshakeComplete.Load() {
		select {
		case <-session.handshakeComplete:
		case <-session.done:
			return
		case <-time.After(lostRetransmitTimeout):
			log.Printf("secure recovery lost request wait timeout for session %s key=%s", session.id, messageRefKey(ref))
			return
		}
	}

	frame := secureControlFrame{
		Type: secureControlLostRequest,
		Messages: []secureControlMsgPayload{
			{Ref: ref},
		},
	}
	if err := c.writeSecureControl(session, frame); err != nil {
		log.Printf("secure recovery failed to send lost request for session %s key=%s: %v", session.id, messageRefKey(ref), err)
	}
}

func (c *Conn) expireLostInbound(sessionId SessionID, key string, seq int64) {
	time.Sleep(lostRetransmitTimeout)

	var ready []readMsgItem
	c.recovery.mu.Lock()
	state := c.recovery.reorder[sessionId]
	if state == nil {
		c.recovery.mu.Unlock()
		return
	}
	if _, exists := state.lost[key]; !exists {
		c.recovery.mu.Unlock()
		return
	}

	delete(state.lost, key)
	log.Printf("secure recovery timed out waiting retransmit session=%s key=%s seq=%d; releasing later messages", sessionId, key, seq)
	ready = c.flushReadyPendingLocked(sessionId, state)
	c.recovery.mu.Unlock()

	c.emitReadItems(ready)
}

func (c *Conn) deliverApplication(sessionId SessionID, ref secureMessageRef, item readMsgItem) {
	var ready []readMsgItem

	c.recovery.mu.Lock()
	if c.recovery.reorder == nil {
		c.initRecovery()
	}
	state := c.reorderStateLocked(sessionId)
	if c.hasBlockingGapLocked(state, ref) {
		key := messageRefKey(ref)
		if key == "" {
			key = fmt.Sprintf("pending:%d:%d", ref.Seq, time.Now().UnixNano())
		}
		state.pending[key] = pendingInboundMsg{ref: ref, item: item}
		log.Printf("secure recovery buffered message session=%s key=%s seq=%d behind missing gap", sessionId, key, ref.Seq)
		c.recovery.mu.Unlock()
		return
	}
	c.recovery.mu.Unlock()

	c.msgChan <- item
	ready = c.flushReadyPending(sessionId)
	c.emitReadItems(ready)
}

func (c *Conn) flushReadyPending(sessionId SessionID) []readMsgItem {
	c.recovery.mu.Lock()
	defer c.recovery.mu.Unlock()

	state := c.recovery.reorder[sessionId]
	if state == nil {
		return nil
	}
	return c.flushReadyPendingLocked(sessionId, state)
}

func (c *Conn) flushReadyPendingLocked(sessionId SessionID, state *reorderState) []readMsgItem {
	if state == nil || len(state.pending) == 0 {
		return nil
	}

	pending := make([]pendingInboundMsg, 0, len(state.pending))
	for _, msg := range state.pending {
		pending = append(pending, msg)
	}
	sort.SliceStable(pending, func(i, j int) bool {
		if pending[i].ref.Seq == 0 || pending[j].ref.Seq == 0 {
			return messageRefKey(pending[i].ref) < messageRefKey(pending[j].ref)
		}
		return pending[i].ref.Seq < pending[j].ref.Seq
	})

	ready := make([]readMsgItem, 0, len(pending))
	for _, msg := range pending {
		if c.hasBlockingGapLocked(state, msg.ref) {
			continue
		}
		delete(state.pending, messageRefKey(msg.ref))
		ready = append(ready, msg.item)
		log.Printf("secure recovery released buffered message session=%s key=%s seq=%d", sessionId, messageRefKey(msg.ref), msg.ref.Seq)
	}
	return ready
}

func (c *Conn) hasBlockingGapLocked(state *reorderState, ref secureMessageRef) bool {
	if state == nil || ref.Seq == 0 {
		return false
	}
	for _, lost := range state.lost {
		if lost.ref.Seq > 0 && lost.ref.Seq < ref.Seq {
			return true
		}
	}
	return false
}

func (c *Conn) handleSecureControl(session *Session, peerID string, payload []byte) {
	var frame secureControlFrame
	if err := json.Unmarshal(payload, &frame); err != nil {
		log.Printf("secure recovery invalid control frame from %s: %v", peerID, err)
		return
	}

	switch frame.Type {
	case secureControlLostRequest:
		c.handleLostRequest(session, frame.Messages)
	case secureControlRetransmit:
		c.handleRetransmit(session, peerID, frame.Messages)
	default:
		log.Printf("secure recovery unknown control type from %s: %s", peerID, frame.Type)
	}
}

func (c *Conn) handleLostRequest(session *Session, messages []secureControlMsgPayload) {
	if session == nil {
		return
	}

	response := secureControlFrame{Type: secureControlRetransmit}

	c.recovery.mu.Lock()
	for _, msg := range messages {
		entry, ok := c.findCachedOutboundLocked(msg.Ref)
		if !ok {
			log.Printf("secure recovery outbound cache miss session=%s key=%s seq=%d", session.id, messageRefKey(msg.Ref), msg.Ref.Seq)
			continue
		}
		response.Messages = append(response.Messages, secureControlMsgPayload{
			Ref:     mergeMessageRef(msg.Ref, entry.ref),
			Content: append([]byte(nil), entry.content...),
		})
	}
	c.recovery.mu.Unlock()

	if len(response.Messages) == 0 {
		return
	}
	if err := c.writeSecureControl(session, response); err != nil {
		log.Printf("secure recovery failed to send retransmit session=%s: %v", session.id, err)
	}
}

func (c *Conn) handleRetransmit(session *Session, peerID string, messages []secureControlMsgPayload) {
	if session == nil {
		return
	}

	var ready []readMsgItem
	c.recovery.mu.Lock()
	state := c.recovery.reorder[session.id]
	if state == nil {
		c.recovery.mu.Unlock()
		return
	}

	for _, msg := range messages {
		key := messageRefKey(msg.Ref)
		lost, ok := state.lost[key]
		if !ok && msg.Ref.ClientMsgID != "" {
			lost, ok = state.lost["client:"+msg.Ref.ClientMsgID]
		}
		if !ok && msg.Ref.ServerMsgID != "" {
			lost, ok = state.lost["server:"+msg.Ref.ServerMsgID]
		}
		if !ok && msg.Ref.Seq != 0 {
			lost, ok = state.lost[fmt.Sprintf("seq:%d", msg.Ref.Seq)]
		}
		if !ok {
			log.Printf("secure recovery retransmit has no waiting shell session=%s key=%s", session.id, key)
			continue
		}

		lost.msgData.SetContent(append([]byte(nil), msg.Content...))
		msgDataBytes, err := c.imParser.MsgDataToBytesReadBound(lost.msgData)
		if err != nil {
			log.Printf("secure recovery failed to rebuild lost message session=%s key=%s: %v", session.id, key, err)
			continue
		}

		delete(state.lost, messageRefKey(lost.ref))
		item := readMsgItem{
			sessionId: session.id,
			remoteId:  peerID,
			msgType:   lost.msgType,
			msg:       msgDataBytes,
		}
		if c.hasBlockingGapLocked(state, lost.ref) {
			state.pending[messageRefKey(lost.ref)] = pendingInboundMsg{
				ref:  lost.ref,
				item: item,
			}
			log.Printf("secure recovery restored but buffered message session=%s key=%s seq=%d behind lower gap", session.id, messageRefKey(lost.ref), lost.ref.Seq)
			continue
		}
		ready = append(ready, item)
		log.Printf("secure recovery restored lost message session=%s key=%s seq=%d", session.id, messageRefKey(lost.ref), lost.ref.Seq)
	}
	ready = append(ready, c.flushReadyPendingLocked(session.id, state)...)
	c.recovery.mu.Unlock()

	c.emitReadItems(ready)
}

func (c *Conn) writeSecureControl(session *Session, frame secureControlFrame) error {
	payload, err := json.Marshal(frame)
	if err != nil {
		return err
	}
	msgData := c.imParser.ConstructMsgData(c.hostId, session.remoteId, payload)
	return c.writeRecordLocked(recordTypeSecureControl, msgData, session)
}

func (c *Conn) emitReadItems(items []readMsgItem) {
	for _, item := range items {
		c.msgChan <- item
	}
}

func (c *Conn) reorderStateLocked(sessionId SessionID) *reorderState {
	state := c.recovery.reorder[sessionId]
	if state == nil {
		state = &reorderState{
			lost:    make(map[string]lostInboundMsg),
			pending: make(map[string]pendingInboundMsg),
		}
		c.recovery.reorder[sessionId] = state
	}
	return state
}

func (c *Conn) findCachedOutboundLocked(ref secureMessageRef) (cachedOutboundMsg, bool) {
	for _, key := range messageRefCandidateKeys(ref) {
		if entry, ok := c.recovery.sendCache[key]; ok {
			return entry, true
		}
	}
	return cachedOutboundMsg{}, false
}

func (c *Conn) messageRef(msgData im_parser.MsgData) secureMessageRef {
	ref := secureMessageRef{
		SendID: msgData.GetSendID(),
		RecvID: msgData.GetRecvID(),
	}
	if meta, ok := msgData.(messageMetaProvider); ok {
		ref.ClientMsgID = meta.GetClientMsgID()
		ref.ServerMsgID = meta.GetServerMsgID()
		ref.Seq = meta.GetSeq()
	}
	return ref
}

func messageRefKey(ref secureMessageRef) string {
	keys := messageRefCandidateKeys(ref)
	if len(keys) == 0 {
		return ""
	}
	return keys[0]
}

func messageRefCandidateKeys(ref secureMessageRef) []string {
	keys := make([]string, 0, 3)
	if ref.ClientMsgID != "" {
		keys = append(keys, "client:"+ref.ClientMsgID)
	}
	if ref.ServerMsgID != "" {
		keys = append(keys, "server:"+ref.ServerMsgID)
	}
	if ref.Seq != 0 {
		keys = append(keys, fmt.Sprintf("seq:%d", ref.Seq))
	}
	return keys
}

func mergeMessageRef(primary, fallback secureMessageRef) secureMessageRef {
	out := primary
	if out.SendID == "" {
		out.SendID = fallback.SendID
	}
	if out.RecvID == "" {
		out.RecvID = fallback.RecvID
	}
	if out.ClientMsgID == "" {
		out.ClientMsgID = fallback.ClientMsgID
	}
	if out.ServerMsgID == "" {
		out.ServerMsgID = fallback.ServerMsgID
	}
	if out.Seq == 0 {
		out.Seq = fallback.Seq
	}
	return out
}
