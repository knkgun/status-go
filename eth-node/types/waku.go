package types

import (
	"crypto/ecdsa"
	"time"

	"github.com/ethereum/go-ethereum/common"
)

// Whisper represents a dark communication interface through the Ethereum
// network, using its very own P2P communication layer.
type Waku interface {
	PublicWakuAPI() PublicWakuAPI

	// Waku protocol version
	Version() uint

	// PeerCount
	PeerCount() int

	Peers() map[string][]string

	StartDiscV5() error

	StopDiscV5() error

	AddStorePeer(address string) (string, error)

	AddRelayPeer(address string) (string, error)

	DialPeer(address string) error

	DialPeerByID(peerID string) error

	DropPeer(peerID string) error

	// MinPow returns the PoW value required by this node.
	MinPow() float64
	// BloomFilter returns the aggregated bloom filter for all the topics of interest.
	// The nodes are required to send only messages that match the advertised bloom filter.
	// If a message does not match the bloom, it will tantamount to spam, and the peer will
	// be disconnected.
	BloomFilter() []byte
	// SetTimeSource assigns a particular source of time to a whisper object.
	SetTimeSource(timesource func() time.Time)
	// GetCurrentTime returns current time.
	GetCurrentTime() time.Time

	// GetPrivateKey retrieves the private key of the specified identity.
	GetPrivateKey(id string) (*ecdsa.PrivateKey, error)

	SubscribeEnvelopeEvents(events chan<- EnvelopeEvent) Subscription

	// AddKeyPair imports a asymmetric private key and returns a deterministic identifier.
	AddKeyPair(key *ecdsa.PrivateKey) (string, error)
	// DeleteKeyPair deletes the key with the specified ID if it exists.
	DeleteKeyPair(keyID string) bool
	AddSymKeyDirect(key []byte) (string, error)
	AddSymKeyFromPassword(password string) (string, error)
	DeleteSymKey(id string) bool
	GetSymKey(id string) ([]byte, error)
	MaxMessageSize() uint32

	GetStats() StatsSummary

	Subscribe(opts *SubscriptionOptions) (string, error)
	GetFilter(id string) Filter
	Unsubscribe(id string) error
	UnsubscribeMany(ids []string) error

	// RequestHistoricMessages sends a message with p2pRequestCode to a specific peer,
	// which is known to implement MailServer interface, and is supposed to process this
	// request and respond with a number of peer-to-peer messages (possibly expired),
	// which are not supposed to be forwarded any further.
	// The whisper protocol is agnostic of the format and contents of envelope.
	// A timeout of 0 never expires.
	RequestHistoricMessagesWithTimeout(peerID []byte, envelope Envelope, timeout time.Duration) error
	// SendMessagesRequest sends a MessagesRequest. This is an equivalent to RequestHistoricMessages
	// in terms of the functionality.
	SendMessagesRequest(peerID []byte, request MessagesRequest) error

	// RequestStoreMessages uses the WAKU2-STORE protocol to request historic messages
	RequestStoreMessages(peerID []byte, request MessagesRequest) (*StoreRequestCursor, error)

	// ProcessingP2PMessages indicates whether there are in-flight p2p messages
	ProcessingP2PMessages() bool

	// MarkP2PMessageAsProcessed tells the waku layer that a P2P message has been processed
	MarkP2PMessageAsProcessed(common.Hash)
}
