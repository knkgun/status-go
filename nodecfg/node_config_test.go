package nodecfg

import (
	"crypto/rand"
	"encoding/json"
	"fmt"
	"io/ioutil"
	"math"
	"math/big"
	"os"
	"sort"
	"testing"
	"time"

	"github.com/stretchr/testify/require"

	"github.com/ethereum/go-ethereum/p2p/discv5"

	"github.com/status-im/status-go/appdatabase"
	"github.com/status-im/status-go/eth-node/crypto"
	"github.com/status-im/status-go/eth-node/types"
	"github.com/status-im/status-go/multiaccounts/accounts"
	"github.com/status-im/status-go/params"
	"github.com/status-im/status-go/protocol/pushnotificationserver"
	"github.com/status-im/status-go/sqlite"
)

func setupTestDB(t *testing.T) (*accounts.Database, func()) {
	tmpfile, err := ioutil.TempFile("", "settings-tests-")
	require.NoError(t, err)
	db, err := appdatabase.InitializeDB(tmpfile.Name(), "settings-tests")
	require.NoError(t, err)

	return accounts.NewDB(db), func() {
		require.NoError(t, db.Close())
		require.NoError(t, os.Remove(tmpfile.Name()))
	}
}

var (
	config = params.NodeConfig{
		NetworkID: 10,
		DataDir:   "test",
	}

	networks = json.RawMessage("{}")
	settings = accounts.Settings{
		Address:                   types.HexToAddress("0xdC540f3745Ff2964AFC1171a5A0DD726d1F6B472"),
		AnonMetricsShouldSend:     false,
		CurrentNetwork:            "mainnet_rpc",
		DappsAddress:              types.HexToAddress("0xD1300f99fDF7346986CbC766903245087394ecd0"),
		InstallationID:            "d3efcff6-cffa-560e-a547-21d3858cbc51",
		KeyUID:                    "0x4e8129f3edfc004875be17bf468a784098a9f69b53c095be1f52deff286935ab",
		BackupEnabled:             true,
		LatestDerivedPath:         0,
		Name:                      "Jittery Cornflowerblue Kingbird",
		Networks:                  &networks,
		PhotoPath:                 "data:image/png;base64,iVBORw0KGgoAAAANSUhEUgAAADIAAAAyCAIAAACRXR/mAAAAjklEQVR4nOzXwQmFMBAAUZXUYh32ZB32ZB02sxYQQSZGsod55/91WFgSS0RM+SyjA56ZRZhFmEWYRRT6h+M6G16zrxv6fdJpmUWYRbxsYr13dKfanpN0WmYRZhGzXz6AWYRZRIfbaX26fT9Jk07LLMIsosPt9I/dTDotswizCG+nhFmEWYRZhFnEHQAA///z1CFkYamgfQAAAABJRU5ErkJggg==",
		PreviewPrivacy:            false,
		PublicKey:                 "0x04211fe0f69772ecf7eb0b5bfc7678672508a9fb01f2d699096f0d59ef7fe1a0cb1e648a80190db1c0f5f088872444d846f2956d0bd84069f3f9f69335af852ac0",
		SigningPhrase:             "yurt joey vibe",
		SendPushNotifications:     true,
		ProfilePicturesShowTo:     accounts.ProfilePicturesShowToContactsOnly,
		ProfilePicturesVisibility: accounts.ProfilePicturesVisibilityContactsOnly,
		DefaultSyncPeriod:         86400,
		UseMailservers:            true,
		LinkPreviewRequestEnabled: true,
		SendStatusUpdates:         true,
		WalletRootAddress:         types.HexToAddress("0x3B591fd819F86D0A6a2EF2Bcb94f77807a7De1a6")}
)

func TestGetNodeConfig(t *testing.T) {
	db, stop := setupTestDB(t)
	defer stop()

	nodeConfig := randomNodeConfig()
	require.NoError(t, db.CreateSettings(settings, *nodeConfig))

	dbNodeConfig, err := GetNodeConfig(db.DB())
	require.NoError(t, err)
	require.Equal(t, nodeConfig, dbNodeConfig)
}

func TestSaveNodeConfig(t *testing.T) {
	db, stop := setupTestDB(t)
	defer stop()

	require.NoError(t, db.CreateSettings(settings, *randomNodeConfig()))

	newNodeConfig := randomNodeConfig()
	require.NoError(t, SaveNodeConfig(db.DB(), newNodeConfig))

	dbNodeConfig, err := GetNodeConfig(db.DB())
	require.NoError(t, err)
	require.Equal(t, *newNodeConfig, *dbNodeConfig)
}

func TestMigrateNodeConfig(t *testing.T) {
	db, stop := setupTestDB(t)
	defer stop()

	nodeConfig := randomNodeConfig()
	require.NoError(t, db.CreateSettings(settings, *nodeConfig))

	value := &sqlite.JSONBlob{Data: nodeConfig}
	update, err := db.DB().Prepare("UPDATE settings SET node_config = ? WHERE synthetic_id = 'id'")
	require.NoError(t, err)
	_, err = update.Exec(value)
	require.NoError(t, err)

	// GetNodeConfig should migrate the settings to a table
	dbNodeConfig, err := GetNodeConfig(db.DB())
	require.NoError(t, err)
	require.Equal(t, nodeConfig, dbNodeConfig)

	// node_config column should be empty
	var result string
	err = db.DB().QueryRow("SELECT COALESCE(NULL, 'empty')").Scan(&result)
	require.NoError(t, err)
	require.Equal(t, "empty", result)
}

func randomString() string {
	b := make([]byte, 10)
	_, _ = rand.Read(b)
	return fmt.Sprintf("%x", b)[:10]
}

func randomBool() bool {
	return randomInt(2) == 1
}

func randomInt(max int64) int {
	r, _ := rand.Int(rand.Reader, big.NewInt(max))
	return int(r.Int64())
}

func randomFloat(max int64) float64 {
	r, _ := rand.Int(rand.Reader, big.NewInt(max))
	return float64(r.Int64()) / (1 << 63)
}

func randomStringSlice() []string {
	m := randomInt(7)
	var result []string
	for i := 0; i < m; i++ {
		result = append(result, randomString())
	}
	sort.Strings(result)
	return result
}

func randomTopicSlice() []discv5.Topic {
	randomValues := randomStringSlice()
	var result []discv5.Topic
	for _, v := range randomValues {
		result = append(result, discv5.Topic(v))
	}
	return result
}

func randomTopicLimits() map[discv5.Topic]params.Limits {
	result := make(map[discv5.Topic]params.Limits)
	m := randomInt(7) + 1
	for i := 0; i < m; i++ {
		result[discv5.Topic(fmt.Sprint(i))] = params.Limits{Min: randomInt(2), Max: randomInt(10)}
	}
	return result
}

func randomCustomNodes() map[string]string {
	result := make(map[string]string)
	m := randomInt(7)
	for i := 0; i < m; i++ {
		result[randomString()] = randomString()
	}
	return result
}

func randomNetworkSlice() []params.Network {
	m := randomInt(7) + 1
	var result []params.Network
	for i := 0; i < m; i++ {
		n := params.Network{
			ChainID:                uint64(i),
			ChainName:              randomString(),
			RPCURL:                 randomString(),
			BlockExplorerURL:       randomString(),
			IconURL:                randomString(),
			NativeCurrencyName:     randomString(),
			NativeCurrencySymbol:   randomString(),
			NativeCurrencyDecimals: uint64(int64(randomInt(math.MaxInt64))),
			IsTest:                 randomBool(),
			Layer:                  uint64(int64(randomInt(math.MaxInt64))),
			Enabled:                randomBool(),
		}
		result = append(result, n)
	}
	return result
}

func randomNodeConfig() *params.NodeConfig {
	privK, _ := crypto.GenerateKey()

	return &params.NodeConfig{
		NetworkID:                 uint64(int64(randomInt(math.MaxInt64))),
		DataDir:                   randomString(),
		KeyStoreDir:               randomString(),
		NodeKey:                   randomString(),
		NoDiscovery:               randomBool(),
		Rendezvous:                randomBool(),
		ListenAddr:                randomString(),
		AdvertiseAddr:             randomString(),
		Name:                      randomString(),
		Version:                   randomString(),
		APIModules:                randomString(),
		TLSEnabled:                randomBool(),
		MaxPeers:                  randomInt(math.MaxInt64),
		MaxPendingPeers:           randomInt(math.MaxInt64),
		EnableStatusService:       randomBool(),
		EnableNTPSync:             randomBool(),
		BridgeConfig:              params.BridgeConfig{Enabled: randomBool()},
		WalletConfig:              params.WalletConfig{Enabled: randomBool()},
		LocalNotificationsConfig:  params.LocalNotificationsConfig{Enabled: randomBool()},
		BrowsersConfig:            params.BrowsersConfig{Enabled: randomBool()},
		ENSConfig:                 params.ENSConfig{Enabled: randomBool()},
		PermissionsConfig:         params.PermissionsConfig{Enabled: randomBool()},
		MailserversConfig:         params.MailserversConfig{Enabled: randomBool()},
		Web3ProviderConfig:        params.Web3ProviderConfig{Enabled: randomBool()},
		SwarmConfig:               params.SwarmConfig{Enabled: randomBool()},
		MailServerRegistryAddress: randomString(),
		HTTPEnabled:               randomBool(),
		HTTPHost:                  randomString(),
		HTTPPort:                  randomInt(math.MaxInt64),
		HTTPVirtualHosts:          randomStringSlice(),
		HTTPCors:                  randomStringSlice(),
		IPCEnabled:                randomBool(),
		IPCFile:                   randomString(),
		LogEnabled:                randomBool(),
		LogMobileSystem:           randomBool(),
		LogDir:                    randomString(),
		LogFile:                   randomString(),
		LogLevel:                  randomString(),
		LogMaxBackups:             randomInt(math.MaxInt64),
		LogMaxSize:                randomInt(math.MaxInt64),
		LogCompressRotated:        randomBool(),
		LogToStderr:               randomBool(),
		UpstreamConfig:            params.UpstreamRPCConfig{Enabled: randomBool(), URL: randomString()},
		Networks:                  randomNetworkSlice(),
		ClusterConfig: params.ClusterConfig{
			Enabled:     randomBool(),
			Fleet:       randomString(),
			StaticNodes: randomStringSlice(),
			BootNodes:   randomStringSlice(),
		},
		LightEthConfig: params.LightEthConfig{
			Enabled:            randomBool(),
			DatabaseCache:      randomInt(math.MaxInt64),
			TrustedNodes:       randomStringSlice(),
			MinTrustedFraction: randomInt(math.MaxInt64),
		},
		RegisterTopics: randomTopicSlice(),
		RequireTopics:  randomTopicLimits(),
		PushNotificationServerConfig: pushnotificationserver.Config{
			Enabled:   randomBool(),
			GorushURL: randomString(),
			Identity:  privK,
		},
		ShhextConfig: params.ShhextConfig{
			PFSEnabled:                   randomBool(),
			BackupDisabledDataDir:        randomString(),
			InstallationID:               randomString(),
			MailServerConfirmations:      randomBool(),
			EnableConnectionManager:      randomBool(),
			EnableLastUsedMonitor:        randomBool(),
			ConnectionTarget:             randomInt(math.MaxInt64),
			RequestsDelay:                time.Duration(randomInt(math.MaxInt64)),
			MaxServerFailures:            randomInt(math.MaxInt64),
			MaxMessageDeliveryAttempts:   randomInt(math.MaxInt64),
			WhisperCacheDir:              randomString(),
			DisableGenericDiscoveryTopic: randomBool(),
			SendV1Messages:               randomBool(),
			DataSyncEnabled:              randomBool(),
			VerifyTransactionURL:         randomString(),
			VerifyENSURL:                 randomString(),
			VerifyENSContractAddress:     randomString(),
			VerifyTransactionChainID:     int64(randomInt(math.MaxInt64)),
			AnonMetricsSendID:            randomString(),
			AnonMetricsServerEnabled:     randomBool(),
			AnonMetricsServerPostgresURI: randomString(),
			BandwidthStatsEnabled:        randomBool(),
		},
		WakuV2Config: params.WakuV2Config{
			Enabled:             randomBool(),
			Host:                randomString(),
			Port:                randomInt(math.MaxInt64),
			KeepAliveInterval:   randomInt(math.MaxInt64),
			LightClient:         randomBool(),
			FullNode:            randomBool(),
			DiscoveryLimit:      randomInt(math.MaxInt64),
			PersistPeers:        randomBool(),
			DataDir:             randomString(),
			MaxMessageSize:      uint32(randomInt(math.MaxInt64)),
			EnableConfirmations: randomBool(),
			CustomNodes:         randomCustomNodes(),
			PeerExchange:        randomBool(),
			EnableDiscV5:        randomBool(),
			UDPPort:             randomInt(math.MaxInt64),
			AutoUpdate:          randomBool(),
		},
		WakuConfig: params.WakuConfig{
			Enabled:                 randomBool(),
			LightClient:             randomBool(),
			FullNode:                randomBool(),
			EnableMailServer:        randomBool(),
			DataDir:                 randomString(),
			MinimumPoW:              randomFloat(math.MaxInt64),
			MailServerPassword:      randomString(),
			MailServerRateLimit:     randomInt(math.MaxInt64),
			MailServerDataRetention: randomInt(math.MaxInt64),
			TTL:                     randomInt(math.MaxInt64),
			MaxMessageSize:          uint32(randomInt(math.MaxInt64)),
			DatabaseConfig: params.DatabaseConfig{
				PGConfig: params.PGConfig{
					Enabled: randomBool(),
					URI:     randomString(),
				},
			},
			EnableRateLimiter:      randomBool(),
			PacketRateLimitIP:      int64(randomInt(math.MaxInt64)),
			PacketRateLimitPeerID:  int64(randomInt(math.MaxInt64)),
			BytesRateLimitIP:       int64(randomInt(math.MaxInt64)),
			BytesRateLimitPeerID:   int64(randomInt(math.MaxInt64)),
			RateLimitTolerance:     int64(randomInt(math.MaxInt64)),
			BloomFilterMode:        randomBool(),
			SoftBlacklistedPeerIDs: randomStringSlice(),
			EnableConfirmations:    randomBool(),
		},
	}
}
