package awskms

import (
	"context"
	"fmt"
	"os"
	"strings"
	"sync"
	"time"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/kms"
	"github.com/aws/aws-sdk-go-v2/service/kms/types"
	"github.com/hashicorp/go-hclog"
	"github.com/hashicorp/hcl"
	"github.com/spiffe/spire/pkg/common/catalog"
	"github.com/spiffe/spire/pkg/server/plugin/keymanager"
	"github.com/spiffe/spire/proto/spire/common/plugin"
	"github.com/zeebo/errs"
	"google.golang.org/protobuf/proto"
)

const (
	pluginName       = "awskms"
	aliasPrefix      = "alias/"
	defaultKeyPrefix = "SPIRE_SERVER_KEY/"

	keyIDTag = "key_id"
	aliasTag = "alias"
)

var (
	kmsErr = errs.Class(pluginName)
)

func BuiltIn() catalog.Plugin {
	return builtin(New())
}

func builtin(p *Plugin) catalog.Plugin {
	return catalog.MakePlugin(pluginName, keymanager.PluginServer(p))
}

type keyEntry struct {
	KMSKeyID  string
	Alias     string
	PublicKey *keymanager.PublicKey
}

// Plugin is the main representation of this keymanager plugin
type Plugin struct {
	keymanager.UnsafeKeyManagerServer
	log       hclog.Logger
	mu        sync.RWMutex
	entries   map[string]keyEntry
	kmsClient kmsClient
	keyPrefix string

	hooks struct {
		newClient func(config *Config) (kmsClient, error)
		getenv    func(string) string
	}
}

// Config provides configuration context for the plugin
type Config struct {
	AccessKeyID     string `hcl:"access_key_id" json:"access_key_id"`
	SecretAccessKey string `hcl:"secret_access_key" json:"secret_access_key"`
	Region          string `hcl:"region" json:"region"`
	KeyPrefix       string `hcl:"key_prefix" json:"key_prefix"`
}

// New returns an instantiated plugin
func New() *Plugin {
	return newPlugin(newKMSClient)
}

func newPlugin(newClient func(config *Config) (kmsClient, error)) *Plugin {
	p := &Plugin{}
	p.hooks.newClient = newClient
	p.hooks.getenv = os.Getenv
	p.entries = make(map[string]keyEntry)
	return p
}

// SetLogger sets a logger
func (p *Plugin) SetLogger(log hclog.Logger) {
	p.log = log
}

// Configure sets up the plugin
func (p *Plugin) Configure(ctx context.Context, req *plugin.ConfigureRequest) (*plugin.ConfigureResponse, error) {
	config, err := p.validateConfig(req.Configuration)
	if err != nil {
		return nil, err
	}

	p.mu.Lock()
	defer p.mu.Unlock()

	p.keyPrefix = config.KeyPrefix
	p.kmsClient, err = p.hooks.newClient(config)
	if err != nil {
		return nil, kmsErr.New("failed to create KMS client: %v", err)
	}

	p.log.Debug("Fetching keys from KMS")
	var nextMarker *string
	for {
		nextMarker, err = p.fetchAliasesPage(ctx, nextMarker)
		if err != nil {
			return nil, err
		}
		if nextMarker == nil {
			break
		}
	}

	return &plugin.ConfigureResponse{}, nil
}

//GenerateKey creates a key in KMS. If a key already exists in the local storage, it is updated.
func (p *Plugin) GenerateKey(ctx context.Context, req *keymanager.GenerateKeyRequest) (*keymanager.GenerateKeyResponse, error) {
	if req.KeyId == "" {
		return nil, kmsErr.New("key id is required")
	}
	if req.KeyType == keymanager.KeyType_UNSPECIFIED_KEY_TYPE {
		return nil, kmsErr.New("key type is required")
	}

	p.mu.Lock()
	defer p.mu.Unlock()

	spireKeyID := req.KeyId
	newEntry, err := p.createKey(ctx, spireKeyID, req.KeyType)
	if err != nil {
		return nil, err
	}

	p.log.Debug("Created key")
	oldEntry, hasOldEntry := p.entry(spireKeyID)

	if !hasOldEntry {
		//create alias
		_, err = p.kmsClient.CreateAlias(ctx, &kms.CreateAliasInput{
			AliasName:   aws.String(newEntry.Alias),
			TargetKeyId: &newEntry.KMSKeyID,
		})
		if err != nil {
			return nil, kmsErr.New("failed to create alias: %v", err)
		}
	} else {
		//update alias
		_, err = p.kmsClient.UpdateAlias(ctx, &kms.UpdateAliasInput{
			AliasName:   aws.String(newEntry.Alias),
			TargetKeyId: &newEntry.KMSKeyID,
		})
		if err != nil {
			return nil, kmsErr.New("failed to update alias: %v", err)
		}

		go func() {
			//schedule delete
			ctx, cancel := context.WithTimeout(context.Background(), time.Second*30)
			defer cancel()
			_, err = p.kmsClient.ScheduleKeyDeletion(ctx, &kms.ScheduleKeyDeletionInput{
				KeyId:               &oldEntry.KMSKeyID,
				PendingWindowInDays: aws.Int32(7),
			})
			if err != nil {
				p.log.Error("It was not possible to schedule deletion for key", "error", err, keyIDTag, &oldEntry.KMSKeyID)
			}
		}()
	}

	err = p.setEntry(spireKeyID, newEntry)
	if err != nil {
		return nil, err
	}

	return &keymanager.GenerateKeyResponse{
		PublicKey: clonePublicKey(newEntry.PublicKey),
	}, nil
}

// SignData creates a digital signature for the data to be signed
func (p *Plugin) SignData(ctx context.Context, req *keymanager.SignDataRequest) (*keymanager.SignDataResponse, error) {
	if req.KeyId == "" {
		return nil, kmsErr.New("key id is required")
	}
	if req.SignerOpts == nil {
		return nil, kmsErr.New("signer opts is required")
	}

	p.mu.RLock()
	defer p.mu.RUnlock()

	keyEntry, hasKey := p.entry(req.KeyId)
	if !hasKey {
		return nil, kmsErr.New("no such key %q", req.KeyId)
	}

	signingAlgo, err := signingAlgorithmForKMS(keyEntry.PublicKey.Type, req.SignerOpts)
	if err != nil {
		return nil, err
	}

	signResp, err := p.kmsClient.Sign(ctx, &kms.SignInput{
		KeyId:            &keyEntry.Alias,
		Message:          req.Data,
		MessageType:      types.MessageTypeDigest,
		SigningAlgorithm: signingAlgo,
	})
	if err != nil {
		return nil, kmsErr.New("failed to sign: %v", err)
	}

	return &keymanager.SignDataResponse{Signature: signResp.Signature}, nil
}

// GetPublicKey returns the public key for a given key
func (p *Plugin) GetPublicKey(ctx context.Context, req *keymanager.GetPublicKeyRequest) (*keymanager.GetPublicKeyResponse, error) {
	if req.KeyId == "" {
		return nil, kmsErr.New("key id is required")
	}

	p.mu.RLock()
	defer p.mu.RUnlock()

	entry, ok := p.entry(req.KeyId)
	if !ok {
		return nil, kmsErr.New("no such key %q", req.KeyId)
	}

	return &keymanager.GetPublicKeyResponse{
		PublicKey: clonePublicKey(entry.PublicKey),
	}, nil
}

// GetPublicKeys return the publicKey for all the keys
func (p *Plugin) GetPublicKeys(context.Context, *keymanager.GetPublicKeysRequest) (*keymanager.GetPublicKeysResponse, error) {
	var keys []*keymanager.PublicKey
	p.mu.RLock()
	defer p.mu.RUnlock()
	for _, key := range p.entries {
		keys = append(keys, clonePublicKey(key.PublicKey))
	}

	return &keymanager.GetPublicKeysResponse{PublicKeys: keys}, nil
}

// GetPluginInfo returns information about this plugin
func (p *Plugin) GetPluginInfo(context.Context, *plugin.GetPluginInfoRequest) (*plugin.GetPluginInfoResponse, error) {
	return &plugin.GetPluginInfoResponse{}, nil
}

func (p *Plugin) setEntry(spireKeyID string, entry keyEntry) error {
	if spireKeyID == "" {
		return kmsErr.New("spireKeyID is required")
	}
	if entry.KMSKeyID == "" {
		return kmsErr.New("KMSKeyID is required")
	}
	if entry.Alias == "" {
		return kmsErr.New("Alias is required")
	}
	if entry.PublicKey == nil {
		return kmsErr.New("PublicKey is required")
	}
	if entry.PublicKey.Id == "" {
		return kmsErr.New("PublicKey.Id is required")
	}
	if entry.PublicKey.Type == keymanager.KeyType_UNSPECIFIED_KEY_TYPE {
		return kmsErr.New("PublicKey.Type is required")
	}
	if entry.PublicKey.PkixData == nil || len(entry.PublicKey.PkixData) == 0 {
		return kmsErr.New("PublicKey.PkixData is required")
	}

	p.entries[spireKeyID] = entry
	return nil
}

func (p *Plugin) entry(spireKeyID string) (keyEntry, bool) {
	value, hasKey := p.entries[spireKeyID]
	return value, hasKey
}

func (p *Plugin) createKey(ctx context.Context, spireKeyID string, keyType keymanager.KeyType) (keyEntry, error) {
	res := keyEntry{}
	description := p.descriptionFromSpireKeyID(spireKeyID)
	keySpec, err := keySpecFromKeyType(keyType)
	if err != nil {
		return res, err
	}

	createKeyInput := &kms.CreateKeyInput{
		Description:           aws.String(description),
		KeyUsage:              types.KeyUsageTypeSignVerify,
		CustomerMasterKeySpec: keySpec,
	}

	key, err := p.kmsClient.CreateKey(ctx, createKeyInput)
	if err != nil {
		return res, kmsErr.New("failed to create key: %v", err)
	}

	pub, err := p.kmsClient.GetPublicKey(ctx, &kms.GetPublicKeyInput{KeyId: key.KeyMetadata.KeyId})
	if err != nil {
		return res, kmsErr.New("failed to get public key: %v", err)
	}

	res = keyEntry{
		KMSKeyID: *pub.KeyId,
		Alias:    p.aliasFromSpireKeyID(spireKeyID),
		PublicKey: &keymanager.PublicKey{
			Id:       spireKeyID,
			Type:     keyType,
			PkixData: pub.PublicKey,
		},
	}

	return res, nil
}

func (p *Plugin) buildKeyEntry(ctx context.Context, alias *string, awsKeyID *string) (*keyEntry, error) {
	describeResp, err := p.kmsClient.DescribeKey(ctx, &kms.DescribeKeyInput{KeyId: alias})
	if err != nil {
		return nil, kmsErr.New("failed to describe key: %v", err)
	}

	if !describeResp.KeyMetadata.Enabled {
		return nil, nil
	}

	spireKeyID, err := p.spireKeyIDFromAlias(*alias)
	if err != nil {
		return nil, nil
	}

	keyType, err := keyTypeFromKeySpec(describeResp.KeyMetadata.CustomerMasterKeySpec)
	if err != nil {
		p.log.Debug("Skipped key", "reason", err)
		return nil, nil
	}

	getPublicKeyResp, err := p.kmsClient.GetPublicKey(ctx, &kms.GetPublicKeyInput{KeyId: alias})
	if err != nil {
		return nil, kmsErr.New("failed to get public key: %v", err)
	}

	return &keyEntry{
		KMSKeyID: *awsKeyID,
		Alias:    *alias,
		PublicKey: &keymanager.PublicKey{
			Id:       spireKeyID,
			Type:     keyType,
			PkixData: getPublicKeyResp.PublicKey,
		},
	}, err
}

func (p *Plugin) fetchAliasesPage(ctx context.Context, marker *string) (*string, error) {
	aliasesResp, err := p.kmsClient.ListAliases(ctx, &kms.ListAliasesInput{
		Marker: marker,
	})
	if err != nil {
		return nil, kmsErr.New("failed to fetch keys: %v", err)
	}

	p.log.Debug("Found aliases", "num_aliases", len(aliasesResp.Aliases))

	for _, alias := range aliasesResp.Aliases {
		if alias.AliasName == nil || alias.TargetKeyId == nil {
			continue
		}
		l := p.log.With(keyIDTag, *alias.TargetKeyId, aliasTag, *alias.AliasName)
		entry, err := p.buildKeyEntry(ctx, alias.AliasName, alias.TargetKeyId)
		switch {
		case err != nil:
			return nil, kmsErr.New("failed to process KMS key: %v", err)
		case entry != nil:
			err := p.setEntry(entry.PublicKey.Id, *entry)
			l.Debug("Loaded key")
			if err != nil {
				return nil, err
			}
		}
	}
	return aliasesResp.NextMarker, nil
}

func (p *Plugin) spireKeyIDFromAlias(alias string) (string, error) {
	tokens := strings.SplitAfter(alias, p.keyPrefix)
	if len(tokens) != 2 {
		return "", fmt.Errorf("alias does not contain the prefix %q", p.keyPrefix)
	}

	return tokens[1], nil
}

func (p *Plugin) aliasFromSpireKeyID(spireKeyID string) string {
	return fmt.Sprintf("%v%v%v", aliasPrefix, p.keyPrefix, spireKeyID)
}

func (p *Plugin) descriptionFromSpireKeyID(spireKeyID string) string {
	return fmt.Sprintf("%v%v", p.keyPrefix, spireKeyID)
}

// validateConfig returns an error if any configuration provided does not meet acceptable criteria
func (p *Plugin) validateConfig(c string) (*Config, error) {
	config := new(Config)

	if err := hcl.Decode(config, c); err != nil {
		return nil, kmsErr.New("unable to decode configuration: %v", err)
	}

	if config.Region == "" {
		return nil, kmsErr.New("configuration is missing a region")
	}

	if config.KeyPrefix == "" {
		config.KeyPrefix = defaultKeyPrefix
	}

	return config, nil
}

func signingAlgorithmForKMS(keyType keymanager.KeyType, signerOpts interface{}) (types.SigningAlgorithmSpec, error) {
	var (
		hashAlgo keymanager.HashAlgorithm
		isPSS    bool
	)

	switch opts := signerOpts.(type) {
	case *keymanager.SignDataRequest_HashAlgorithm:
		hashAlgo = opts.HashAlgorithm
		isPSS = false
	case *keymanager.SignDataRequest_PssOptions:
		if opts.PssOptions == nil {
			return "", kmsErr.New("PSS options are required")
		}
		hashAlgo = opts.PssOptions.HashAlgorithm
		isPSS = true
		// opts.PssOptions.SaltLength is handled by KMS. The salt length matches the bits of the hashing algorithm.
	default:
		return "", kmsErr.New("unsupported signer opts type %T", opts)
	}

	isRSA := keyType == keymanager.KeyType_RSA_2048 || keyType == keymanager.KeyType_RSA_4096

	switch {
	case hashAlgo == keymanager.HashAlgorithm_UNSPECIFIED_HASH_ALGORITHM:
		return "", kmsErr.New("hash algorithm is required")
	case keyType == keymanager.KeyType_EC_P256 && hashAlgo == keymanager.HashAlgorithm_SHA256:
		return types.SigningAlgorithmSpecEcdsaSha256, nil
	case keyType == keymanager.KeyType_EC_P384 && hashAlgo == keymanager.HashAlgorithm_SHA384:
		return types.SigningAlgorithmSpecEcdsaSha384, nil
	case isRSA && !isPSS && hashAlgo == keymanager.HashAlgorithm_SHA256:
		return types.SigningAlgorithmSpecRsassaPkcs1V15Sha256, nil
	case isRSA && !isPSS && hashAlgo == keymanager.HashAlgorithm_SHA384:
		return types.SigningAlgorithmSpecRsassaPkcs1V15Sha384, nil
	case isRSA && !isPSS && hashAlgo == keymanager.HashAlgorithm_SHA512:
		return types.SigningAlgorithmSpecRsassaPkcs1V15Sha512, nil
	case isRSA && isPSS && hashAlgo == keymanager.HashAlgorithm_SHA256:
		return types.SigningAlgorithmSpecRsassaPssSha256, nil
	case isRSA && isPSS && hashAlgo == keymanager.HashAlgorithm_SHA384:
		return types.SigningAlgorithmSpecRsassaPssSha384, nil
	case isRSA && isPSS && hashAlgo == keymanager.HashAlgorithm_SHA512:
		return types.SigningAlgorithmSpecRsassaPssSha512, nil
	default:
		return "", kmsErr.New("unsupported combination of keytype: %v and hashing algorithm: %v", keyType, hashAlgo)
	}
}

func keyTypeFromKeySpec(keySpec types.CustomerMasterKeySpec) (keymanager.KeyType, error) {
	switch keySpec {
	case types.CustomerMasterKeySpecRsa2048:
		return keymanager.KeyType_RSA_2048, nil
	case types.CustomerMasterKeySpecRsa4096:
		return keymanager.KeyType_RSA_4096, nil
	case types.CustomerMasterKeySpecEccNistP256:
		return keymanager.KeyType_EC_P256, nil
	case types.CustomerMasterKeySpecEccNistP384:
		return keymanager.KeyType_EC_P384, nil
	default:
		return keymanager.KeyType_UNSPECIFIED_KEY_TYPE, fmt.Errorf("unsupported key spec: %v", keySpec)
	}
}

func keySpecFromKeyType(keyType keymanager.KeyType) (types.CustomerMasterKeySpec, error) {
	switch keyType {
	case keymanager.KeyType_RSA_1024:
		return "", kmsErr.New("unsupported key type: KeyType_RSA_1024")
	case keymanager.KeyType_RSA_2048:
		return types.CustomerMasterKeySpecRsa2048, nil
	case keymanager.KeyType_RSA_4096:
		return types.CustomerMasterKeySpecRsa4096, nil
	case keymanager.KeyType_EC_P256:
		return types.CustomerMasterKeySpecEccNistP256, nil
	case keymanager.KeyType_EC_P384:
		return types.CustomerMasterKeySpecEccNistP384, nil
	default:
		return "", kmsErr.New("unknown key type")
	}
}

func clonePublicKey(publicKey *keymanager.PublicKey) *keymanager.PublicKey {
	return proto.Clone(publicKey).(*keymanager.PublicKey)
}
