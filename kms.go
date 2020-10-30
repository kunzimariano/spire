package kms

import (
	"context"
	"fmt"
	"strings"
	"sync"
	"time"

	"github.com/aws/aws-sdk-go/aws"
	"github.com/aws/aws-sdk-go/service/kms"
	"github.com/hashicorp/go-hclog"
	"github.com/hashicorp/hcl"
	"github.com/spiffe/spire/proto/spire/common/plugin"
	"github.com/spiffe/spire/proto/spire/server/keymanager"
	"github.com/zeebo/errs"
)

// Major TODOS:
// - timeouts
// - request input validations
// - error embellishment and wrapping
// - testing - Andres-GC

var (
	kmsErr = errs.Class("kms")
)

const (
	aliasPrefix = "alias/"
	keyPrefix   = "SPIRE_SERVER_KEY/"
)

type keyEntry struct {
	KMSKeyID     string
	CreationDate time.Time
	PublicKey    *keymanager.PublicKey
}

type Plugin struct {
	log       hclog.Logger
	mu        sync.RWMutex
	entries   map[string]*keyEntry
	kmsClient kmsClient
}

type Config struct {
	AccessKeyID     string `hcl:"access_key_id" json:"access_key_id"`
	SecretAccessKey string `hcl:"secret_access_key" json:"secret_access_key"`
	Region          string `hcl:"region" json:"region"`
}

func New() *Plugin {
	return &Plugin{
		entries: make(map[string]*keyEntry),
	}
}

func (p *Plugin) SetLogger(log hclog.Logger) {
	p.log = log
}

func (p *Plugin) Configure(ctx context.Context, req *plugin.ConfigureRequest) (*plugin.ConfigureResponse, error) {
	config, err := validateConfig(req.Configuration)
	if err != nil {
		return nil, err
	}

	p.kmsClient, err = newKMSClient(config)
	if err != nil {
		return nil, err
	}

	// TODO: pagination
	aliasesResp, err := p.kmsClient.ListAliasesWithContext(ctx, &kms.ListAliasesInput{})
	if err != nil {
		return nil, err
	}

	for _, alias := range aliasesResp.Aliases {
		err := p.processAWSKey(ctx, alias.AliasName, alias.TargetKeyId)
		if err != nil {
			p.log.With("KeyID", *alias.TargetKeyId).Warn("Failed to process kms key: %v", err)
		}
	}

	return &plugin.ConfigureResponse{}, nil
}

func (p *Plugin) GenerateKey(ctx context.Context, req *keymanager.GenerateKeyRequest) (*keymanager.GenerateKeyResponse, error) {
	spireKeyID := req.KeyId
	alias := getAlias(spireKeyID)

	newEntry, err := p.createKey(ctx, spireKeyID, req.KeyType)
	if err != nil {
		return nil, err
	}

	oldEntry, hasOldEntry := p.entry(spireKeyID)

	if !hasOldEntry {
		//create alias
		_, err = p.kmsClient.CreateAliasWithContext(ctx, &kms.CreateAliasInput{
			AliasName:   aws.String(alias),
			TargetKeyId: &newEntry.KMSKeyID,
		})
		if err != nil {
			return nil, err
		}

		//set map
		p.setEntry(spireKeyID, newEntry)

		return &keymanager.GenerateKeyResponse{PublicKey: newEntry.PublicKey}, nil
	}

	//update alias
	_, err = p.kmsClient.UpdateAliasWithContext(ctx, &kms.UpdateAliasInput{
		AliasName:   aws.String(alias),
		TargetKeyId: &newEntry.KMSKeyID,
	})
	if err != nil {
		return nil, err
	}

	//update map
	p.setEntry(spireKeyID, newEntry)

	//schedule delete
	_, err = p.kmsClient.ScheduleKeyDeletionWithContext(ctx, &kms.ScheduleKeyDeletionInput{
		KeyId:               &oldEntry.KMSKeyID,
		PendingWindowInDays: aws.Int64(7),
	})
	if err != nil {
		p.log.With("KeyID", &oldEntry.KMSKeyID).Error("It was not possible to schedule deletion for key: %v", err)
	}

	return &keymanager.GenerateKeyResponse{PublicKey: newEntry.PublicKey}, nil

}

func (p *Plugin) SignData(ctx context.Context, req *keymanager.SignDataRequest) (*keymanager.SignDataResponse, error) {
	keyEntry, hasKey := p.entry(req.KeyId)
	if !hasKey {
		return nil, kmsErr.New("unable to find KeyId: %v", req.KeyId)
	}

	signingAlgo, err := signingAlgorithmForKMS(keyEntry.PublicKey.Type, req.SignerOpts)
	if err != nil {
		return nil, err
	}

	signResp, err := p.kmsClient.SignWithContext(ctx, &kms.SignInput{
		KeyId:            &keyEntry.KMSKeyID, //TODO: use alias instead
		Message:          req.Data,
		MessageType:      aws.String(kms.MessageTypeDigest),
		SigningAlgorithm: aws.String(signingAlgo),
	})
	if err != nil {
		return nil, err
	}

	return &keymanager.SignDataResponse{Signature: signResp.Signature}, nil
}

func (p *Plugin) GetPublicKey(ctx context.Context, req *keymanager.GetPublicKeyRequest) (*keymanager.GetPublicKeyResponse, error) {
	if req.KeyId == "" {
		return nil, kmsErr.New("KeyId is required")
	}

	resp := new(keymanager.GetPublicKeyResponse)

	e, ok := p.entry(req.KeyId)
	if !ok {
		//TODO: isn't it better to return error?
		return resp, nil
	}

	//TODO: clone it
	resp.PublicKey = e.PublicKey
	return resp, nil
}

func (p *Plugin) GetPublicKeys(context.Context, *keymanager.GetPublicKeysRequest) (*keymanager.GetPublicKeysResponse, error) {
	keys := p.publicKeys()
	return &keymanager.GetPublicKeysResponse{PublicKeys: keys}, nil
}

func (p *Plugin) GetPluginInfo(context.Context, *plugin.GetPluginInfoRequest) (*plugin.GetPluginInfoResponse, error) {
	return &plugin.GetPluginInfoResponse{}, nil
}

func (p *Plugin) setEntry(spireKeyID string, newEntry *keyEntry) {
	//TODO: validate new entry
	p.mu.Lock()
	defer p.mu.Unlock()
	p.entries[spireKeyID] = newEntry
}

func (p *Plugin) entry(spireKeyID string) (*keyEntry, bool) {
	p.mu.Lock()
	defer p.mu.Unlock()
	value, hasKey := p.entries[spireKeyID]
	return value, hasKey
}

func (p *Plugin) createKey(ctx context.Context, spireKeyID string, keyType keymanager.KeyType) (*keyEntry, error) {
	description := getDescription(spireKeyID)
	keySpec, err := keySpecFromKeyType(keyType)
	if err != nil {
		return nil, err
	}

	createKeyInput := &kms.CreateKeyInput{
		Description:           aws.String(description),
		KeyUsage:              aws.String(kms.KeyUsageTypeSignVerify),
		CustomerMasterKeySpec: aws.String(keySpec),
	}

	key, err := p.kmsClient.CreateKeyWithContext(ctx, createKeyInput)
	if err != nil {
		return nil, err
	}

	pub, err := p.kmsClient.GetPublicKeyWithContext(ctx, &kms.GetPublicKeyInput{KeyId: key.KeyMetadata.KeyId})
	if err != nil {
		return nil, err
	}

	newEntry := &keyEntry{
		KMSKeyID:     *pub.KeyId,
		CreationDate: *key.KeyMetadata.CreationDate,
		PublicKey: &keymanager.PublicKey{
			Id:       spireKeyID,
			Type:     keyType,
			PkixData: pub.PublicKey,
		},
	}

	return newEntry, nil
}

func (p *Plugin) publicKeys() []*keymanager.PublicKey {
	var keys []*keymanager.PublicKey

	p.mu.Lock()
	defer p.mu.Unlock()

	for _, key := range p.entries {
		keys = append(keys, key.PublicKey)
	}
	return keys
}

func (p *Plugin) processAWSKey(ctx context.Context, alias *string, awsKeyID *string) error {
	describeResp, err := p.kmsClient.DescribeKeyWithContext(ctx, &kms.DescribeKeyInput{KeyId: awsKeyID})
	if err != nil {
		return err
	}

	if *describeResp.KeyMetadata.Enabled == false {
		return nil
	}

	spireKeyID, err := spireKeyIDFromAlias(*alias)
	if err != nil {
		return err
	}

	keyType, err := keyTypeFromKeySpec(*describeResp.KeyMetadata.CustomerMasterKeySpec)
	if err != nil {
		return err
	}

	getPublicKeyResp, err := p.kmsClient.GetPublicKeyWithContext(ctx, &kms.GetPublicKeyInput{KeyId: awsKeyID})
	if err != nil {
		return err
	}

	newEntry := &keyEntry{
		KMSKeyID:     *awsKeyID,
		CreationDate: *describeResp.KeyMetadata.CreationDate,
		PublicKey: &keymanager.PublicKey{
			Id:       spireKeyID,
			Type:     keyType,
			PkixData: getPublicKeyResp.PublicKey,
		},
	}

	// Just being defensive here. It shouldn't be necessary given alias can only be associated with one key
	oldEntry, keyExists := p.entries[spireKeyID]
	switch {
	case keyExists && newEntry.CreationDate.Unix() < oldEntry.CreationDate.Unix():
		p.log.Warn("An newer key already exists. Skipping keyID: %v", newEntry.KMSKeyID)
		return nil
	case keyExists && oldEntry.CreationDate.Unix() <= newEntry.CreationDate.Unix():
		p.log.Warn("An older key was found. Overwriting keyID: %v", oldEntry.KMSKeyID)
		p.setEntry(spireKeyID, newEntry)
		return nil
	default:
		p.setEntry(spireKeyID, newEntry)

	}

	return nil
}

func spireKeyIDFromAlias(alias string) (string, error) {
	tokens := strings.SplitAfter(alias, keyPrefix)
	if len(tokens) != 2 {
		return "", kmsErr.New("alias does not contain SPIRE prefix")
	}

	return tokens[1], nil
}

func getAlias(spireKeyID string) string {
	return fmt.Sprintf("%v%v%v", aliasPrefix, keyPrefix, spireKeyID)
}

func getDescription(spireKeyID string) string {
	return fmt.Sprintf("%v%v", keyPrefix, spireKeyID)
}

// validateConfig returns an error if any configuration provided does not meet acceptable criteria
func validateConfig(c string) (*Config, error) {
	config := new(Config)

	if err := hcl.Decode(config, c); err != nil {
		return nil, kmsErr.New("unable to decode configuration: %v", err)
	}

	if config.AccessKeyID == "" {
		return nil, kmsErr.New("configuration is missing an access key id")
	}

	if config.SecretAccessKey == "" {
		return nil, kmsErr.New("configuration is missing a secret access key")
	}

	if config.Region == "" {
		return nil, kmsErr.New("configuration is missing a region")
	}

	return config, nil
}

func signingAlgorithmForKMS(keyType keymanager.KeyType, signerOpts interface{}) (string, error) {
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
			return "", kmsErr.New("PSS options are nil")
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
		return kms.SigningAlgorithmSpecEcdsaSha256, nil
	case keyType == keymanager.KeyType_EC_P384 && hashAlgo == keymanager.HashAlgorithm_SHA384:
		return kms.SigningAlgorithmSpecEcdsaSha384, nil
	case isRSA && !isPSS && hashAlgo == keymanager.HashAlgorithm_SHA256:
		return kms.SigningAlgorithmSpecRsassaPkcs1V15Sha256, nil
	case isRSA && !isPSS && hashAlgo == keymanager.HashAlgorithm_SHA384:
		return kms.SigningAlgorithmSpecRsassaPkcs1V15Sha384, nil
	case isRSA && !isPSS && hashAlgo == keymanager.HashAlgorithm_SHA512:
		return kms.SigningAlgorithmSpecRsassaPkcs1V15Sha512, nil
	case isRSA && isPSS && hashAlgo == keymanager.HashAlgorithm_SHA256:
		return kms.SigningAlgorithmSpecRsassaPssSha256, nil
	case isRSA && isPSS && hashAlgo == keymanager.HashAlgorithm_SHA384:
		return kms.SigningAlgorithmSpecRsassaPssSha384, nil
	case isRSA && isPSS && hashAlgo == keymanager.HashAlgorithm_SHA512:
		return kms.SigningAlgorithmSpecRsassaPssSha512, nil
	default:
		return "", kmsErr.New("unsupported combo of keytype: %v and hashing algo: %v", keyType, hashAlgo)
	}
}

func keyTypeFromKeySpec(keySpec string) (keymanager.KeyType, error) {
	switch keySpec {
	case kms.CustomerMasterKeySpecRsa2048:
		return keymanager.KeyType_RSA_2048, nil
	case kms.CustomerMasterKeySpecRsa4096:
		return keymanager.KeyType_RSA_4096, nil
	case kms.CustomerMasterKeySpecEccNistP256:
		return keymanager.KeyType_EC_P256, nil
	case kms.CustomerMasterKeySpecEccNistP384:
		return keymanager.KeyType_EC_P384, nil
	default:
		return keymanager.KeyType_UNSPECIFIED_KEY_TYPE, kmsErr.New("unsupported keyspec: %v", keySpec)
	}

}

func keySpecFromKeyType(keyType keymanager.KeyType) (string, error) {
	switch keyType {
	case keymanager.KeyType_RSA_1024:
		return "", kmsErr.New("unsupported")
	case keymanager.KeyType_RSA_2048:
		return kms.CustomerMasterKeySpecRsa2048, nil
	case keymanager.KeyType_RSA_4096:
		return kms.CustomerMasterKeySpecRsa4096, nil
	case keymanager.KeyType_EC_P256:
		return kms.CustomerMasterKeySpecEccNistP256, nil
	case keymanager.KeyType_EC_P384:
		return kms.CustomerMasterKeySpecEccNistP384, nil
	default:
		return "", kmsErr.New("unknown and unsupported")
	}
}
