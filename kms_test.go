package kms

import (
	"context"
	"errors"
	"fmt"
	"testing"
	"time"

	"github.com/aws/aws-sdk-go/aws"
	"github.com/aws/aws-sdk-go/service/kms"
	"github.com/hashicorp/go-hclog"
	"github.com/spiffe/spire/pkg/server/plugin/keymanager"
	"github.com/spiffe/spire/proto/spire/common/plugin"
	"github.com/stretchr/testify/suite"
)

const (
	// Defaults used for testing
	validAccessKeyID     = "AKIAIOSFODNN7EXAMPLE"
	validSecretAccessKey = "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY"
	validRegion          = "us-west-2"
	kmsKeyID             = "kmsKeyID"
	spireKeyID           = "spireKeyID"
)

var (
	ctx           = context.Background()
	spireKeyAlias = fmt.Sprintf("%s%s", keyPrefix, spireKeyID)
)

func TestKeyManager(t *testing.T) {
	suite.Run(t, new(KmsPluginSuite))
}

type KmsPluginSuite struct {
	// spiretest.Suite
	suite.Suite

	kmsClientFake *kmsClientFake
	rawPlugin     *Plugin
	// The plugin under test
	plugin keymanager.Plugin
}

func (ps *KmsPluginSuite) SetupTest() {

	ps.kmsClientFake = &kmsClientFake{t: ps.T()}

	// Setup plugin
	plugin := newPlugin(func(c *Config) (kmsClient, error) {
		return ps.kmsClientFake, nil
	})

	plugin.SetLogger(hclog.NewNullLogger())
	plugin.kmsClient = ps.kmsClientFake
	ps.rawPlugin = plugin
	ps.plugin = plugin
}

func (ps *KmsPluginSuite) Test_Configure() {
	ps.configurePluginWithExistingKeys()

	// Should return Key metadata
	ps.setupDescribeKey(kms.CustomerMasterKeySpecRsa4096, nil)

	// Should return Key publicKey
	ps.setupGetPublicKey(nil)

	_, err := ps.plugin.Configure(ctx, ps.defaultConfigureRequest())

	ps.Require().NoError(err)
	ps.Require().Equal(1, len(ps.rawPlugin.entries))
	ps.Require().Equal(ps.rawPlugin.entries[spireKeyID].KMSKeyID, kmsKeyID)
	ps.Require().Equal(ps.rawPlugin.entries[spireKeyID].PublicKey.Type, keymanager.KeyType_RSA_4096)
	ps.Require().Equal(ps.rawPlugin.entries[spireKeyID].PublicKey.Id, spireKeyID)
}

func (ps *KmsPluginSuite) Test_Configure_Invalid_Config() {
	missingAccessKeyConfig := `{
		"secret_access_key":"secret_access_key",
		"region":"region"
	}`
	_, err := ps.plugin.Configure(ctx, ps.configureRequest(missingAccessKeyConfig))
	ps.Require().Error(err)

	missingSecretAccessKeyConfig := `{
		"access_key_id":"access_key",
		"region":"region"
	}`
	_, err = ps.plugin.Configure(ctx, ps.configureRequest(missingSecretAccessKeyConfig))
	ps.Assert().Error(err)

	missingRegionConfig := `{
		"access_key_id":"access_key",
		"secret_access_key":"secret_access_key",
	}`
	_, err = ps.plugin.Configure(ctx, ps.configureRequest(missingRegionConfig))

	ps.Assert().Error(err)
}

func (ps *KmsPluginSuite) Test_Configure_DecodeError() {
	malformedConfig := `{
		badjson
	}`
	_, err := ps.plugin.Configure(ctx, ps.configureRequest(malformedConfig))
	ps.Require().Error(err)
}

func (ps *KmsPluginSuite) Test_Configure_ListKeysError() {
	errMsg := "List Aliases error"
	kmsErr := fmt.Sprintf("kms: failed to fetch keys: %s", errMsg)

	// Should return error
	ps.setupListAliases(true, errors.New(errMsg))

	_, err := ps.plugin.Configure(ctx, ps.defaultConfigureRequest())

	ps.Require().Error(err)
	ps.Require().Equal(err.Error(), kmsErr)
}

func (ps *KmsPluginSuite) Test_Configure_DescribeKeyError() {
	errMsg := "Describe Key error"
	kmsErr := fmt.Sprintf("kms: failed to process KMS key: kms: failed to describe key: %s", errMsg)

	// Should return a list of Key aliases
	ps.setupListAliases(true, nil)

	// Should return error
	ps.setupDescribeKey(kms.CustomerMasterKeySpecRsa4096, errors.New(errMsg))

	_, err := ps.plugin.Configure(ctx, ps.defaultConfigureRequest())
	ps.Require().Error(err)
	ps.Require().Equal(err.Error(), kmsErr)
}

func (ps *KmsPluginSuite) Test_Configure_UnsupportedKeySpecError() {
	// Should return a list of Key aliases
	ps.setupListAliases(true, nil)

	// Response should include an unsupported KeySpec
	ps.setupDescribeKey("Unsupported keySpec", nil)

	// An error processing keySpec only prevents the key to be included into the internal keys storage
	_, err := ps.plugin.Configure(ctx, ps.defaultConfigureRequest())

	ps.Require().NoError(err)
	ps.Require().Equal(0, len(ps.rawPlugin.entries))
}

func (ps *KmsPluginSuite) Test_Configure_GetPublicKeyError() {
	errMsg := "Get Public Key error"
	kmsErr := fmt.Sprintf("kms: failed to process KMS key: kms: failed to get public key: %s", errMsg)

	// Should return a list of Key aliases
	ps.setupListAliases(true, nil)

	// Should return Key metadata
	ps.setupDescribeKey(kms.CustomerMasterKeySpecRsa4096, nil)

	// Should return error
	ps.setupGetPublicKey(errors.New(errMsg))

	_, err := ps.plugin.Configure(ctx, ps.defaultConfigureRequest())

	ps.Require().Error(err)
	ps.Require().Equal(err.Error(), kmsErr)
}

func (ps *KmsPluginSuite) Test_GenerateKey_NonExistingKey() {
	ps.configurePluginWithoutKeys()

	// Should return new created Key
	ps.setupCreateKey(kms.CustomerMasterKeySpecRsa4096, nil)

	// Should return Key PublicKey
	ps.setupGetPublicKey(nil)

	_, err := ps.plugin.GenerateKey(ctx, &keymanager.GenerateKeyRequest{
		KeyId:   spireKeyID,
		KeyType: keymanager.KeyType_RSA_4096,
	})

	ps.Require().NoError(err)
	ps.Require().Equal(1, len(ps.rawPlugin.entries))
	ps.Require().Equal(ps.rawPlugin.entries[spireKeyID].KMSKeyID, kmsKeyID)
	ps.Require().Equal(ps.rawPlugin.entries[spireKeyID].PublicKey.Type, keymanager.KeyType_RSA_4096)
	ps.Require().Equal(ps.rawPlugin.entries[spireKeyID].PublicKey.Id, spireKeyID)
}

func (ps *KmsPluginSuite) Test_GenerateKey_ReplaceOldKey() {
	ps.configurePluginWithExistingKeys()

	// Should return new created Key
	ps.setupCreateKey(kms.CustomerMasterKeySpecRsa4096, nil)

	// Should return Key publicKey
	ps.setupGetPublicKey(nil)

	// Should Schedule key for deletion
	ps.setupScheduleKeyDeletion(nil)

	_, err := ps.plugin.GenerateKey(ctx, &keymanager.GenerateKeyRequest{
		KeyId:   spireKeyID,
		KeyType: keymanager.KeyType_RSA_4096,
	})

	ps.Require().NoError(err)
	ps.Require().Equal(1, len(ps.rawPlugin.entries))
	ps.Require().Equal(ps.rawPlugin.entries[spireKeyID].KMSKeyID, kmsKeyID)
	ps.Require().Equal(ps.rawPlugin.entries[spireKeyID].PublicKey.Type, keymanager.KeyType_RSA_4096)
	ps.Require().Equal(ps.rawPlugin.entries[spireKeyID].PublicKey.Id, spireKeyID)
}

func (ps *KmsPluginSuite) Test_GenerateKey_UnsupportedKeySpecError() {
	ps.configurePluginWithExistingKeys()

	_, err := ps.plugin.GenerateKey(ctx, &keymanager.GenerateKeyRequest{
		KeyId:   spireKeyID,
		KeyType: keymanager.KeyType_RSA_1024,
	})

	ps.Require().Error(err)
	ps.Require().Equal(err.Error(), "kms: unsupported key type: KeyType_RSA_1024")
}

func (ps *KmsPluginSuite) Test_GenerateKey_KmsCreateKeyError() {
	errMsg := "Create Key Error"
	kmsErr := fmt.Sprintf("kms: failed to create key: %s", errMsg)

	ps.configurePluginWithExistingKeys()

	// Should return error
	ps.setupCreateKey(kms.CustomerMasterKeySpecRsa4096, errors.New(errMsg))

	_, err := ps.plugin.GenerateKey(ctx, &keymanager.GenerateKeyRequest{
		KeyId:   spireKeyID,
		KeyType: keymanager.KeyType_RSA_4096,
	})

	ps.Require().Error(err)
	ps.Require().Equal(err.Error(), kmsErr)
}

func (ps *KmsPluginSuite) Test_GenerateKey_GetPublicKeyError() {
	errMsg := "Get Public Key Error"
	kmsErr := fmt.Sprintf("kms: failed to get public key: %s", errMsg)

	ps.configurePluginWithExistingKeys()

	// Should create the new key
	ps.setupCreateKey(kms.CustomerMasterKeySpecRsa4096, nil)

	// Should return error
	ps.setupGetPublicKey(errors.New(errMsg))

	_, err := ps.plugin.GenerateKey(ctx, &keymanager.GenerateKeyRequest{
		KeyId:   spireKeyID,
		KeyType: keymanager.KeyType_RSA_4096,
	})

	ps.Require().Error(err)
	ps.Require().Equal(err.Error(), kmsErr)
}

func (ps *KmsPluginSuite) Test_GenerateKey_ScheduleKeyDeletionError() {
	errMsg := "Schedule Key Deletion Error"

	ps.configurePluginWithExistingKeys()

	// Should create the new key
	ps.setupCreateKey(kms.CustomerMasterKeySpecRsa4096, nil)

	// Should return Key publicKey
	ps.setupGetPublicKey(nil)

	// Should return error
	ps.setupScheduleKeyDeletion(errors.New(errMsg))

	resp, err := ps.plugin.GenerateKey(ctx, &keymanager.GenerateKeyRequest{
		KeyId:   spireKeyID,
		KeyType: keymanager.KeyType_RSA_4096,
	})

	ps.Require().NotNil(resp)
	ps.Require().NoError(err)
	ps.Require().Equal(1, len(ps.rawPlugin.entries))
}

func (ps *KmsPluginSuite) Test_SignData() {
	ps.configurePluginWithExistingKeys()

	// Should sign data
	ps.setupSignData(nil)

	resp, err := ps.plugin.SignData(ctx, &keymanager.SignDataRequest{
		KeyId: spireKeyID,
		Data:  []byte("data"),
		SignerOpts: &keymanager.SignDataRequest_HashAlgorithm{
			HashAlgorithm: keymanager.HashAlgorithm_SHA256,
		},
	})

	ps.Require().NoError(err)
	ps.Require().NotNil(resp)
	ps.Require().Equal(resp.Signature, []byte("signature"))
}

func (ps *KmsPluginSuite) Test_SignData_NoExistingKeyError() {
	kmsErr := fmt.Sprintf("kms: no such key \"%s\"", spireKeyID)

	ps.configurePluginWithoutKeys()

	_, err := ps.plugin.SignData(ctx, &keymanager.SignDataRequest{
		KeyId: spireKeyID,
		Data:  []byte("data"),
		SignerOpts: &keymanager.SignDataRequest_HashAlgorithm{
			HashAlgorithm: keymanager.HashAlgorithm_SHA256,
		},
	})

	ps.Require().Error(err)
	ps.Require().Equal(err.Error(), kmsErr)
}

func (ps *KmsPluginSuite) Test_SignData_SignError() {
	errMsg := "Sign Data Error"
	kmsErr := fmt.Sprintf("kms: failed to sign: %s", errMsg)

	ps.configurePluginWithExistingKeys()

	// Should return error
	ps.setupSignData(errors.New(errMsg))

	_, err := ps.plugin.SignData(ctx, &keymanager.SignDataRequest{
		KeyId: spireKeyID,
		Data:  []byte("data"),
		SignerOpts: &keymanager.SignDataRequest_HashAlgorithm{
			HashAlgorithm: keymanager.HashAlgorithm_SHA256,
		},
	})

	ps.Require().Error(err)
	ps.Require().Equal(err.Error(), kmsErr)
}

func (ps *KmsPluginSuite) Test_GetPublicKey_ExistingKey() {
	ps.configurePluginWithExistingKeys()

	resp, err := ps.plugin.GetPublicKey(ctx, &keymanager.GetPublicKeyRequest{
		KeyId: spireKeyID,
	})

	ps.Require().NoError(err)
	ps.Require().Equal(resp.PublicKey.Id, ps.rawPlugin.entries[spireKeyID].PublicKey.Id)
	ps.Require().Equal(resp.PublicKey.Type, ps.rawPlugin.entries[spireKeyID].PublicKey.Type)
	ps.Require().Equal(resp.PublicKey.PkixData, ps.rawPlugin.entries[spireKeyID].PublicKey.PkixData)
}

func (ps *KmsPluginSuite) Test_GetPublicKey_NotExistingKey() {
	kmsErr := fmt.Sprintf("kms: no such key \"%s\"", spireKeyID)

	ps.configurePluginWithoutKeys()

	_, err := ps.plugin.GetPublicKey(ctx, &keymanager.GetPublicKeyRequest{
		KeyId: spireKeyID,
	})

	ps.Require().Error(err)
	ps.Require().Equal(err.Error(), kmsErr)
}

func (ps *KmsPluginSuite) Test_GetPublicKey_MissingKeyID() {
	kmsErr := "kms: key id is required"

	ps.configurePluginWithoutKeys()

	_, err := ps.plugin.GetPublicKey(ctx, &keymanager.GetPublicKeyRequest{
		KeyId: "",
	})

	ps.Require().Error(err)
	ps.Require().Equal(err.Error(), kmsErr)
}

func (ps *KmsPluginSuite) Test_GetPublicKeys_ExistingKeys() {
	ps.configurePluginWithExistingKeys()

	resp, err := ps.plugin.GetPublicKeys(ctx, &keymanager.GetPublicKeysRequest{})

	ps.Require().NoError(err)
	ps.Require().Equal(len(ps.rawPlugin.entries), len(resp.PublicKeys))
}

func (ps *KmsPluginSuite) Test_GetPublicKeys_NotExistingKey() {
	ps.configurePluginWithoutKeys()

	resp, err := ps.plugin.GetPublicKeys(ctx, &keymanager.GetPublicKeysRequest{})

	ps.Require().NoError(err)
	ps.Require().Equal(len(ps.rawPlugin.entries), len(resp.PublicKeys))
	ps.Require().Equal(0, len(resp.PublicKeys))
}

func (ps *KmsPluginSuite) Test_GetPluginInfo() {
	ps.configurePluginWithoutKeys()

	resp, err := ps.plugin.GetPluginInfo(ctx, &plugin.GetPluginInfoRequest{})

	ps.Require().NoError(err)
	ps.Require().NotNil(resp)
}

// helper methods
func (ps *KmsPluginSuite) configurePluginWithExistingKeys() {
	ps.configurePlugin(true)
}

func (ps *KmsPluginSuite) configurePluginWithoutKeys() {
	ps.configurePlugin(false)
}

func (ps *KmsPluginSuite) configurePlugin(existingKeys bool) {
	// Should return a list of Keys aliases
	ps.setupListAliases(existingKeys, nil)

	// Should return Key metadata
	ps.setupDescribeKey(kms.CustomerMasterKeySpecRsa4096, nil)

	// Should return Key PublicKey
	ps.setupGetPublicKey(nil)

	_, err := ps.plugin.Configure(ctx, ps.defaultConfigureRequest())
	ps.Require().NoError(err)
}

func (ps *KmsPluginSuite) configureRequest(config string) *plugin.ConfigureRequest {
	return &plugin.ConfigureRequest{
		Configuration: config,
	}
}

func (ps *KmsPluginSuite) defaultConfigureRequest() *plugin.ConfigureRequest {
	return &plugin.ConfigureRequest{
		Configuration: ps.defaultSerializedConfiguration(),
	}
}

func (ps *KmsPluginSuite) defaultSerializedConfiguration() string {
	config := ps.serializedConfiguration(validAccessKeyID, validSecretAccessKey, validRegion)
	return config
}

func (ps *KmsPluginSuite) serializedConfiguration(accessKeyID, secretAccessKey, region string) string {
	return fmt.Sprintf(`{
		"access_key_id": "%s",
		"secret_access_key": "%s",
		"region":"%s"
		}`,
		accessKeyID,
		secretAccessKey,
		region)
}

func (ps *KmsPluginSuite) setupListKeys(withKeys bool, fakeError error) {
	var keys []*kms.KeyListEntry

	if withKeys {
		keys = append(keys, &kms.KeyListEntry{
			KeyArn: aws.String("arn:aws:iam::123456789012:user/Development/key/1"),
			KeyId:  aws.String(kmsKeyID),
		})
	}

	ps.kmsClientFake.expectedListKeysInput = &kms.ListKeysInput{}
	ps.kmsClientFake.listKeysErr = fakeError

	ps.kmsClientFake.listKeysOutput = &kms.ListKeysOutput{
		Keys: keys,
	}
}

func (ps *KmsPluginSuite) setupListAliases(withAliases bool, fakeError error) {
	var aliases []*kms.AliasListEntry

	if withAliases {
		aliases = append(aliases, &kms.AliasListEntry{
			AliasName:   aws.String(spireKeyAlias),
			TargetKeyId: aws.String(kmsKeyID),
		})
	}

	ps.kmsClientFake.expectedListAliasesInput = &kms.ListAliasesInput{}
	ps.kmsClientFake.listAliasesErr = fakeError

	ps.kmsClientFake.listAliasesOutput = &kms.ListAliasesOutput{
		Aliases: aliases,
	}
}

func (ps *KmsPluginSuite) setupDescribeKey(keySpec string, fakeError error) {
	km := &kms.KeyMetadata{
		KeyId:                 aws.String(kmsKeyID),
		Description:           aws.String(keyPrefix + spireKeyID),
		CustomerMasterKeySpec: aws.String(keySpec),
		Enabled:               aws.Bool(true),
		CreationDate:          aws.Time(time.Now()),
	}

	ps.kmsClientFake.expectedDescribeKeyInput = &kms.DescribeKeyInput{KeyId: aws.String(kmsKeyID)}
	ps.kmsClientFake.describeKeyErr = fakeError

	ps.kmsClientFake.describeKeyOutput = &kms.DescribeKeyOutput{KeyMetadata: km}
}

func (ps *KmsPluginSuite) setupGetPublicKey(fakeError error) {
	var data string

	for n := 0; n < 4096; n++ {
		data = data + "*"
	}

	pub := &kms.GetPublicKeyOutput{
		CustomerMasterKeySpec: aws.String(kms.CustomerMasterKeySpecEccNistP256),
		KeyId:                 aws.String(kmsKeyID),
		KeyUsage:              aws.String(signVerifyKeyUsage),
		PublicKey:             []byte(data),
		SigningAlgorithms:     []*string{aws.String(kms.SigningAlgorithmSpecRsassaPssSha256)},
	}

	ps.kmsClientFake.expectedGetPublicKeyInput = &kms.GetPublicKeyInput{KeyId: aws.String(kmsKeyID)}
	ps.kmsClientFake.getPublicKeyErr = fakeError

	ps.kmsClientFake.getPublicKeyOutput = pub
}

func (ps *KmsPluginSuite) setupCreateKey(keySpec string, fakeError error) {
	desc := aws.String(keyPrefix + spireKeyID)
	ku := aws.String(kms.KeyUsageTypeSignVerify)
	ks := aws.String(keySpec)

	ps.kmsClientFake.expectedCreateKeyInput = &kms.CreateKeyInput{
		Description:           desc,
		KeyUsage:              ku,
		CustomerMasterKeySpec: ks,
	}

	ps.kmsClientFake.createKeyErr = fakeError

	km := &kms.KeyMetadata{
		KeyId:                 aws.String(kmsKeyID),
		CreationDate:          aws.Time(time.Now()),
		Description:           desc,
		KeyUsage:              ku,
		CustomerMasterKeySpec: ks,
	}
	ps.kmsClientFake.createKeyOutput = &kms.CreateKeyOutput{KeyMetadata: km}
}

func (ps *KmsPluginSuite) setupScheduleKeyDeletion(fakeError error) {
	ps.kmsClientFake.expectedScheduleKeyDeletionInput = &kms.ScheduleKeyDeletionInput{
		KeyId:               aws.String(kmsKeyID),
		PendingWindowInDays: aws.Int64(7),
	}

	ps.kmsClientFake.scheduleKeyDeletionErr = fakeError

	ps.kmsClientFake.scheduleKeyDeletionOutput = &kms.ScheduleKeyDeletionOutput{
		KeyId:        aws.String(kmsKeyID),
		DeletionDate: aws.Time(time.Now()),
	}
}

func (ps *KmsPluginSuite) setupSignData(fakeError error) {
	ps.kmsClientFake.expectedSignInput = &kms.SignInput{
		KeyId:            aws.String(spireKeyAlias),
		Message:          []byte("data"),
		MessageType:      aws.String(kms.MessageTypeDigest),
		SigningAlgorithm: aws.String(kms.SigningAlgorithmSpecRsassaPkcs1V15Sha256),
	}

	ps.kmsClientFake.signErr = fakeError

	ps.kmsClientFake.signOutput = &kms.SignOutput{
		Signature: []byte("signature"),
	}
}
