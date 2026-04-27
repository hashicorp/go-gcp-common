// Copyright IBM Corp. 2018, 2025
// SPDX-License-Identifier: MPL-2.0

package gcputil

import (
	"context"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"errors"
	"fmt"
	"io"
	"io/ioutil"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/go-jose/go-jose/v4"
	"github.com/hashicorp/go-cleanhttp"
	"github.com/mitchellh/go-homedir"
	"golang.org/x/oauth2"
	"golang.org/x/oauth2/google"
	"golang.org/x/oauth2/google/externalaccount"
	"golang.org/x/oauth2/jwt"
	"google.golang.org/api/googleapi"
)

const (
	defaultHomeCredentialsFile = ".gcp/credentials"

	// Default service endpoint for interaction with Google APIs
	// https://cloud.google.com/apis/design/glossary#api_service_endpoint
	defaultGoogleAPIsEndpoint = "https://www.googleapis.com"

	// serviceAccountPublicKeyURLPathTemplate is a templated URL path for obtaining the
	// public keys associated with a service account. See details at
	//   - https://cloud.google.com/iam/docs/creating-managing-service-account-keys
	//   - https://cloud.google.com/iam/docs/reference/credentials/rest/v1/projects.serviceAccounts/signJwt#response-body
	serviceAccountPublicKeyURLPathTemplate = "/service_accounts/v1/metadata/x509/%s?alt=json"

	// Default Google Open ID connect issuer endpoint
	defaultGoogleOpenIDEndpoint = "https://accounts.google.com"

	// Open ID connect discovery path
	openIDConfigurationPath = "/.well-known/openid-configuration"

	// Default service endpoint for interaction with the IAM Credentials API
	defaultIAMCredentialsAPIsEndpoint = "https://iamcredentials.googleapis.com"

	// defaultJWTSubjectTokenType is the token type expected by the STS API
	// when requesting for STS Tokens
	defaultJWTSubjectTokenType = "urn:ietf:params:oauth:token-type:jwt"
)

var defaultTokenAuthScopes = []string{"https://www.googleapis.com/auth/cloud-platform"}

// GcpCredentials represents a simplified version of the Google Cloud Platform credentials file format.
type GcpCredentials struct {
	ClientEmail  string `json:"client_email" structs:"client_email" mapstructure:"client_email"`
	ClientId     string `json:"client_id" structs:"client_id" mapstructure:"client_id"`
	PrivateKeyId string `json:"private_key_id" structs:"private_key_id" mapstructure:"private_key_id"`
	PrivateKey   string `json:"private_key" structs:"private_key" mapstructure:"private_key"`
	ProjectId    string `json:"project_id" structs:"project_id" mapstructure:"project_id"`
}

type ExternalAccountConfig struct {
	// External Account fields
	Audience                   string
	TTL                        time.Duration
	ServiceAccountEmail        string
	TokenSupplier              externalaccount.SubjectTokenSupplier
	TokenURL                   string
	IAMCredentialsAPIsEndpoint string
}

func (c *ExternalAccountConfig) GetExternalAccountCredentials(ctx context.Context) (*google.Credentials, error) {
	iamCredentialsAPIsEndpoint := c.IAMCredentialsAPIsEndpoint
	if iamCredentialsAPIsEndpoint == "" {
		iamCredentialsAPIsEndpoint = defaultIAMCredentialsAPIsEndpoint
	}

	config := externalaccount.Config{
		Audience:                       strings.TrimPrefix(c.Audience, "https:"),
		SubjectTokenType:               defaultJWTSubjectTokenType,
		ServiceAccountImpersonationURL: fmt.Sprintf("%s/v1/projects/-/serviceAccounts/%s:generateAccessToken", iamCredentialsAPIsEndpoint, c.ServiceAccountEmail),
		ServiceAccountImpersonationLifetimeSeconds: int(c.TTL.Seconds()),
		SubjectTokenSupplier:                       c.TokenSupplier,
		Scopes:                                     defaultTokenAuthScopes,
		TokenURL:                                   c.TokenURL,
	}

	ts, err := externalaccount.NewTokenSource(ctx, config)
	if err != nil {
		return nil, err
	}

	return &google.Credentials{
		TokenSource: ts,
	}, nil
}

// FindCredentials attempts to obtain GCP credentials in the
// following ways:
// * Parse JSON from provided credentialsJson
// * Parse JSON from the environment variables GOOGLE_CREDENTIALS or GOOGLE_CLOUD_KEYFILE_JSON
// * Parse JSON file ~/.gcp/credentials
// * Google Application Default Credentials (see https://developers.google.com/identity/protocols/application-default-credentials)
func FindCredentials(credsJson string, ctx context.Context, scopes ...string) (*GcpCredentials, oauth2.TokenSource, error) {
	var creds *GcpCredentials
	var err error
	// 1. Parse JSON from provided credentialsJson
	if credsJson == "" {
		// 2. JSON from env var GOOGLE_CREDENTIALS
		credsJson = os.Getenv("GOOGLE_CREDENTIALS")
	}

	if credsJson == "" {
		// 3. JSON from env var GOOGLE_CLOUD_KEYFILE_JSON
		credsJson = os.Getenv("GOOGLE_CLOUD_KEYFILE_JSON")
	}

	if credsJson == "" {
		// 4. JSON from ~/.gcp/credentials
		home, err := homedir.Dir()
		if err != nil {
			return nil, nil, errors.New("could not find home directory")
		}
		credBytes, err := ioutil.ReadFile(filepath.Join(home, defaultHomeCredentialsFile))
		if err == nil {
			credsJson = string(credBytes)
		}
	}

	// Parse JSON into credentials.
	if credsJson != "" {
		creds, err = Credentials(credsJson)
		if err == nil {
			conf := jwt.Config{
				Email:      creds.ClientEmail,
				PrivateKey: []byte(creds.PrivateKey),
				Scopes:     scopes,
				TokenURL:   "https://accounts.google.com/o/oauth2/token",
			}
			return creds, conf.TokenSource(ctx), nil
		}
	}

	// 5. Use Application default credentials.
	defaultCreds, err := google.FindDefaultCredentials(ctx, scopes...)
	if err != nil {
		return nil, nil, err
	}

	if defaultCreds.JSON != nil {
		creds, err = Credentials(string(defaultCreds.JSON))
		if err != nil {
			return nil, nil, errors.New("could not read credentials from application default credential JSON")
		}
	}

	return creds, defaultCreds.TokenSource, nil
}

// Credentials attempts to parse GcpCredentials from a JSON string.
func Credentials(credentialsJson string) (*GcpCredentials, error) {
	credentials := &GcpCredentials{}
	if err := json.Unmarshal([]byte(credentialsJson), &credentials); err != nil {
		return nil, err
	}
	return credentials, nil
}

// GetHttpClient creates an HTTP client from the given Google credentials and scopes.
func GetHttpClient(credentials *GcpCredentials, clientScopes ...string) (*http.Client, error) {
	conf := jwt.Config{
		Email:      credentials.ClientEmail,
		PrivateKey: []byte(credentials.PrivateKey),
		Scopes:     clientScopes,
		TokenURL:   "https://accounts.google.com/o/oauth2/token",
	}

	ctx := context.WithValue(context.Background(), oauth2.HTTPClient, cleanhttp.DefaultClient())
	client := conf.Client(ctx)
	return client, nil
}

// PublicKey returns a public key from a Google PEM key file (type TYPE_X509_PEM_FILE).
func PublicKey(pemString string) (interface{}, error) {
	// Attempt to base64 decode
	pemBytes := []byte(pemString)
	if b64decoded, err := base64.StdEncoding.DecodeString(pemString); err == nil {
		pemBytes = b64decoded
	}

	block, _ := pem.Decode(pemBytes)
	if block == nil {
		return nil, errors.New("unable to find pem block in key")
	}

	cert, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		return nil, err
	}

	return cert.PublicKey, nil
}

// ServiceAccountPublicKey returns the public key with the given key ID for
// the given service account if it exists. If the key does not exist, an error
// is returned.
func ServiceAccountPublicKey(serviceAccount string, keyId string) (interface{}, error) {
	return ServiceAccountPublicKeyWithEndpoint(context.Background(), serviceAccount, keyId, "")
}

// ServiceAccountPublicKeyWithEndpoint returns the public key with the given key
// ID for the given service account if it exists. If endpoint is provided, it will
// be used as the service endpoint for the request. If endpoint is not provided,
// a default of "https://www.googleapis.com" will be used. If the key does not exist,
// an error is returned.
func ServiceAccountPublicKeyWithEndpoint(ctx context.Context, serviceAccount, keyID, endpoint string) (interface{}, error) {
	if endpoint == "" {
		endpoint = defaultGoogleAPIsEndpoint
	}

	keyURLPath := fmt.Sprintf(serviceAccountPublicKeyURLPathTemplate, url.PathEscape(serviceAccount))
	keyURL := strings.TrimSuffix(endpoint, "/") + keyURLPath
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, keyURL, nil)
	if err != nil {
		return nil, err
	}
	resp, err := cleanhttp.DefaultClient().Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	if err := googleapi.CheckResponse(resp); err != nil {
		return nil, err
	}

	jwks := map[string]interface{}{}
	if err := json.NewDecoder(resp.Body).Decode(&jwks); err != nil {
		return nil, fmt.Errorf("unable to decode JSON response: %v", err)
	}
	kRaw, ok := jwks[keyID]
	if !ok {
		return nil, fmt.Errorf("service account %q key %q not found at GET %q", keyID, serviceAccount, keyURL)
	}

	kStr, ok := kRaw.(string)
	if !ok {
		return nil, fmt.Errorf("unexpected error - decoded JSON key value %v is not string", kRaw)
	}
	return PublicKey(kStr)
}

// OAuth2RSAPublicKey returns the public key with the given key ID from Google's
// public set of OAuth 2.0 keys. If the key does not exist, an error is returned.
func OAuth2RSAPublicKey(ctx context.Context, keyID string) (interface{}, error) {
	return OAuth2RSAPublicKeyWithEndpoint(ctx, keyID, "")
}

// OAuth2RSAPublicKeyWithEndpoint performs OpenID Connect Discovery to find the
// JSON Web Key Set (JWKS) URL for the given OpenID Connect issuer endpoint,
// fetches the keys, and returns the public key matching the specified key ID.
// If issuer endpoint is not provided, a default of
// "https://accounts.google.com" will be used. If the key does not exist, an
// error is returned.
func OAuth2RSAPublicKeyWithEndpoint(ctx context.Context, keyID, endpoint string) (interface{}, error) {
	jwksEndpoint, err := jwksURL(ctx, endpoint)
	if err != nil {
		return nil, err
	}

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, jwksEndpoint, nil)
	if err != nil {
		return nil, err
	}
	resp, err := cleanhttp.DefaultClient().Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	if err := googleapi.CheckResponse(resp); err != nil {
		return nil, err
	}

	jwksRaw, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, err
	}

	var jwks jose.JSONWebKeySet
	if err := json.Unmarshal(jwksRaw, &jwks); err != nil {
		return nil, fmt.Errorf("failed to unmarshal JWKS JSON: %v", err)
	}

	keys := jwks.Key(keyID)
	if len(keys) == 0 {
		return nil, fmt.Errorf("key %q not found (GET %q)", keyID, jwksEndpoint)
	}

	// Specification states that a JWK Set "SHOULD" use distinct key IDs, but
	// allows for some cases where they are not distinct, hence JSONWebKeySet.Key
	// returns a slice. So, picking the first key from the slice.
	jwkKey := keys[0]
	if !jwkKey.Valid() {
		return nil, fmt.Errorf("jwk is missing key material")
	}
	return jwkKey.Key, nil
}

func jwksURL(ctx context.Context, endpoint string) (string, error) {
	if endpoint == "" {
		endpoint = defaultGoogleOpenIDEndpoint
	}
	configURL := strings.TrimSuffix(endpoint, "/") + openIDConfigurationPath

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, configURL, nil)
	if err != nil {
		return "", err
	}
	resp, err := cleanhttp.DefaultClient().Do(req)
	if err != nil {
		return "", err
	}
	defer resp.Body.Close()

	if err := googleapi.CheckResponse(resp); err != nil {
		return "", err
	}

	config := map[string]interface{}{}
	if err := json.NewDecoder(resp.Body).Decode(&config); err != nil {
		return "", fmt.Errorf("unable to decode JSON response: %v", err)
	}
	jwksUrlRaw, ok := config["jwks_uri"]
	if !ok {
		return "", fmt.Errorf("jwks_uri not found (GET %q)", configURL)
	}
	jwksUrl, ok := jwksUrlRaw.(string)
	if !ok {
		return "", fmt.Errorf("unexpected error - decoded JSON url value %v is not string", jwksUrlRaw)
	}
	return jwksUrl, nil
}
