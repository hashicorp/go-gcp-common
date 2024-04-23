package gcputil

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"

	"github.com/hashicorp/go-cleanhttp"
)

var errTokenRequestNil = errors.New("expected token request fields; got nil")

// ExchangeSTSToken performs a token exchange request against the STS Token API
// and returns an STSTokenResponse
func ExchangeSTSToken(ctx context.Context, endpoint string, request *STSTokenExchangeRequest) (*STSTokenResponse, error) {
	if request == nil {
		return nil, errTokenRequestNil
	}
	return makeSTSRequest(ctx, endpoint, request)
}

// ExchangeServiceAccountToken performs a token exchange request against the IAM Credentials Token API
// and returns an IAMTokenResponse
func ExchangeServiceAccountToken(ctx context.Context, endpoint string, request *IAMTokenExchangeRequest) (*IAMTokenResponse, error) {
	if request == nil {
		return nil, errTokenRequestNil
	}
	return makeIAMRequest(ctx, endpoint, request)
}

// @TODO consolidate both methods
func makeSTSRequest(ctx context.Context, endpoint string, r *STSTokenExchangeRequest) (*STSTokenResponse, error) {
	client := cleanhttp.DefaultClient()
	// The STS API expects data in URL Form Encoded Form
	data := url.Values{}
	data.Set("audience", r.Audience)
	data.Set("grant_type", "urn:ietf:params:oauth:grant-type:token-exchange")
	data.Set("requested_token_type", "urn:ietf:params:oauth:token-type:access_token")
	data.Set("subject_token_type", r.SubjectTokenType)
	data.Set("subject_token", r.SubjectToken)
	data.Set("scope", strings.Join(r.Scope, " "))
	encodedData := data.Encode()

	req, err := http.NewRequest("POST", endpoint, strings.NewReader(encodedData))
	if err != nil {
		return nil, fmt.Errorf("sts/google: failed to properly build http request: %v", err)
	}
	req = req.WithContext(ctx)
	req.Header.Add("Content-Type", "application/x-www-form-urlencoded")

	resp, err := client.Do(req)

	if err != nil {
		return nil, fmt.Errorf("sts/google: invalid response from Secure Token Server: %v", err)
	}
	defer resp.Body.Close()

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, err
	}
	if c := resp.StatusCode; c < 200 || c > 299 {
		return nil, fmt.Errorf("sts/google: status code %d: %s", c, body)
	}
	var stsResp STSTokenResponse
	err = json.Unmarshal(body, &stsResp)
	if err != nil {
		return nil, fmt.Errorf("sts/google: failed to unmarshal response body from Secure Token Server: %v", err)

	}

	return &stsResp, nil
}

func makeIAMRequest(ctx context.Context, endpoint string, r *IAMTokenExchangeRequest) (*IAMTokenResponse, error) {
	c := cleanhttp.DefaultClient()
	data := map[string]interface{}{
		"scope": r.Scope,
	}
	if r.Lifetime != "" {
		data["lifetime"] = r.Lifetime
	}
	b, err := json.Marshal(data)
	if err != nil {
		return nil, err
	}

	req, err := http.NewRequest("POST", endpoint, bytes.NewBuffer(b))
	if err != nil {
		return nil, fmt.Errorf("iamCredentials/google: failed to properly build http request: %v", err)
	}
	req = req.WithContext(ctx)
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Authorization", fmt.Sprintf("Bearer %s", r.STSAccessToken))
	resp, err := c.Do(req)
	if err != nil {
		return nil, fmt.Errorf("iamCredentials/google: invalid response from IAM Credentials Server: %v", err)
	}
	defer resp.Body.Close()

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, err
	}
	if c := resp.StatusCode; c < 200 || c > 299 {
		return nil, fmt.Errorf("iamCredentials/google: status code %d: %s", c, body)
	}

	var stsResp IAMTokenResponse
	err = json.Unmarshal(body, &stsResp)
	if err != nil {
		return nil, fmt.Errorf("iamCredentials/google: failed to unmarshal response body from IAM Credentials Server: %v", err)

	}

	return &stsResp, nil
}

// STSTokenExchangeRequest contains fields necessary to make an STS token exchange.
type STSTokenExchangeRequest struct {
	GrantType          string
	Audience           string
	Scope              []string
	RequestedTokenType string
	SubjectToken       string
	SubjectTokenType   string
}

// STSTokenResponse is used to decode the remote server response during an STS token exchange.
type STSTokenResponse struct {
	AccessToken     string `json:"access_token"`
	IssuedTokenType string `json:"issued_token_type"`
	TokenType       string `json:"token_type"`
	ExpiresIn       int    `json:"expires_in"`
	Scope           string `json:"scope"`
	RefreshToken    string `json:"refresh_token"`
}

// IAMTokenExchangeRequest contains fields necessary to make an IAM token exchange.
type IAMTokenExchangeRequest struct {
	Scope          []string
	Lifetime       string
	STSAccessToken string
}

// IAMTokenResponse is used to decode the remote server response during an IAM token exchange.
// Note: The response from the IAM Token API follows camel-case while the STS Token API
// uses snake-case for the response keys.
type IAMTokenResponse struct {
	AccessToken string `json:"accessToken"`
	ExpireTime  string `json:"expireTime"`
}
