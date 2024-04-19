package gcputil

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"
)

var stsTokenRequest = STSTokenExchangeRequest{
	GrantType:          "urn:ietf:params:oauth:grant-type:token-exchange",
	RequestedTokenType: "urn:ietf:params:oauth:token-type:access_token",
	SubjectTokenType:   "urn:ietf:params:oauth:token-type:jwt",
	Audience:           "test-audience",
	Scope:              []string{"https://www.googleapis.com/auth/cloud-platform"},
	SubjectToken:       "test-workloadIdentity-token",
}

var stsRequestBody = "audience=test-audience&grant_type=urn%3Aietf%3Aparams%3Aoauth%3Agrant-type%3Atoken-exchange&requested_token_type=urn%3Aietf%3Aparams%3Aoauth%3Atoken-type%3Aaccess_token&scope=https%3A%2F%2Fwww.googleapis.com%2Fauth%2Fcloud-platform&subject_token=test-workloadIdentity-token&subject_token_type=urn%3Aietf%3Aparams%3Aoauth%3Atoken-type%3Ajwt"
var stsResponseBody = `{"access_token":"Sample.Access.Token","issued_token_type":"urn:ietf:params:oauth:token-type:access_token","token_type":"Bearer","expires_in":3600,"scope":"https://www.googleapis.com/auth/cloud-platform"}`

var expectedSTSExchangeToken = STSTokenResponse{
	AccessToken:     "Sample.Access.Token",
	IssuedTokenType: "urn:ietf:params:oauth:token-type:access_token",
	TokenType:       "Bearer",
	ExpiresIn:       3600,
	Scope:           "https://www.googleapis.com/auth/cloud-platform",
	RefreshToken:    "",
}

var iamTokenRequest = IAMTokenExchangeRequest{
	STSAccessToken: "test-token",
	Scope:          []string{"https://www.googleapis.com/auth/cloud-platform"},
}

var iamRequestBody = map[string]interface{}{
	"scope": []string{"https://www.googleapis.com/auth/cloud-platform"},
}

func TestExchangeSTSToken(t *testing.T) {
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != "POST" {
			t.Errorf("Unexpected request method, %v is found", r.Method)
		}
		if r.URL.String() != "/" {
			t.Errorf("Unexpected request URL, %v is found", r.URL)
		}
		if got, want := r.Header.Get("Content-Type"), "application/x-www-form-urlencoded"; got != want {
			t.Errorf("Unexpected Content-Type header, got %v, want %v", got, want)
		}
		body, err := io.ReadAll(r.Body)
		if err != nil {
			t.Errorf("Failed reading request body: %v.", err)
		}
		if got, want := string(body), stsRequestBody; got != want {
			t.Errorf("Unexpected exchange payload, got %v but want %v", got, want)
		}
		w.Write([]byte(stsResponseBody))
	}))
	defer ts.Close()

	// test nil request case
	_, err := ExchangeSTSToken(context.Background(), ts.URL, nil)
	if err == nil {
		t.Fatalf("expected error; got nil")
	}

	if !errors.Is(err, errTokenRequestNil) {
		t.Fatalf("expected error %s, got %s", errTokenRequestNil, err)
	}

	// test general case
	resp, err := ExchangeSTSToken(context.Background(), ts.URL, &stsTokenRequest)
	if err != nil {
		t.Fatalf("exchangeToken failed with error: %v", err)
	}

	if expectedSTSExchangeToken != *resp {
		t.Fatalf("mismatched messages received by mock server. Want: \n%v\n\nGot:\n%v", expectedSTSExchangeToken, *resp)
	}
}

func TestExchangeServiceAccountToken(t *testing.T) {
	now := time.Now().Add(1 * time.Hour)
	iamResponseBody := getIAMResponseBody(&now)
	expectedIAMExchangeToken := getExpectedIAMToken(&now)

	expectedRequestBytes, err := json.Marshal(iamRequestBody)
	if err != nil {
		t.Fatalf("error marshalling IAM Request: %s", err)
	}
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != "POST" {
			t.Errorf("Unexpected request method, %v is found", r.Method)
		}
		if r.URL.String() != "/" {
			t.Errorf("Unexpected request URL, %v is found", r.URL)
		}
		if got, want := r.Header.Get("Content-Type"), "application/json"; got != want {
			t.Errorf("Unexpected Content-Type header, got %v, want %v", got, want)
		}
		if got, want := r.Header.Get("Authorization"), "Bearer test-token"; got != want {
			t.Errorf("Unexpected Authorization header, got %v, want %v", got, want)
		}
		body, err := io.ReadAll(r.Body)
		if err != nil {
			t.Errorf("Failed reading request body: %v.", err)
		}
		if got, want := string(body), string(expectedRequestBytes); got != want {
			t.Errorf("Unexpected exchange payload, got %v but want %v", got, want)
		}
		w.Write([]byte(iamResponseBody))
	}))
	defer ts.Close()

	// test nil request case
	_, err = ExchangeServiceAccountToken(context.Background(), ts.URL, nil)
	if err == nil {
		t.Fatalf("expected error; got nil")
	}

	if !errors.Is(err, errTokenRequestNil) {
		t.Fatalf("expected error %s, got %s", errTokenRequestNil, err)
	}

	resp, err := ExchangeServiceAccountToken(context.Background(), ts.URL, &iamTokenRequest)
	if err != nil {
		t.Fatalf("exchangeToken failed with error: %v", err)
	}

	if *expectedIAMExchangeToken != *resp {
		t.Errorf("mismatched messages received by mock server. Want: \n%v\n\nGot:\n%v", expectedSTSExchangeToken, *resp)
	}
}

func getIAMResponseBody(t *time.Time) string {
	return fmt.Sprintf(`{"accessToken":"Sample.Access.Token","expireTime":"%s"}`, t.String())
}

func getExpectedIAMToken(t *time.Time) *IAMTokenResponse {
	return &IAMTokenResponse{
		AccessToken: "Sample.Access.Token",
		ExpireTime:  t.String(),
	}
}
