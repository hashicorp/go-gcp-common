package gcputil

import (
	"context"
	"fmt"

	"google.golang.org/api/iam/v1"
)

const (
	// ServiceAccountTemplate is used with Google IAM v1.
	//
	// Deprecated: Use ServiceAccountCredentialsTemplate with Service Account Credentials API v1
	// instead. See https://cloud.google.com/iam/docs/migrating-to-credentials-api
	// ServiceAccountTemplate is used with
	// https://pkg.go.dev/google.golang.org/api@v0.3.0/iam/v1
	ServiceAccountTemplate = "projects/%s/serviceAccounts/%s"

	// ServiceAccountCredentialsTemplate is used with
	// https://pkg.go.dev/google.golang.org/api@v0.3.0/iamcredentials/v1
	ServiceAccountCredentialsTemplate = "projects/-/serviceAccounts/%s"
	ServiceAccountKeyTemplate         = "projects/%s/serviceAccounts/%s/keys/%s"
	ServiceAccountKeyFileType         = "TYPE_X509_PEM_FILE"
)

type ServiceAccountId struct {
	Project   string
	EmailOrId string
}

func (id *ServiceAccountId) ResourceName() string {
	return fmt.Sprintf(ServiceAccountTemplate, id.Project, id.EmailOrId)
}

type ServiceAccountKeyId struct {
	Project   string
	EmailOrId string
	Key       string
}

func (id *ServiceAccountKeyId) ResourceName() string {
	return fmt.Sprintf(ServiceAccountKeyTemplate, id.Project, id.EmailOrId, id.Key)
}

// ServiceAccountWithContext wraps a call to the GCP IAM API to get a service account.
func ServiceAccountWithContext(ctx context.Context, iamClient *iam.Service, accountId *ServiceAccountId) (*iam.ServiceAccount, error) {
	saResource := accountId.ResourceName()
	req := iamClient.Projects.ServiceAccounts.Get(saResource).Context(ctx)
	req.Header().Set("Host", "iam.googleapis.com")
	account, err := req.Do()
	if err != nil {
		return nil, fmt.Errorf("could not find service account %q: %v", saResource, err)
	}

	return account, nil
}

// ServiceAccount wraps a call to the GCP IAM API to get a service account.
func ServiceAccount(iamClient *iam.Service, accountId *ServiceAccountId) (*iam.ServiceAccount, error) {
	return ServiceAccountWithContext(context.Background(), iamClient, accountId)
}

// ServiceAccountKeyWithContext wraps a call to the GCP IAM API to get a service account key.
func ServiceAccountKeyWithContext(ctx context.Context, iamClient *iam.Service, keyId *ServiceAccountKeyId) (*iam.ServiceAccountKey, error) {
	keyResource := keyId.ResourceName()
	req := iamClient.Projects.ServiceAccounts.Keys.Get(keyResource).
		PublicKeyType(ServiceAccountKeyFileType).Context(ctx)
	req.Header().Set("Host", "iam.googleapis.com")
	key, err := req.Do()
	if err != nil {
		return nil, fmt.Errorf("could not find service account key %q: %v", keyResource, err)
	}

	return key, nil
}

// ServiceAccountKey wraps a call to the GCP IAM API to get a service account key.
func ServiceAccountKey(iamClient *iam.Service, keyId *ServiceAccountKeyId) (*iam.ServiceAccountKey, error) {
	return ServiceAccountKeyWithContext(context.Background(), iamClient, keyId)
}
