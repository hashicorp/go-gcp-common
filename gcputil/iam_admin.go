package gcputil

import (
	"fmt"
	"google.golang.org/api/iam/v1"
)

const (
	ServiceAccountTemplate    = "projects/%s/serviceAccounts/%s"
	ServiceAccountKeyTemplate = "projects/%s/serviceAccounts/%s/keys/%s"
	ServiceAccountKeyFileType = "TYPE_X509_PEM_FILE"
)

type ServiceAccountId struct {
	Project   string
	EmailOrId string
}

type ServiceAccountKeyId struct {
	Project   string
	EmailOrId string
	Key       string
}

// ServiceAccount wraps a call to the GCP IAM API to get a service account.
func ServiceAccount(iamClient *iam.Service, accountId *ServiceAccountId) (*iam.ServiceAccount, error) {
	accountResource := fmt.Sprintf(ServiceAccountTemplate, accountId.Project, accountId.EmailOrId)
	account, err := iamClient.Projects.ServiceAccounts.Get(accountResource).Do()
	if err != nil {
		return nil, fmt.Errorf("could not find service account '%s': %v", accountResource, err)
	}

	return account, nil
}

// ServiceAccountKey wraps a call to the GCP IAM API to get a service account key.
func ServiceAccountKey(iamClient *iam.Service, keyId *ServiceAccountKeyId) (*iam.ServiceAccountKey, error) {
	keyResource := fmt.Sprintf(ServiceAccountKeyTemplate, keyId.Project, keyId.EmailOrId, keyId.Key)
	key, err := iamClient.Projects.ServiceAccounts.Keys.Get(keyResource).PublicKeyType(ServiceAccountKeyFileType).Do()
	if err != nil {
		return nil, fmt.Errorf("could not find service account key '%s': %v", keyResource, err)
	}
	return key, nil
}
