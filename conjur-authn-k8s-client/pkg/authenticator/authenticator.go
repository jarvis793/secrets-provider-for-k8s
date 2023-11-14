package authenticator

import (
	"context"
	"secrets-provider-for-k8s/conjur-authn-k8s-client/pkg/access_token"
)

type Authenticator interface {
	Authenticate() error
	AuthenticateWithContext(ctx context.Context) error
	GetAccessToken() access_token.AccessToken
}
