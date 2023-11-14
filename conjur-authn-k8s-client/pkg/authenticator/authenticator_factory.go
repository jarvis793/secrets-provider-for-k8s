package authenticator

import (
	"fmt"
	"secrets-provider-for-k8s2/conjur-authn-k8s-client/pkg/access_token"
	"secrets-provider-for-k8s2/conjur-authn-k8s-client/pkg/access_token/file"
	jwtAuthenticator "secrets-provider-for-k8s2/conjur-authn-k8s-client/pkg/authenticator/jwt"
	k8sAuthenticator "secrets-provider-for-k8s2/conjur-authn-k8s-client/pkg/authenticator/k8s"
	"secrets-provider-for-k8s2/conjur-authn-k8s-client/pkg/log"
	"secrets-provider-for-k8s2/conjur-authn-k8s-client/pkg/pkg/authenticator/config"
)

// NewAuthenticator creates an instance of the Authenticator interface based on configured authenticator type.
func NewAuthenticator(conf config.Configuration) (Authenticator, error) {
	accessToken, error := file.NewAccessToken(conf.GetTokenFilePath())
	if error != nil {
		return nil, error
	}
	return getAuthenticator(conf, accessToken)
}

// NewAuthenticatorWithAccessToken creates an instance of the Authenticator interface based on configured authenticator type
// and access token
func NewAuthenticatorWithAccessToken(conf config.Configuration, token access_token.AccessToken) (Authenticator, error) {
	return getAuthenticator(conf, token)
}

func getAuthenticator(conf config.Configuration, token access_token.AccessToken) (Authenticator, error) {
	switch c := conf.(type) {
	case *k8sAuthenticator.Config:
		log.Info(log.CAKC075, k8sAuthenticator.AuthnType)
		return k8sAuthenticator.NewWithAccessToken(*c, token)
	case *jwtAuthenticator.Config:
		log.Info(log.CAKC075, jwtAuthenticator.AuthnType)
		return jwtAuthenticator.NewWithAccessToken(*c, token)
	default:
		return nil, fmt.Errorf(log.CAKC064)
	}
}
