package handlers

import (
	"strings"

	"github.com/cyberark/conjur-authn-k8s-client/pkg/access_token"

	"github.com/cyberark/cyberark-secrets-provider-for-k8s/pkg/log"
	secretsConfig "github.com/cyberark/cyberark-secrets-provider-for-k8s/pkg/secrets/config"
	"github.com/cyberark/cyberark-secrets-provider-for-k8s/pkg/secrets/conjur"
	"github.com/cyberark/cyberark-secrets-provider-for-k8s/pkg/secrets/k8s"
)

type SecretsHandlerK8sUseCase struct {
	AccessToken            access_token.AccessToken
	ConjurSecretsRetriever conjur.ConjurSecretsRetriever
	K8sSecretsHandler      k8s.K8sSecretsHandler
}

func NewSecretHandlerK8sUseCase(secretsConfig secretsConfig.Config, AccessToken access_token.AccessToken) (SecretsHandler *SecretsHandlerK8sUseCase, err error) {
	k8sSecretsHandler, err := k8s.New(secretsConfig)
	if err != nil {
		return nil, log.RecorderError(log.CSPFK022E)
	}

	accessToken, err := AccessToken.Read()
	if err != nil {
		return nil, log.RecorderError(log.CSPFK024E)
	}

	conjurSecretsRetriever, err := conjur.NewConjurSecretsRetriever(accessToken)
	if err != nil {
		return nil, log.RecorderError(log.CSPFK069E)
	}

	return &SecretsHandlerK8sUseCase{
		AccessToken:            AccessToken,
		ConjurSecretsRetriever: *conjurSecretsRetriever,
		K8sSecretsHandler:      *k8sSecretsHandler,
	}, nil
}

func (secretsHandlerK8sUseCase SecretsHandlerK8sUseCase) HandleSecrets() error {
	k8sSecretsMap, err := secretsHandlerK8sUseCase.K8sSecretsHandler.RetrieveK8sSecrets()
	if err != nil {
		return log.RecorderError(log.CSPFK023E)
	}

	variableIDs, err := getVariableIDsToRetrieve(k8sSecretsMap.PathMap)
	if err != nil {
		return log.RecorderError(log.CSPFK025E)
	}

	retrievedConjurSecrets, err := secretsHandlerK8sUseCase.ConjurSecretsRetriever.RetrieveConjurSecrets(variableIDs)
	if err != nil {
		return log.RecorderError(log.CSPFK026E)
	}

	err = updateK8sSecretsMapWithConjurSecrets(k8sSecretsMap, retrievedConjurSecrets)
	if err != nil {
		return log.RecorderError(log.CSPFK027E)
	}

	err = secretsHandlerK8sUseCase.K8sSecretsHandler.PatchK8sSecrets(k8sSecretsMap)
	if err != nil {
		return log.RecorderError(log.CSPFK028E)
	}

	return nil
}

func getVariableIDsToRetrieve(pathMap map[string][]string) ([]string, error) {
	var variableIDs []string

	if len(pathMap) == 0 {
		return nil, log.RecorderError(log.CSPFK029E)
	}

	for key, _ := range pathMap {
		variableIDs = append(variableIDs, key)
	}

	return variableIDs, nil
}

func updateK8sSecretsMapWithConjurSecrets(k8sSecretsMap *k8s.K8sSecretsMap, conjurSecrets map[string][]byte) error {
	var err error

	// Update K8s map by replacing variable IDs with their corresponding secret values
	for variableId, secret := range conjurSecrets {
		variableId, err = parseVariableID(variableId)
		if err != nil {
			return log.RecorderError(log.CSPFK030E)
		}

		for _, locationInK8sSecretsMap := range k8sSecretsMap.PathMap[variableId] {
			locationInK8sSecretsMap := strings.Split(locationInK8sSecretsMap, ":")
			k8sSecretName := locationInK8sSecretsMap[0]
			k8sSecretDataEntryKey := locationInK8sSecretsMap[1]
			k8sSecretsMap.K8sSecrets[k8sSecretName][k8sSecretDataEntryKey] = secret
		}
	}

	return nil
}

// The variable ID is in the format "<account>:variable:<variable_id>. we need only the last part.
func parseVariableID(fullVariableId string) (string, error) {
	variableIdParts := strings.Split(fullVariableId, ":")
	if len(variableIdParts) != 3 {
		return "", log.RecorderError(log.CSPFK031E, fullVariableId)
	}

	return variableIdParts[2], nil
}
