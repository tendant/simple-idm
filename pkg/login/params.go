package login

// MessageDeliveryOption represents an option for message delivery
type MessageDeliveryOption struct {
	DisplayValue string
	HashedValue  string
}

// ACCESS_TOKEN_NAME defines the name of the access token cookie
const ACCESS_TOKEN_NAME = "idm_access_token"
