package login

import "github.com/tendant/simple-idm/pkg/twofa"

type Option func(*Handle)

func WithTwoFactorService(twoFactorService twofa.TwoFactorService) Option {
	return func(h *Handle) {
		h.twoFactorService = twoFactorService
	}
}
