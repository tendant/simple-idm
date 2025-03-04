package login

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestCheckPasswordHash(t *testing.T) {
	// Test cases
	t.Run("ValidPassword", func(t *testing.T) {
		password := "validPassword123"
		hashedPassword, err := HashPassword(password)
		assert.NoError(t, err)

		match, err := CheckPasswordHash(password, hashedPassword)
		assert.NoError(t, err)
		assert.True(t, match, "The password should match the hashed password")
	})

	t.Run("EmptyPassword", func(t *testing.T) {
		password := ""
		hashedPassword := ""

		match, err := CheckPasswordHash(password, hashedPassword)
		assert.Error(t, err)
		assert.False(t, match, "Empty password and hash should not match")
	})

	t.Run("EmptyHashedPassword", func(t *testing.T) {
		password := "somePassword"
		hashedPassword := ""

		match, err := CheckPasswordHash(password, hashedPassword)
		assert.Error(t, err)
		assert.False(t, match, "A valid password and empty hash should not match")
	})

	t.Run("IncorrectPassword", func(t *testing.T) {
		password := "correctPassword"
		hashedPassword, err := HashPassword(password)
		assert.NoError(t, err)

		incorrectPassword := "incorrectPassword"
		match, err := CheckPasswordHash(incorrectPassword, hashedPassword)
		assert.Error(t, err)
		assert.False(t, match, "Incorrect password should not match the hashed password")
	})

	t.Run("CorruptedHashedPassword", func(t *testing.T) {
		password := "correctPassword"
		corruptedHash := "invalidHash"

		match, err := CheckPasswordHash(password, corruptedHash)
		assert.Error(t, err)
		assert.False(t, match, "Corrupted hashed password should not match")
	})

	t.Run("GeneratedHashNotEmpty", func(t *testing.T) {
		password := "myPassword"
		hashedPassword, err := HashPassword(password)
		assert.NoError(t, err)
		assert.NotEmpty(t, hashedPassword, "Hashed password should not be empty")
	})
}
