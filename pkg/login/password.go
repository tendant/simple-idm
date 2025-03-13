package login

// HashPassword generates a bcrypt hash from a password string
// func HashPassword(password string) (string, error) {
// 	if password == "" {
// 		return "", errors.New("password cannot be empty")
// 	}

// 	// Use bcrypt with default cost
// 	bytes, err := bcrypt.GenerateFromPassword([]byte(password), bcrypt.DefaultCost)
// 	if err != nil {
// 		return "", fmt.Errorf("failed to hash password: %w", err)
// 	}

// 	return string(bytes), nil
// }

// CheckPasswordHash compares a password with a bcrypt hashed password
// Returns true if they match, false and an error otherwise
// func CheckPasswordHash(password, hashedPassword string) (bool, error) {
// 	// Check for empty values
// 	if password == "" {
// 		return false, errors.New("password cannot be empty")
// 	}

// 	if hashedPassword == "" {
// 		return false, errors.New("hashed password cannot be empty")
// 	}

// 	// Compare the password with the hash
// 	err := bcrypt.CompareHashAndPassword([]byte(hashedPassword), []byte(password))
// 	if err != nil {
// 		if errors.Is(err, bcrypt.ErrMismatchedHashAndPassword) {
// 			return false, errors.New("password does not match")
// 		}
// 		return false, fmt.Errorf("error comparing password: %w", err)
// 	}

// 	return true, nil
// }
