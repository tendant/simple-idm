package jwks

import (
	"context"
	"fmt"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
)

// PostgresJWKSRepository implements JWKSRepository using PostgreSQL
type PostgresJWKSRepository struct {
	db *pgxpool.Pool
}

// NewPostgresJWKSRepository creates a new PostgreSQL JWKS repository
func NewPostgresJWKSRepository(db *pgxpool.Pool) (*PostgresJWKSRepository, error) {
	if db == nil {
		return nil, fmt.Errorf("database connection cannot be nil")
	}

	return &PostgresJWKSRepository{
		db: db,
	}, nil
}

// GetKeyStore retrieves the entire key store
func (r *PostgresJWKSRepository) GetKeyStore(ctx context.Context) (*KeyStore, error) {
	keys, err := r.ListKeys(ctx)
	if err != nil {
		return nil, fmt.Errorf("failed to list keys for key store: %w", err)
	}

	keyStore := &KeyStore{
		Keys: make([]KeyPair, len(keys)),
	}

	for i, key := range keys {
		keyStore.Keys[i] = *key
	}

	return keyStore, nil
}

// SaveKeyStore saves the entire key store
func (r *PostgresJWKSRepository) SaveKeyStore(ctx context.Context, keyStore *KeyStore) error {
	// Start transaction
	tx, err := r.db.Begin(ctx)
	if err != nil {
		return fmt.Errorf("failed to begin transaction: %w", err)
	}
	defer tx.Rollback(ctx)

	// Clear existing keys
	_, err = tx.Exec(ctx, "DELETE FROM jwks_keys")
	if err != nil {
		return fmt.Errorf("failed to clear existing keys: %w", err)
	}

	// Insert all keys from the key store
	for _, keyPair := range keyStore.Keys {
		err = r.insertKeyWithTx(ctx, tx, &keyPair)
		if err != nil {
			return fmt.Errorf("failed to insert key %s: %w", keyPair.Kid, err)
		}
	}

	if err := tx.Commit(ctx); err != nil {
		return fmt.Errorf("failed to commit transaction: %w", err)
	}

	return nil
}

// GetKeyByID retrieves a key pair by its ID
func (r *PostgresJWKSRepository) GetKeyByID(ctx context.Context, kid string) (*KeyPair, error) {
	query := `
		SELECT kid, alg, private_key_pem, public_key_pem, created_at, updated_at, active
		FROM jwks_keys 
		WHERE kid = $1
	`

	var keyPair KeyPair
	var createdAt, updatedAt time.Time
	var privateKeyPEM, publicKeyPEM string

	err := r.db.QueryRow(ctx, query, kid).Scan(
		&keyPair.Kid,
		&keyPair.Alg,
		&privateKeyPEM,
		&publicKeyPEM,
		&createdAt,
		&updatedAt,
		&keyPair.Active,
	)

	if err != nil {
		if err == pgx.ErrNoRows {
			return nil, fmt.Errorf("key not found: %s", kid)
		}
		return nil, fmt.Errorf("failed to get key: %w", err)
	}

	// Set timestamps directly
	keyPair.CreatedAt = createdAt
	keyPair.UpdatedAt = updatedAt

	// Decode PEM keys
	privateKey, err := DecodePrivateKeyFromPEM(privateKeyPEM)
	if err != nil {
		return nil, fmt.Errorf("failed to decode private key: %w", err)
	}
	keyPair.PrivateKey = privateKey

	publicKey, err := DecodePublicKeyFromPEM(publicKeyPEM)
	if err != nil {
		return nil, fmt.Errorf("failed to decode public key: %w", err)
	}
	keyPair.PublicKey = publicKey

	return &keyPair, nil
}

// GetActiveKey retrieves the currently active signing key
func (r *PostgresJWKSRepository) GetActiveKey(ctx context.Context) (*KeyPair, error) {
	query := `
		SELECT kid, alg, private_key_pem, public_key_pem, created_at, updated_at, active
		FROM jwks_keys 
		WHERE active = true
		LIMIT 1
	`

	var keyPair KeyPair
	var createdAt, updatedAt time.Time
	var privateKeyPEM, publicKeyPEM string

	err := r.db.QueryRow(ctx, query).Scan(
		&keyPair.Kid,
		&keyPair.Alg,
		&privateKeyPEM,
		&publicKeyPEM,
		&createdAt,
		&updatedAt,
		&keyPair.Active,
	)

	if err != nil {
		if err == pgx.ErrNoRows {
			return nil, fmt.Errorf("no active key found")
		}
		return nil, fmt.Errorf("failed to get active key: %w", err)
	}

	// Convert timestamps to Unix timestamps
	keyPair.CreatedAt = createdAt
	keyPair.UpdatedAt = updatedAt

	// Decode PEM keys
	privateKey, err := DecodePrivateKeyFromPEM(privateKeyPEM)
	if err != nil {
		return nil, fmt.Errorf("failed to decode private key: %w", err)
	}
	keyPair.PrivateKey = privateKey

	publicKey, err := DecodePublicKeyFromPEM(publicKeyPEM)
	if err != nil {
		return nil, fmt.Errorf("failed to decode public key: %w", err)
	}
	keyPair.PublicKey = publicKey

	return &keyPair, nil
}

// AddKey adds a new key pair to the store
func (r *PostgresJWKSRepository) AddKey(ctx context.Context, keyPair *KeyPair) error {
	// Check if key already exists
	exists, err := r.KeyExists(ctx, keyPair.Kid)
	if err != nil {
		return fmt.Errorf("failed to check key existence: %w", err)
	}
	if exists {
		return fmt.Errorf("key already exists: %s", keyPair.Kid)
	}

	return r.insertKey(ctx, keyPair)
}

// UpdateKey updates an existing key pair
func (r *PostgresJWKSRepository) UpdateKey(ctx context.Context, keyPair *KeyPair) error {
	// Check if key exists
	exists, err := r.KeyExists(ctx, keyPair.Kid)
	if err != nil {
		return fmt.Errorf("failed to check key existence: %w", err)
	}
	if !exists {
		return fmt.Errorf("key not found: %s", keyPair.Kid)
	}

	// Encode keys to PEM
	privateKeyPEM := EncodePrivateKeyToPEM(keyPair.PrivateKey)
	publicKeyPEM := EncodePublicKeyToPEM(keyPair.PublicKey)

	query := `
		UPDATE jwks_keys 
		SET alg = $2, private_key_pem = $3, public_key_pem = $4, 
		    updated_at = (NOW() AT TIME ZONE 'UTC'), active = $5
		WHERE kid = $1
	`

	_, err = r.db.Exec(ctx, query, keyPair.Kid, keyPair.Alg, privateKeyPEM, publicKeyPEM, keyPair.Active)
	if err != nil {
		return fmt.Errorf("failed to update key: %w", err)
	}

	return nil
}

// DeleteKey removes a key pair by its ID
func (r *PostgresJWKSRepository) DeleteKey(ctx context.Context, kid string) error {
	query := `DELETE FROM jwks_keys WHERE kid = $1`

	result, err := r.db.Exec(ctx, query, kid)
	if err != nil {
		return fmt.Errorf("failed to delete key: %w", err)
	}

	if result.RowsAffected() == 0 {
		return fmt.Errorf("key not found: %s", kid)
	}

	return nil
}

// SetActiveKey sets a key as active and deactivates others
func (r *PostgresJWKSRepository) SetActiveKey(ctx context.Context, kid string) error {
	// Start transaction
	tx, err := r.db.Begin(ctx)
	if err != nil {
		return fmt.Errorf("failed to begin transaction: %w", err)
	}
	defer tx.Rollback(ctx)

	// Check if key exists
	var exists bool
	err = tx.QueryRow(ctx, "SELECT EXISTS(SELECT 1 FROM jwks_keys WHERE kid = $1)", kid).Scan(&exists)
	if err != nil {
		return fmt.Errorf("failed to check key existence: %w", err)
	}
	if !exists {
		return fmt.Errorf("key not found: %s", kid)
	}

	// Deactivate all keys
	_, err = tx.Exec(ctx, "UPDATE jwks_keys SET active = false, updated_at = (NOW() AT TIME ZONE 'UTC')")
	if err != nil {
		return fmt.Errorf("failed to deactivate keys: %w", err)
	}

	// Activate the specified key
	_, err = tx.Exec(ctx, "UPDATE jwks_keys SET active = true, updated_at = (NOW() AT TIME ZONE 'UTC') WHERE kid = $1", kid)
	if err != nil {
		return fmt.Errorf("failed to activate key: %w", err)
	}

	if err := tx.Commit(ctx); err != nil {
		return fmt.Errorf("failed to commit transaction: %w", err)
	}

	return nil
}

// ListKeys returns all key pairs
func (r *PostgresJWKSRepository) ListKeys(ctx context.Context) ([]*KeyPair, error) {
	query := `
		SELECT kid, alg, private_key_pem, public_key_pem, created_at, updated_at, active
		FROM jwks_keys 
		ORDER BY created_at DESC
	`

	rows, err := r.db.Query(ctx, query)
	if err != nil {
		return nil, fmt.Errorf("failed to list keys: %w", err)
	}
	defer rows.Close()

	var keys []*KeyPair
	for rows.Next() {
		var keyPair KeyPair
		var createdAt, updatedAt time.Time
		var privateKeyPEM, publicKeyPEM string

		err := rows.Scan(
			&keyPair.Kid,
			&keyPair.Alg,
			&privateKeyPEM,
			&publicKeyPEM,
			&createdAt,
			&updatedAt,
			&keyPair.Active,
		)
		if err != nil {
			return nil, fmt.Errorf("failed to scan key row: %w", err)
		}

		// Convert timestamps to Unix timestamps
		keyPair.CreatedAt = createdAt
		keyPair.UpdatedAt = updatedAt

		// Decode PEM keys
		privateKey, err := DecodePrivateKeyFromPEM(privateKeyPEM)
		if err != nil {
			return nil, fmt.Errorf("failed to decode private key for key %s: %w", keyPair.Kid, err)
		}
		keyPair.PrivateKey = privateKey

		publicKey, err := DecodePublicKeyFromPEM(publicKeyPEM)
		if err != nil {
			return nil, fmt.Errorf("failed to decode public key for key %s: %w", keyPair.Kid, err)
		}
		keyPair.PublicKey = publicKey

		keys = append(keys, &keyPair)
	}

	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("error iterating over key rows: %w", err)
	}

	return keys, nil
}

// GetKeysByStatus returns keys filtered by active status
func (r *PostgresJWKSRepository) GetKeysByStatus(ctx context.Context, active bool) ([]*KeyPair, error) {
	query := `
		SELECT kid, alg, private_key_pem, public_key_pem, created_at, updated_at, active
		FROM jwks_keys 
		WHERE active = $1
		ORDER BY created_at DESC
	`

	rows, err := r.db.Query(ctx, query, active)
	if err != nil {
		return nil, fmt.Errorf("failed to get keys by status: %w", err)
	}
	defer rows.Close()

	var keys []*KeyPair
	for rows.Next() {
		var keyPair KeyPair
		var createdAt, updatedAt time.Time
		var privateKeyPEM, publicKeyPEM string

		err := rows.Scan(
			&keyPair.Kid,
			&keyPair.Alg,
			&privateKeyPEM,
			&publicKeyPEM,
			&createdAt,
			&updatedAt,
			&keyPair.Active,
		)
		if err != nil {
			return nil, fmt.Errorf("failed to scan key row: %w", err)
		}

		// Set timestamps directly
		keyPair.CreatedAt = createdAt
		keyPair.UpdatedAt = updatedAt

		// Decode PEM keys
		privateKey, err := DecodePrivateKeyFromPEM(privateKeyPEM)
		if err != nil {
			return nil, fmt.Errorf("failed to decode private key for key %s: %w", keyPair.Kid, err)
		}
		keyPair.PrivateKey = privateKey

		publicKey, err := DecodePublicKeyFromPEM(publicKeyPEM)
		if err != nil {
			return nil, fmt.Errorf("failed to decode public key for key %s: %w", keyPair.Kid, err)
		}
		keyPair.PublicKey = publicKey

		keys = append(keys, &keyPair)
	}

	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("error iterating over key rows: %w", err)
	}

	return keys, nil
}

// GetKeysOlderThan returns keys created before the specified time
func (r *PostgresJWKSRepository) GetKeysOlderThan(ctx context.Context, cutoffTime time.Time) ([]*KeyPair, error) {
	query := `
		SELECT kid, alg, private_key_pem, public_key_pem, created_at, updated_at, active
		FROM jwks_keys 
		WHERE created_at < $1
		ORDER BY created_at DESC
	`

	rows, err := r.db.Query(ctx, query, cutoffTime)
	if err != nil {
		return nil, fmt.Errorf("failed to get keys older than cutoff: %w", err)
	}
	defer rows.Close()

	var keys []*KeyPair
	for rows.Next() {
		var keyPair KeyPair
		var createdAt, updatedAt time.Time
		var privateKeyPEM, publicKeyPEM string

		err := rows.Scan(
			&keyPair.Kid,
			&keyPair.Alg,
			&privateKeyPEM,
			&publicKeyPEM,
			&createdAt,
			&updatedAt,
			&keyPair.Active,
		)
		if err != nil {
			return nil, fmt.Errorf("failed to scan key row: %w", err)
		}

		// Set timestamps directly
		keyPair.CreatedAt = createdAt
		keyPair.UpdatedAt = updatedAt

		// Decode PEM keys
		privateKey, err := DecodePrivateKeyFromPEM(privateKeyPEM)
		if err != nil {
			return nil, fmt.Errorf("failed to decode private key for key %s: %w", keyPair.Kid, err)
		}
		keyPair.PrivateKey = privateKey

		publicKey, err := DecodePublicKeyFromPEM(publicKeyPEM)
		if err != nil {
			return nil, fmt.Errorf("failed to decode public key for key %s: %w", keyPair.Kid, err)
		}
		keyPair.PublicKey = publicKey

		keys = append(keys, &keyPair)
	}

	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("error iterating over key rows: %w", err)
	}

	return keys, nil
}

// GetKeyCount returns the total number of keys
func (r *PostgresJWKSRepository) GetKeyCount(ctx context.Context) (int64, error) {
	var count int64
	err := r.db.QueryRow(ctx, "SELECT COUNT(*) FROM jwks_keys").Scan(&count)
	if err != nil {
		return 0, fmt.Errorf("failed to get key count: %w", err)
	}
	return count, nil
}

// CleanupOldKeys removes keys older than the specified duration, preserving active keys
func (r *PostgresJWKSRepository) CleanupOldKeys(ctx context.Context, maxAge time.Duration) error {
	cutoffTime := time.Now().Add(-maxAge)

	query := `
		DELETE FROM jwks_keys 
		WHERE created_at < $1 AND active = false
	`

	result, err := r.db.Exec(ctx, query, cutoffTime)
	if err != nil {
		return fmt.Errorf("failed to cleanup old keys: %w", err)
	}

	_ = result.RowsAffected() // We don't need to check the count, cleanup is best effort

	return nil
}

// KeyExists checks if a key with the given ID exists
func (r *PostgresJWKSRepository) KeyExists(ctx context.Context, kid string) (bool, error) {
	var exists bool
	err := r.db.QueryRow(ctx, "SELECT EXISTS(SELECT 1 FROM jwks_keys WHERE kid = $1)", kid).Scan(&exists)
	if err != nil {
		return false, fmt.Errorf("failed to check key existence: %w", err)
	}
	return exists, nil
}

// WithTx returns a new repository instance that uses the provided transaction
func (r *PostgresJWKSRepository) WithTx(tx interface{}) JWKSRepository {
	pgxTx, ok := tx.(pgx.Tx)
	if !ok {
		// Return the same instance if tx is not a pgx.Tx
		return r
	}

	return &PostgresJWKSRepositoryTx{
		tx: pgxTx,
	}
}

// Helper methods

// insertKey inserts a key pair into the database
func (r *PostgresJWKSRepository) insertKey(ctx context.Context, keyPair *KeyPair) error {
	// Generate UUID if kid is empty
	kid := keyPair.Kid
	if kid == "" {
		kid = uuid.New().String()
	}

	// Encode keys to PEM
	privateKeyPEM := EncodePrivateKeyToPEM(keyPair.PrivateKey)
	publicKeyPEM := EncodePublicKeyToPEM(keyPair.PublicKey)

	query := `
		INSERT INTO jwks_keys (kid, alg, private_key_pem, public_key_pem, active)
		VALUES ($1, $2, $3, $4, $5)
	`

	_, err := r.db.Exec(ctx, query, kid, keyPair.Alg, privateKeyPEM, publicKeyPEM, keyPair.Active)
	if err != nil {
		return fmt.Errorf("failed to insert key: %w", err)
	}

	// Update the keyPair with the generated kid
	keyPair.Kid = kid

	return nil
}

// insertKeyWithTx inserts a key pair using a transaction
func (r *PostgresJWKSRepository) insertKeyWithTx(ctx context.Context, tx pgx.Tx, keyPair *KeyPair) error {
	// Generate UUID if kid is empty
	kid := keyPair.Kid
	if kid == "" {
		kid = uuid.New().String()
	}

	// Encode keys to PEM
	privateKeyPEM := EncodePrivateKeyToPEM(keyPair.PrivateKey)
	publicKeyPEM := EncodePublicKeyToPEM(keyPair.PublicKey)

	// Use time.Time values directly
	var createdAt, updatedAt time.Time
	if !keyPair.CreatedAt.IsZero() {
		createdAt = keyPair.CreatedAt.UTC()
	} else {
		createdAt = time.Now().UTC()
	}
	if !keyPair.UpdatedAt.IsZero() {
		updatedAt = keyPair.UpdatedAt.UTC()
	} else {
		updatedAt = createdAt
	}

	query := `
		INSERT INTO jwks_keys (kid, alg, private_key_pem, public_key_pem, created_at, updated_at, active)
		VALUES ($1, $2, $3, $4, $5, $6, $7)
	`

	_, err := tx.Exec(ctx, query, kid, keyPair.Alg, privateKeyPEM, publicKeyPEM, createdAt, updatedAt, keyPair.Active)
	if err != nil {
		return fmt.Errorf("failed to insert key with transaction: %w", err)
	}

	// Update the keyPair with the generated kid
	keyPair.Kid = kid

	return nil
}

// PostgresJWKSRepositoryTx implements JWKSRepository using a PostgreSQL transaction
type PostgresJWKSRepositoryTx struct {
	tx pgx.Tx
}

// GetKeyStore retrieves the entire key store using transaction
func (r *PostgresJWKSRepositoryTx) GetKeyStore(ctx context.Context) (*KeyStore, error) {
	keys, err := r.ListKeys(ctx)
	if err != nil {
		return nil, fmt.Errorf("failed to list keys for key store: %w", err)
	}

	keyStore := &KeyStore{
		Keys: make([]KeyPair, len(keys)),
	}

	for i, key := range keys {
		keyStore.Keys[i] = *key
	}

	return keyStore, nil
}

// SaveKeyStore saves the entire key store using transaction
func (r *PostgresJWKSRepositoryTx) SaveKeyStore(ctx context.Context, keyStore *KeyStore) error {
	// Clear existing keys
	_, err := r.tx.Exec(ctx, "DELETE FROM jwks_keys")
	if err != nil {
		return fmt.Errorf("failed to clear existing keys: %w", err)
	}

	// Insert all keys from the key store
	for _, keyPair := range keyStore.Keys {
		err = r.insertKeyWithTx(ctx, &keyPair)
		if err != nil {
			return fmt.Errorf("failed to insert key %s: %w", keyPair.Kid, err)
		}
	}

	return nil
}

// GetKeyByID retrieves a key pair by its ID using transaction
func (r *PostgresJWKSRepositoryTx) GetKeyByID(ctx context.Context, kid string) (*KeyPair, error) {
	query := `
		SELECT kid, alg, private_key_pem, public_key_pem, created_at, updated_at, active
		FROM jwks_keys 
		WHERE kid = $1
	`

	var keyPair KeyPair
	var createdAt, updatedAt time.Time
	var privateKeyPEM, publicKeyPEM string

	err := r.tx.QueryRow(ctx, query, kid).Scan(
		&keyPair.Kid,
		&keyPair.Alg,
		&privateKeyPEM,
		&publicKeyPEM,
		&createdAt,
		&updatedAt,
		&keyPair.Active,
	)

	if err != nil {
		if err == pgx.ErrNoRows {
			return nil, fmt.Errorf("key not found: %s", kid)
		}
		return nil, fmt.Errorf("failed to get key: %w", err)
	}

	// Convert timestamps to Unix timestamps
	keyPair.CreatedAt = createdAt
	keyPair.UpdatedAt = updatedAt
	// Decode PEM keys
	privateKey, err := DecodePrivateKeyFromPEM(privateKeyPEM)
	if err != nil {
		return nil, fmt.Errorf("failed to decode private key: %w", err)
	}
	keyPair.PrivateKey = privateKey

	publicKey, err := DecodePublicKeyFromPEM(publicKeyPEM)
	if err != nil {
		return nil, fmt.Errorf("failed to decode public key: %w", err)
	}
	keyPair.PublicKey = publicKey

	return &keyPair, nil
}

// GetActiveKey retrieves the currently active signing key using transaction
func (r *PostgresJWKSRepositoryTx) GetActiveKey(ctx context.Context) (*KeyPair, error) {
	query := `
		SELECT kid, alg, private_key_pem, public_key_pem, created_at, updated_at, active
		FROM jwks_keys 
		WHERE active = true
		LIMIT 1
	`

	var keyPair KeyPair
	var createdAt, updatedAt time.Time
	var privateKeyPEM, publicKeyPEM string

	err := r.tx.QueryRow(ctx, query).Scan(
		&keyPair.Kid,
		&keyPair.Alg,
		&privateKeyPEM,
		&publicKeyPEM,
		&createdAt,
		&updatedAt,
		&keyPair.Active,
	)

	if err != nil {
		if err == pgx.ErrNoRows {
			return nil, fmt.Errorf("no active key found")
		}
		return nil, fmt.Errorf("failed to get active key: %w", err)
	}

	// Convert timestamps to Unix timestamps
	keyPair.CreatedAt = createdAt
	keyPair.UpdatedAt = updatedAt

	// Decode PEM keys
	privateKey, err := DecodePrivateKeyFromPEM(privateKeyPEM)
	if err != nil {
		return nil, fmt.Errorf("failed to decode private key: %w", err)
	}
	keyPair.PrivateKey = privateKey

	publicKey, err := DecodePublicKeyFromPEM(publicKeyPEM)
	if err != nil {
		return nil, fmt.Errorf("failed to decode public key: %w", err)
	}
	keyPair.PublicKey = publicKey

	return &keyPair, nil
}

// AddKey adds a new key pair to the store using transaction
func (r *PostgresJWKSRepositoryTx) AddKey(ctx context.Context, keyPair *KeyPair) error {
	// Check if key already exists
	exists, err := r.KeyExists(ctx, keyPair.Kid)
	if err != nil {
		return fmt.Errorf("failed to check key existence: %w", err)
	}
	if exists {
		return fmt.Errorf("key already exists: %s", keyPair.Kid)
	}

	return r.insertKeyWithTx(ctx, keyPair)
}

// UpdateKey updates an existing key pair using transaction
func (r *PostgresJWKSRepositoryTx) UpdateKey(ctx context.Context, keyPair *KeyPair) error {
	// Check if key exists
	exists, err := r.KeyExists(ctx, keyPair.Kid)
	if err != nil {
		return fmt.Errorf("failed to check key existence: %w", err)
	}
	if !exists {
		return fmt.Errorf("key not found: %s", keyPair.Kid)
	}

	// Encode keys to PEM
	privateKeyPEM := EncodePrivateKeyToPEM(keyPair.PrivateKey)
	publicKeyPEM := EncodePublicKeyToPEM(keyPair.PublicKey)

	query := `
		UPDATE jwks_keys 
		SET alg = $2, private_key_pem = $3, public_key_pem = $4, 
		    updated_at = (NOW() AT TIME ZONE 'UTC'), active = $5
		WHERE kid = $1
	`

	_, err = r.tx.Exec(ctx, query, keyPair.Kid, keyPair.Alg, privateKeyPEM, publicKeyPEM, keyPair.Active)
	if err != nil {
		return fmt.Errorf("failed to update key: %w", err)
	}

	return nil
}

// DeleteKey removes a key pair by its ID using transaction
func (r *PostgresJWKSRepositoryTx) DeleteKey(ctx context.Context, kid string) error {
	query := `DELETE FROM jwks_keys WHERE kid = $1`

	result, err := r.tx.Exec(ctx, query, kid)
	if err != nil {
		return fmt.Errorf("failed to delete key: %w", err)
	}

	if result.RowsAffected() == 0 {
		return fmt.Errorf("key not found: %s", kid)
	}

	return nil
}

// SetActiveKey sets a key as active and deactivates others using transaction
func (r *PostgresJWKSRepositoryTx) SetActiveKey(ctx context.Context, kid string) error {
	// Check if key exists
	var exists bool
	err := r.tx.QueryRow(ctx, "SELECT EXISTS(SELECT 1 FROM jwks_keys WHERE kid = $1)", kid).Scan(&exists)
	if err != nil {
		return fmt.Errorf("failed to check key existence: %w", err)
	}
	if !exists {
		return fmt.Errorf("key not found: %s", kid)
	}

	// Deactivate all keys
	_, err = r.tx.Exec(ctx, "UPDATE jwks_keys SET active = false, updated_at = (NOW() AT TIME ZONE 'UTC')")
	if err != nil {
		return fmt.Errorf("failed to deactivate keys: %w", err)
	}

	// Activate the specified key
	_, err = r.tx.Exec(ctx, "UPDATE jwks_keys SET active = true, updated_at = (NOW() AT TIME ZONE 'UTC') WHERE kid = $1", kid)
	if err != nil {
		return fmt.Errorf("failed to activate key: %w", err)
	}

	return nil
}

// ListKeys returns all key pairs using transaction
func (r *PostgresJWKSRepositoryTx) ListKeys(ctx context.Context) ([]*KeyPair, error) {
	query := `
		SELECT kid, alg, private_key_pem, public_key_pem, created_at, updated_at, active
		FROM jwks_keys 
		ORDER BY created_at DESC
	`

	rows, err := r.tx.Query(ctx, query)
	if err != nil {
		return nil, fmt.Errorf("failed to list keys: %w", err)
	}
	defer rows.Close()

	var keys []*KeyPair
	for rows.Next() {
		var keyPair KeyPair
		var createdAt, updatedAt time.Time
		var privateKeyPEM, publicKeyPEM string

		err := rows.Scan(
			&keyPair.Kid,
			&keyPair.Alg,
			&privateKeyPEM,
			&publicKeyPEM,
			&createdAt,
			&updatedAt,
			&keyPair.Active,
		)
		if err != nil {
			return nil, fmt.Errorf("failed to scan key row: %w", err)
		}

		// Convert timestamps to Unix timestamps
		keyPair.CreatedAt = createdAt
		keyPair.UpdatedAt = updatedAt

		// Decode PEM keys
		privateKey, err := DecodePrivateKeyFromPEM(privateKeyPEM)
		if err != nil {
			return nil, fmt.Errorf("failed to decode private key for key %s: %w", keyPair.Kid, err)
		}
		keyPair.PrivateKey = privateKey

		publicKey, err := DecodePublicKeyFromPEM(publicKeyPEM)
		if err != nil {
			return nil, fmt.Errorf("failed to decode public key for key %s: %w", keyPair.Kid, err)
		}
		keyPair.PublicKey = publicKey

		keys = append(keys, &keyPair)
	}

	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("error iterating over key rows: %w", err)
	}

	return keys, nil
}

// GetKeysByStatus returns keys filtered by active status using transaction
func (r *PostgresJWKSRepositoryTx) GetKeysByStatus(ctx context.Context, active bool) ([]*KeyPair, error) {
	query := `
		SELECT kid, alg, private_key_pem, public_key_pem, created_at, updated_at, active
		FROM jwks_keys 
		WHERE active = $1
		ORDER BY created_at DESC
	`

	rows, err := r.tx.Query(ctx, query, active)
	if err != nil {
		return nil, fmt.Errorf("failed to get keys by status: %w", err)
	}
	defer rows.Close()

	var keys []*KeyPair
	for rows.Next() {
		var keyPair KeyPair
		var createdAt, updatedAt time.Time
		var privateKeyPEM, publicKeyPEM string

		err := rows.Scan(
			&keyPair.Kid,
			&keyPair.Alg,
			&privateKeyPEM,
			&publicKeyPEM,
			&createdAt,
			&updatedAt,
			&keyPair.Active,
		)
		if err != nil {
			return nil, fmt.Errorf("failed to scan key row: %w", err)
		}

		// Convert timestamps to Unix timestamps
		keyPair.CreatedAt = createdAt
		keyPair.UpdatedAt = updatedAt

		// Decode PEM keys
		privateKey, err := DecodePrivateKeyFromPEM(privateKeyPEM)
		if err != nil {
			return nil, fmt.Errorf("failed to decode private key for key %s: %w", keyPair.Kid, err)
		}
		keyPair.PrivateKey = privateKey

		publicKey, err := DecodePublicKeyFromPEM(publicKeyPEM)
		if err != nil {
			return nil, fmt.Errorf("failed to decode public key for key %s: %w", keyPair.Kid, err)
		}
		keyPair.PublicKey = publicKey

		keys = append(keys, &keyPair)
	}

	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("error iterating over key rows: %w", err)
	}

	return keys, nil
}

// GetKeysOlderThan returns keys created before the specified time using transaction
func (r *PostgresJWKSRepositoryTx) GetKeysOlderThan(ctx context.Context, cutoffTime time.Time) ([]*KeyPair, error) {
	query := `
		SELECT kid, alg, private_key_pem, public_key_pem, created_at, updated_at, active
		FROM jwks_keys 
		WHERE created_at < $1
		ORDER BY created_at DESC
	`

	rows, err := r.tx.Query(ctx, query, cutoffTime)
	if err != nil {
		return nil, fmt.Errorf("failed to get keys older than cutoff: %w", err)
	}
	defer rows.Close()

	var keys []*KeyPair
	for rows.Next() {
		var keyPair KeyPair
		var createdAt, updatedAt time.Time
		var privateKeyPEM, publicKeyPEM string

		err := rows.Scan(
			&keyPair.Kid,
			&keyPair.Alg,
			&privateKeyPEM,
			&publicKeyPEM,
			&createdAt,
			&updatedAt,
			&keyPair.Active,
		)
		if err != nil {
			return nil, fmt.Errorf("failed to scan key row: %w", err)
		}

		// Convert timestamps to Unix timestamps
		keyPair.CreatedAt = createdAt
		keyPair.UpdatedAt = updatedAt

		// Decode PEM keys
		privateKey, err := DecodePrivateKeyFromPEM(privateKeyPEM)
		if err != nil {
			return nil, fmt.Errorf("failed to decode private key for key %s: %w", keyPair.Kid, err)
		}
		keyPair.PrivateKey = privateKey

		publicKey, err := DecodePublicKeyFromPEM(publicKeyPEM)
		if err != nil {
			return nil, fmt.Errorf("failed to decode public key for key %s: %w", keyPair.Kid, err)
		}
		keyPair.PublicKey = publicKey

		keys = append(keys, &keyPair)
	}

	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("error iterating over key rows: %w", err)
	}

	return keys, nil
}

// GetKeyCount returns the total number of keys using transaction
func (r *PostgresJWKSRepositoryTx) GetKeyCount(ctx context.Context) (int64, error) {
	var count int64
	err := r.tx.QueryRow(ctx, "SELECT COUNT(*) FROM jwks_keys").Scan(&count)
	if err != nil {
		return 0, fmt.Errorf("failed to get key count: %w", err)
	}
	return count, nil
}

// CleanupOldKeys removes keys older than the specified duration, preserving active keys using transaction
func (r *PostgresJWKSRepositoryTx) CleanupOldKeys(ctx context.Context, maxAge time.Duration) error {
	cutoffTime := time.Now().Add(-maxAge)

	query := `
		DELETE FROM jwks_keys 
		WHERE created_at < $1 AND active = false
	`

	result, err := r.tx.Exec(ctx, query, cutoffTime)
	if err != nil {
		return fmt.Errorf("failed to cleanup old keys: %w", err)
	}

	_ = result.RowsAffected() // We don't need to check the count, cleanup is best effort

	return nil
}

// KeyExists checks if a key with the given ID exists using transaction
func (r *PostgresJWKSRepositoryTx) KeyExists(ctx context.Context, kid string) (bool, error) {
	var exists bool
	err := r.tx.QueryRow(ctx, "SELECT EXISTS(SELECT 1 FROM jwks_keys WHERE kid = $1)", kid).Scan(&exists)
	if err != nil {
		return false, fmt.Errorf("failed to check key existence: %w", err)
	}
	return exists, nil
}

// WithTx returns a new repository instance that uses the provided transaction
func (r *PostgresJWKSRepositoryTx) WithTx(tx interface{}) JWKSRepository {
	pgxTx, ok := tx.(pgx.Tx)
	if !ok {
		// Return the same instance if tx is not a pgx.Tx
		return r
	}

	return &PostgresJWKSRepositoryTx{
		tx: pgxTx,
	}
}

// Helper method for transaction repository

// insertKeyWithTx inserts a key pair using a transaction
func (r *PostgresJWKSRepositoryTx) insertKeyWithTx(ctx context.Context, keyPair *KeyPair) error {
	// Generate UUID if kid is empty
	kid := keyPair.Kid
	if kid == "" {
		kid = uuid.New().String()
	}

	// Encode keys to PEM
	privateKeyPEM := EncodePrivateKeyToPEM(keyPair.PrivateKey)
	publicKeyPEM := EncodePublicKeyToPEM(keyPair.PublicKey)

	// Use time.Time values directly
	var createdAt, updatedAt time.Time
	if !keyPair.CreatedAt.IsZero() {
		createdAt = keyPair.CreatedAt.UTC()
	} else {
		createdAt = time.Now().UTC()
	}
	if !keyPair.UpdatedAt.IsZero() {
		updatedAt = keyPair.UpdatedAt.UTC()
	} else {
		updatedAt = createdAt
	}

	query := `
		INSERT INTO jwks_keys (kid, alg, private_key_pem, public_key_pem, created_at, updated_at, active)
		VALUES ($1, $2, $3, $4, $5, $6, $7)
	`

	_, err := r.tx.Exec(ctx, query, kid, keyPair.Alg, privateKeyPEM, publicKeyPEM, createdAt, updatedAt, keyPair.Active)
	if err != nil {
		return fmt.Errorf("failed to insert key with transaction: %w", err)
	}

	// Update the keyPair with the generated kid
	keyPair.Kid = kid

	return nil
}
