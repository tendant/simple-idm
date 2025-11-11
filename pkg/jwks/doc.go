// Package jwks provides JSON Web Key Set (JWKS) management for JWT token signing and verification.
//
// This package implements RFC 7517 (JSON Web Key) and provides a complete solution for managing
// RSA key pairs used in JWT token signing. It includes automatic key generation, rotation,
// and multiple storage backends.
//
// # Features
//
//   - RSA key pair generation (2048-bit default)
//   - JWKS endpoint support for public key distribution
//   - Key rotation with zero-downtime
//   - Multiple storage backends (in-memory, file-based)
//   - Thread-safe operations with mutex protection
//   - Automatic cleanup of old keys
//
// # Key Concepts
//
// **JWKS (JSON Web Key Set)**: A set of public keys published at a well-known endpoint
// that allows token verifiers to validate JWT signatures without sharing private keys.
//
// **Active Key**: The currently-used key for signing new tokens. Only one key can be
// active at a time, but multiple keys can exist for verification of older tokens.
//
// **Key Rotation**: The process of generating a new key and making it active while
// keeping old keys available for verification during a grace period.
//
// # Basic Usage
//
// ## Quick Start with In-Memory Storage
//
//	import "github.com/tendant/simple-idm/pkg/jwks"
//
//	// Create service with auto-generated key
//	service, err := jwks.NewJWKSServiceWithInMemoryStorage()
//	if err != nil {
//	    log.Fatal(err)
//	}
//
//	// Get active signing key
//	activeKey, err := service.GetActiveSigningKey()
//	if err != nil {
//	    log.Fatal(err)
//	}
//
//	// Use private key for signing JWTs
//	privateKey := activeKey.PrivateKey
//
//	// Get public JWKS for verification endpoint
//	jwks, err := service.GetJWKS()
//	if err != nil {
//	    log.Fatal(err)
//	}
//	// Serve jwks at /.well-known/jwks.json
//
// ## Using an Existing RSA Key
//
//	// Load existing private key from PEM file
//	privateKey, err := jwks.LoadPrivateKeyFromFile("jwt-private.pem")
//	if err != nil {
//	    log.Fatal(err)
//	}
//
//	keyPair := &jwks.KeyPair{
//	    Kid:        "my-key-2024",
//	    Alg:        "RS256",
//	    PrivateKey: privateKey,
//	}
//
//	service, err := jwks.NewJWKSServiceWithKey(keyPair)
//	if err != nil {
//	    log.Fatal(err)
//	}
//
// ## Key Rotation
//
// Rotate keys periodically to enhance security. Old keys remain available for token
// verification during the grace period.
//
//	// Recommended: Rotate keys every 90 days
//	func rotateKeysDaily(service *jwks.JWKSService) {
//	    ticker := time.NewTicker(24 * time.Hour)
//	    defer ticker.Stop()
//
//	    for range ticker.C {
//	        // Check if rotation is needed (e.g., every 90 days)
//	        activeKey, _ := service.GetActiveSigningKey()
//	        if time.Since(activeKey.CreatedAt) > 90*24*time.Hour {
//	            newKey, err := service.RotateKeys()
//	            if err != nil {
//	                log.Printf("Key rotation failed: %v", err)
//	                continue
//	            }
//	            log.Printf("Keys rotated successfully. New active key: %s", newKey.Kid)
//
//	            // Cleanup keys older than 180 days (2x rotation period)
//	            if err := service.CleanupOldKeys(180 * 24 * time.Hour); err != nil {
//	                log.Printf("Cleanup failed: %v", err)
//	            }
//	        }
//	    }
//	}
//
// ## File-Based Persistence
//
// Use file-based storage to persist keys across application restarts:
//
//	import "github.com/tendant/simple-idm/pkg/jwks"
//
//	// Create file repository
//	repository, err := jwks.NewFileJWKSRepository("./keys/jwks.json")
//	if err != nil {
//	    log.Fatal(err)
//	}
//
//	// Check if keys already exist
//	keyStore, _ := repository.GetKeyStore(context.Background())
//	if len(keyStore.Keys) == 0 {
//	    // Generate initial key if none exist
//	    privateKey, _ := jwks.GenerateRSAKeyPair(2048)
//	    keyPair := &jwks.KeyPair{
//	        Kid:        uuid.New().String(),
//	        Alg:        "RS256",
//	        PrivateKey: privateKey,
//	        PublicKey:  &privateKey.PublicKey,
//	        CreatedAt:  time.Now().UTC(),
//	        Active:     true,
//	    }
//	    service, err := jwks.NewJWKSService(repository, keyPair)
//	} else {
//	    // Use existing keys
//	    service := &jwks.JWKSService{Repository: repository}
//	}
//
// # HTTP Integration
//
// Expose JWKS endpoint for token verifiers:
//
//	import (
//	    "encoding/json"
//	    "net/http"
//	)
//
//	func jwksHandler(service *jwks.JWKSService) http.HandlerFunc {
//	    return func(w http.ResponseWriter, r *http.Request) {
//	        jwks, err := service.GetJWKS()
//	        if err != nil {
//	            http.Error(w, "Failed to get JWKS", http.StatusInternalServerError)
//	            return
//	        }
//
//	        w.Header().Set("Content-Type", "application/json")
//	        w.Header().Set("Cache-Control", "public, max-age=3600")
//	        json.NewEncoder(w).Encode(jwks)
//	    }
//	}
//
//	// Register route
//	http.HandleFunc("/.well-known/jwks.json", jwksHandler(service))
//
// # JWT Integration Example
//
// Using with golang-jwt/jwt library:
//
//	import (
//	    "github.com/golang-jwt/jwt/v5"
//	    "github.com/tendant/simple-idm/pkg/jwks"
//	)
//
//	// Signing tokens
//	func signToken(service *jwks.JWKSService, claims jwt.Claims) (string, error) {
//	    activeKey, err := service.GetActiveSigningKey()
//	    if err != nil {
//	        return "", err
//	    }
//
//	    token := jwt.NewWithClaims(jwt.SigningMethodRS256, claims)
//	    token.Header["kid"] = activeKey.Kid
//
//	    return token.SignedString(activeKey.PrivateKey)
//	}
//
//	// Verifying tokens
//	func verifyToken(service *jwks.JWKSService, tokenString string) (*jwt.Token, error) {
//	    return jwt.Parse(tokenString, func(token *jwt.Token) (interface{}, error) {
//	        // Get key ID from token header
//	        kid, ok := token.Header["kid"].(string)
//	        if !ok {
//	            return nil, fmt.Errorf("missing kid in token header")
//	        }
//
//	        // Retrieve public key from JWKS
//	        keyPair, err := service.GetKeyByID(kid)
//	        if err != nil {
//	            return nil, fmt.Errorf("key not found: %w", err)
//	        }
//
//	        return keyPair.PublicKey, nil
//	    })
//	}
//
// # Security Best Practices
//
//  1. **Key Size**: Use at least 2048-bit RSA keys (3072 or 4096 for higher security)
//  2. **Key Rotation**: Rotate keys every 90 days or after suspected compromise
//  3. **Grace Period**: Keep old keys for at least 2x your longest token lifetime
//  4. **Storage**: Protect private keys with filesystem permissions (0600)
//  5. **Backup**: Regularly backup key files to prevent data loss
//  6. **Monitoring**: Log all key operations (generation, rotation, deletion)
//
// # Production Deployment
//
//	// Production-ready setup with file persistence and rotation
//	func setupJWKS(keyFile string) (*jwks.JWKSService, error) {
//	    repository, err := jwks.NewFileJWKSRepository(keyFile)
//	    if err != nil {
//	        return nil, err
//	    }
//
//	    keyStore, err := repository.GetKeyStore(context.Background())
//	    if err != nil {
//	        return nil, err
//	    }
//
//	    var service *jwks.JWKSService
//	    if len(keyStore.Keys) == 0 {
//	        // First-time setup: generate initial key
//	        privateKey, err := jwks.GenerateRSAKeyPair(2048)
//	        if err != nil {
//	            return nil, err
//	        }
//
//	        keyPair := &jwks.KeyPair{
//	            Kid:        uuid.New().String(),
//	            Alg:        "RS256",
//	            PrivateKey: privateKey,
//	            PublicKey:  &privateKey.PublicKey,
//	            CreatedAt:  time.Now().UTC(),
//	            Active:     true,
//	        }
//
//	        service, err = jwks.NewJWKSService(repository, keyPair)
//	        if err != nil {
//	            return nil, err
//	        }
//	        log.Printf("Generated initial JWKS key: %s", keyPair.Kid)
//	    } else {
//	        // Existing keys found
//	        service = &jwks.JWKSService{Repository: repository}
//	        activeKey, err := service.GetActiveSigningKey()
//	        if err != nil {
//	            return nil, err
//	        }
//	        log.Printf("Loaded existing JWKS key: %s", activeKey.Kid)
//	    }
//
//	    // Start background key rotation
//	    go rotateKeysDaily(service)
//
//	    return service, nil
//	}
//
// # Repository Interface
//
// Implement JWKSRepository for custom storage backends:
//
//	type JWKSRepository interface {
//	    GetKeyStore(ctx context.Context) (*KeyStore, error)
//	    SaveKeyStore(ctx context.Context, keyStore *KeyStore) error
//	    GetKeyByID(ctx context.Context, kid string) (*KeyPair, error)
//	    GetActiveKey(ctx context.Context) (*KeyPair, error)
//	    AddKey(ctx context.Context, keyPair *KeyPair) error
//	    SetActiveKey(ctx context.Context, kid string) error
//	    ListKeys(ctx context.Context) ([]*KeyPair, error)
//	    CleanupOldKeys(ctx context.Context, maxAge time.Duration) error
//	    // ... see interface definition for complete list
//	}
//
// Example custom repository (PostgreSQL):
//
//	type PostgresJWKSRepository struct {
//	    db *pgxpool.Pool
//	}
//
//	func (r *PostgresJWKSRepository) GetActiveKey(ctx context.Context) (*KeyPair, error) {
//	    var keyPair KeyPair
//	    // Query active key from database
//	    err := r.db.QueryRow(ctx, "SELECT * FROM jwks_keys WHERE active = true").Scan(&keyPair)
//	    return &keyPair, err
//	}
//	// ... implement remaining interface methods
//
// # Thread Safety
//
// All operations are thread-safe. The in-memory repository uses sync.RWMutex for
// concurrent access protection. Custom repositories should implement their own
// synchronization as needed.
//
// # Error Handling
//
// Common errors:
//   - "key not found": Key with specified ID doesn't exist
//   - "no active key found": No key is marked as active (database inconsistency)
//   - "key already exists": Attempted to add a key with duplicate ID
//   - "failed to generate RSA key pair": Cryptographic operation failed
//
// # Performance Considerations
//
//   - Key generation: ~100-500ms for 2048-bit keys
//   - Key lookup: O(1) with proper indexing, O(n) with in-memory
//   - JWKS endpoint: Cache response for 1 hour (keys rarely change)
//   - Rotation: Non-blocking, doesn't affect ongoing token verification
//
// # Standards Compliance
//
//   - RFC 7517: JSON Web Key (JWK)
//   - RFC 7518: JSON Web Algorithms (JWA)
//   - Supports RS256 algorithm (RSA with SHA-256)
//
package jwks
