# File-Based Persistence Implementation Progress

## Completed Work

### Phase 1: Repository Abstraction for `pkg/logins` ✅

**Files Created:**
- `pkg/logins/repository.go` - Repository interface and PostgreSQL implementation
- `pkg/logins/file_repository.go` - File-based implementation

**Files Modified:**
- `pkg/logins/service.go` - Updated to use `LoginsRepository` interface instead of direct sqlc queries
- `pkg/logins/models.go` - Added `FromLoginEntity()` and `FromLoginEntities()` converters
- `cmd/loginv2/main.go` - Updated to use `NewPostgresLoginsRepository()`
- `cmd/quick/main.go` - Updated to use `NewPostgresLoginsRepository()`

**Key Changes:**
1. Extracted `LoginsRepository` interface with 8 methods
2. Created `PostgresLoginsRepository` wrapping sqlc queries
3. Created `FileLoginsRepository` storing data in JSON files
4. Service now depends on interface, not concrete implementation

### Phase 2: Adapted In-Memory Repositories to File-Based ✅

**Quick Wins - Adapted 4 existing in-memory implementations:**

1. **`pkg/oidc/file_repository.go`** ✅
   - Stores authorization codes and sessions in `oidc.json`
   - 5 interface methods
   - Handles PKCE fields and expiration checks
   - ~280 lines

2. **`pkg/oauth2client/file_repository.go`** ✅
   - Stores OAuth2 clients with metadata in `oauth2_clients.json`
   - 12 interface methods (Get, Create, Update, Delete, List, Validate, Query operations)
   - Includes active/inactive status filtering
   - ~340 lines

3. **`pkg/jwks/file_repository.go`** ✅
   - Stores JWKS KeyStore with key pairs in `jwks.json`
   - 15 interface methods (key management, query, cleanup)
   - Handles key rotation and expiration
   - ~330 lines

4. **`pkg/externalprovider/file_repository.go`** ✅
   - Stores external providers and OAuth2 states in `external_providers.json`
   - 14 interface methods (provider management, state operations)
   - Handles state expiration cleanup
   - ~350 lines

**Total: 4 packages adapted, ~1,300 lines of file-based implementation**

### Phase 2.5: File-Based Implementations for Remaining Packages ✅

**Created file-based implementations for 4 more packages with existing interfaces:**

5. **`pkg/login/file_repository.go`** ✅
   - Stores credentials, password reset tokens, password history, login attempts, magic links in `login.json`
   - 46 interface methods (comprehensive authentication data)
   - Handles complex operations: password history, account locking, magic links
   - ~680 lines

6. **`pkg/device/file_repository.go`** ✅
   - Stores devices and login-device links in `devices.json`
   - 14 interface methods (device tracking and linking)
   - Configurable expiry duration for "remember me" feature
   - ~320 lines

7. **`pkg/delegate/file_repository.go`** ✅
   - Stores delegation relationships in `delegations.json`
   - 1 interface method (FindDelegators) + 2 helper methods
   - Supports user delegation/impersonation
   - ~170 lines

8. **`pkg/emailverification/file_repository.go`** ✅
   - Stores verification tokens and user email status in `email_verification.json`
   - 11 interface methods (token management, verification status)
   - Handles token expiration and cleanup
   - ~340 lines
   - Also created `EmailVerificationRepository` interface (was concrete before)

**Total Phase 2 + 2.5: 9 packages with file-based storage, ~3,110 lines of implementation**

### Phase 3: Repository Interface Extraction for Remaining Packages ✅

**Completed repository interface extraction:**

9. **`pkg/mapper/repository.go`** ✅
   - Extracted `MapperRepository` interface with 3 methods
   - Created domain entity `UserEntity` without database types
   - Implemented `PostgresMapperRepository` wrapping mapperdb.Queries
   - Added conversion helpers for arrays (roles, groups)
   - Updated `DefaultUserMapper` to use repository interface
   - Updated callers in cmd/loginv2, cmd/quick, cmd/login, cmd/passwordless-auth
   - ~210 lines

**Key changes:**
- Repository handles database operations (GetUsersByLoginID, GetUserByUserID, FindUsernamesByEmail)
- UserMapper focuses on business logic and token claims conversion
- Clean separation of concerns between data access and domain logic

10. **`pkg/auth/repository.go`** ✅
   - Extracted `AuthRepository` interface with 2 methods
   - Created domain entity `UserAuthEntity` without database types
   - Implemented `PostgresAuthRepository` wrapping auth/db.Queries
   - Updated `AuthLoginService` to use repository interface
   - ~77 lines
   - Note: AuthLoginService not currently used in main applications (legacy/unused)

### Pattern Established

**Repository Interface Structure:**
```go
type XRepository interface {
    // CRUD operations
    GetX(ctx context.Context, id uuid.UUID) (XEntity, error)
    ListX(ctx context.Context, params ListXParams) ([]XEntity, error)
    CreateX(ctx context.Context, params CreateXParams) (XEntity, error)
    UpdateX(ctx context.Context, params UpdateXParams) (XEntity, error)
    DeleteX(ctx context.Context, id uuid.UUID) error

    // Transaction support
    WithTx(tx interface{}) XRepository
}
```

**PostgreSQL Implementation:**
- Wraps sqlc `*Queries`
- Converts between domain models (`XEntity`) and database models
- Delegates to sqlc-generated methods
- Supports transactions via `WithTx(pgx.Tx)`

**File-Based Implementation:**
- Stores data in `{dataDir}/x.json`
- In-memory map with `sync.RWMutex` for thread safety
- Atomic writes (temp file + rename)
- Loads on startup, saves after mutations
- No transaction support (returns self in `WithTx`)

## Remaining Work

### Phase 1: Extract Repository Interfaces (6 packages)

**Packages needing repository abstraction:**
1. `pkg/twofa` - Two-factor authentication settings
2. `pkg/role` - Role definitions (DONE - already has repository)
3. ✅ `pkg/auth` - Auth tokens (DONE)
4. ✅ `pkg/mapper` - User-login mappings (DONE)
5. ✅ `pkg/iam` - Users and groups (DONE - already has repository)
6. `pkg/profile` - User profiles

**For each package:**
1. Create `pkg/X/repository.go`:
   - Define domain entities (without sql.Null* types)
   - Define `XRepository` interface
   - Create `PostgresXRepository` implementation
   - Add conversion helpers

2. Update `pkg/X/service.go`:
   - Change field from `*Xdb.Queries` to `XRepository`
   - Update `NewXService()` to accept interface
   - Update all methods to use domain entities

3. Update callers:
   - `cmd/loginv2/main.go`
   - `cmd/quick/main.go`
   - Any test files

### Phase 2: File-Based Implementations (Partially Complete)

**Packages with existing repository interfaces:**
1. ✅ `pkg/logins` - DONE
2. ✅ `pkg/oidc` - DONE (adapted from in-memory)
3. ✅ `pkg/oauth2client` - DONE (adapted from in-memory)
4. ✅ `pkg/jwks` - DONE (adapted from in-memory)
5. ✅ `pkg/externalprovider` - DONE (adapted from in-memory)
6. `pkg/login` - Credentials (needs file implementation)
7. `pkg/device` - Device tracking (needs file implementation)
8. `pkg/delegate` - Delegation (needs file implementation)
9. `pkg/emailverification` - Email verification (needs file implementation)

**Packages needing both interface + file implementation:**
10. `pkg/twofa`
11. `pkg/auth`
12. `pkg/mapper`
13. `pkg/iam`
14. `pkg/profile`

### Phase 3: Factory Pattern

Create factory functions to instantiate the correct repository based on configuration:

**Add to each package:**
```go
func NewRepository(persistenceType string, config RepositoryConfig) (XRepository, error) {
    switch persistenceType {
    case "postgres":
        return NewPostgresXRepository(config.Queries), nil
    case "file":
        return NewFileXRepository(config.DataDir)
    default:
        return nil, fmt.Errorf("unsupported persistence type: %s", persistenceType)
    }
}
```

**Configuration:**
```go
type Config struct {
    PersistenceType string `env:"IDM_PERSISTENCE_TYPE" env-default:"postgres"`
    FileDataDir     string `env:"IDM_FILE_DATA_DIR" env-default:"./data"`
    // ... existing postgres config
}
```

**Update main.go:**
```go
// Current:
loginsQueries := loginsdb.New(pool)
loginsRepo := logins.NewPostgresLoginsRepository(loginsQueries)

// After factory:
loginsRepo, err := logins.NewRepository(config.PersistenceType, logins.RepositoryConfig{
    Queries: loginsQueries,  // nil if file-based
    DataDir: config.FileDataDir,
})
```

### Phase 4: Testing

**For each file-based repository:**
1. Unit tests for CRUD operations
2. Concurrent access tests (multiple goroutines)
3. Data persistence tests (restart simulation)
4. Edge cases (missing files, corrupted JSON, etc.)

**Integration tests:**
1. Full application with file-based backend
2. Migration tests (postgres → file, file → postgres)

### Phase 5: Documentation

**Update documentation:**
1. README files for each package with file-based usage examples
2. Main README explaining persistence configuration
3. Migration guide (switching backends)
4. Performance considerations

## Replication Guide

### For Packages Without Repository Interface

**Step 1: Analyze Service Dependencies**
```bash
grep "\.queries\." pkg/X/service.go
```

**Step 2: Create Repository Interface**
1. Copy domain models from `pkg/X/Xdb/models.go`
2. Remove sql.Null* types, add separate Valid fields
3. List all query methods used by service
4. Define interface with clean parameter types

**Step 3: Create PostgreSQL Implementation**
- Wrap `*Xdb.Queries`
- Convert parameters (domain → sqlc types)
- Convert results (sqlc → domain types)

**Step 4: Create File-Based Implementation**
- Use `FileLoginsRepository` as template
- Replace entity types and JSON filename
- Implement interface methods

**Step 5: Update Service**
- Change field type to interface
- Update constructor parameter
- Update method calls to use domain entities

**Step 6: Update Callers**
- Wrap queries in repository before passing to service

### For Packages With Existing Repository Interface

**Step 1: Study Interface**
```bash
cat pkg/X/repository.go
```

**Step 2: Create File Implementation**
- Use existing `FileLoginsRepository` as template
- Adjust entity types
- Implement all interface methods

**Step 3: Test**
```bash
go build ./pkg/X/...
```

## Quick Win: Adapt Existing In-Memory Repositories

**Packages with in-memory implementations:**
- `pkg/oidc` - `InMemoryOIDCRepository`
- `pkg/oauth2client` - `InMemoryOAuth2ClientRepository`
- `pkg/jwks` - `InMemoryJWKSRepository`
- `pkg/externalprovider` - `InMemoryExternalProviderRepository`

**To make file-based:**
1. Add `dataDir` field
2. Add `load()` method (read from JSON on startup)
3. Add `save()` method (write after mutations)
4. Call `save()` in Create/Update/Delete methods

**Example diff for OIDC:**
```go
type InMemoryOIDCRepository struct {
+   dataDir   string
    authCodes map[string]*AuthorizationCode
    mutex     sync.RWMutex
}

func NewInMemoryOIDCRepository(dataDir string) *InMemoryOIDCRepository {
    repo := &InMemoryOIDCRepository{
+       dataDir: dataDir,
        authCodes: make(map[string]*AuthorizationCode),
    }
+   repo.load()
    return repo
}

func (r *InMemoryOIDCRepository) StoreAuthorizationCode(...) error {
    // ... existing logic ...
    r.authCodes[code.Code] = code
+   return r.save()
}
```

## Benefits Achieved

**For Developers:**
- ✅ Single binary deployment (no external DB needed)
- ✅ Easy local development (no Docker required)
- ✅ Simple data inspection (just open JSON files)
- ✅ Easy backups (copy data directory)

**For Testing:**
- ✅ Fast test execution (no DB setup)
- ✅ Predictable test data (committed JSON files)
- ✅ Easy test isolation (temp directories)

**For Production:**
- ✅ Embedded use cases supported
- ✅ Progressive enhancement (start file-based, migrate to PostgreSQL later)
- ✅ No breaking changes (same interfaces)

## Next Steps

1. **Extract remaining repository interfaces** (6 packages × ~1 hour = 6 hours)
2. **Create file-based implementations** (14 packages × ~2 hours = 28 hours)
3. **Add factory pattern** (~4 hours)
4. **Write tests** (~8 hours)
5. **Update documentation** (~4 hours)

**Total estimated effort: 50 hours (~1.5 weeks)**

**Fastest path:**
1. Adapt 4 existing in-memory repos to file-based (~4 hours)
2. Extract interface + file impl for 2-3 critical packages (logins ✅, iam, auth) (~8 hours)
3. Add factory pattern for those packages (~2 hours)
4. Document pattern for others to replicate (~2 hours)

**Result: Minimal working file-based backend in 16 hours**
