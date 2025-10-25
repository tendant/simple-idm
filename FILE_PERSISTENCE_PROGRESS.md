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
3. `pkg/auth` - Auth tokens
4. `pkg/mapper` - User-login mappings
5. `pkg/iam` - Users and groups
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

### Phase 2: File-Based Implementations (15 packages)

**Packages with existing repository interfaces:**
1. ✅ `pkg/logins` - DONE
2. `pkg/login` - Credentials
3. `pkg/device` - Device tracking
4. `pkg/oidc` - OIDC authorization codes (already has in-memory!)
5. `pkg/oauth2client` - OAuth2 clients (already has in-memory!)
6. `pkg/jwks` - JWKS keys (already has in-memory!)
7. `pkg/externalprovider` - External providers (already has in-memory!)
8. `pkg/delegate` - Delegation
9. `pkg/emailverification` - Email verification

**Packages needing both interface + file implementation:**
10. `pkg/twofa`
11. `pkg/auth`
12. `pkg/mapper`
13. `pkg/iam`
14. `pkg/profile`

**Note:** Packages 4-7 already have in-memory implementations that could be adapted to file-based storage!

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
