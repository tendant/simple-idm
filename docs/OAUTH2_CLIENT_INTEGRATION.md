# OAuth2 Client Integration Guide

This guide provides comprehensive instructions for integrating applications with simple-idm using OAuth2/OIDC authentication. It includes step-by-step client registration, configuration examples for popular tools like Concourse CI and ArgoCD, and best practices for secure implementation.

## Table of Contents

1. [Overview](#overview)
2. [Prerequisites](#prerequisites)
3. [Client Registration](#client-registration)
   - [Using the Web Interface](#using-the-web-interface)
   - [Using the API](#using-the-api)
4. [Integration Examples](#integration-examples)
   - [Concourse CI](#concourse-ci-integration)
   - [ArgoCD](#argocd-integration)
5. [Configuration Reference](#configuration-reference)
6. [Troubleshooting](#troubleshooting)
7. [Security Best Practices](#security-best-practices)

## Overview

Simple-idm provides a standards-compliant OAuth2/OIDC identity provider that supports:

- **OAuth2 Authorization Code Flow** with PKCE support
- **OpenID Connect (OIDC)** for identity information
- **RFC 7591** compliant Dynamic Client Registration
- **Scopes**: `openid`, `profile`, `email`, `groups`
- **Grant Types**: `authorization_code`
- **Response Types**: `code`

### Key Endpoints

- **Authorization**: `https://your-idm-server.com/api/idm/oauth2/authorize`
- **Token Exchange**: `https://your-idm-server.com/api/idm/oauth2/token`
- **Client Registration**: `https://your-idm-server.com/api/oauth2client/`
- **OIDC Discovery**: `https://your-idm-server.com/.well-known/openid_configuration`

## Prerequisites

Before integrating with simple-idm, ensure you have:

1. **Admin Access**: You need administrator privileges to register OAuth2 clients
2. **Simple-IDM Server**: A running simple-idm instance
3. **Application Details**: Know your application's redirect URIs and required scopes
4. **HTTPS**: Production deployments should use HTTPS for security

## Client Registration

### Using the Web Interface

The web interface provides an intuitive way to register and manage OAuth2 clients.

#### Step 1: Access OAuth2 Clients Page

Navigate to the OAuth2 Clients section in the simple-idm admin interface:

![OAuth2 Clients List](screenshots/oauth2-clients-list.png)

The page shows:
- Existing OAuth2 clients (e.g., "Argo CD", "Concourse CI")
- Client details: Type, Grant Types, Creation date
- Actions: View, Edit, Delete for each client
- "Register New Client" button

#### Step 2: Register New Client

Click "Register New Client" to open the registration form:

![Register New OAuth2 Client](screenshots/register-oauth2-client.png)

Fill in the required information:

**Basic Information:**
- **Client ID**: Unique identifier (e.g., `my-app-client`)
- **Client Name**: Human-readable name (e.g., "My Application")
- **Client Type**: Select "Confidential" for server-side applications

**OAuth2 Configuration:**
- **Redirect URIs**: Valid callback URLs for your application
- **Grant Types**: Keep "authorization_code" selected
- **Response Types**: Keep "code" selected
- **Scope**: Space-separated scopes (e.g., `openid profile email groups`)

#### Step 3: Save and Retrieve Credentials

After registration, you'll receive:
- **Client ID**: Your application identifier
- **Client Secret**: Keep this secure - it's only shown once
- **Configuration details**: All the settings you specified

#### Step 4: Edit Client (Optional)

You can modify client settings using the Edit form:

![Edit OAuth2 Client](screenshots/edit-oauth2-client.png)

Note: The Client ID cannot be changed after creation, but all other settings are editable.

### Using the API

For programmatic client registration, use the REST API:

#### Register a New Client

```bash
curl -X POST https://your-idm-server.com/api/oauth2client/ \
  -H "Authorization: Bearer YOUR_ADMIN_TOKEN" \
  -H "Content-Type: application/json" \
  -d '{
    "client_id": "my-app-client",
    "client_name": "My Application",
    "client_type": "confidential",
    "redirect_uris": ["https://myapp.example.com/callback"],
    "grant_types": ["authorization_code"],
    "response_types": ["code"],
    "scope": "openid profile email groups"
  }'
```

#### Response

```json
{
  "client_id": "my-app-client",
  "client_secret": "secret_abc123...",
  "client_name": "My Application",
  "client_type": "confidential",
  "redirect_uris": ["https://myapp.example.com/callback"],
  "grant_types": ["authorization_code"],
  "response_types": ["code"],
  "scope": "openid profile email groups",
  "created_at": "2023-09-12T03:14:00Z",
  "updated_at": "2023-09-12T03:14:00Z"
}
```

#### List Existing Clients

```bash
curl -X GET https://your-idm-server.com/api/oauth2client/ \
  -H "Authorization: Bearer YOUR_ADMIN_TOKEN"
```

#### Update a Client

```bash
curl -X PUT https://your-idm-server.com/api/oauth2client/my-app-client \
  -H "Authorization: Bearer YOUR_ADMIN_TOKEN" \
  -H "Content-Type: application/json" \
  -d '{
    "client_name": "My Updated Application",
    "redirect_uris": ["https://myapp.example.com/callback", "https://myapp.example.com/auth"],
    "scope": "openid profile email"
  }'
```

#### Regenerate Client Secret

```bash
curl -X POST https://your-idm-server.com/api/oauth2client/my-app-client/regenerate-secret \
  -H "Authorization: Bearer YOUR_ADMIN_TOKEN"
```

## Integration Examples

### Concourse CI Integration

Concourse CI supports OIDC authentication for team authorization and user identification.

#### 1. Register Concourse Client

**Via Web Interface:**
- **Client ID**: `concourse_client`
- **Client Name**: `Concourse CI`
- **Client Type**: `Confidential`
- **Redirect URIs**: `https://concourse.example.com/sky/issuer/callback`
- **Scope**: `openid profile email groups`

**Via API:**
```bash
curl -X POST https://your-idm-server.com/api/oauth2client/ \
  -H "Authorization: Bearer YOUR_ADMIN_TOKEN" \
  -H "Content-Type: application/json" \
  -d '{
    "client_id": "concourse_client",
    "client_name": "Concourse CI",
    "client_type": "confidential",
    "redirect_uris": ["https://concourse.example.com/sky/issuer/callback"],
    "grant_types": ["authorization_code"],
    "response_types": ["code"],
    "scope": "openid profile email groups"
  }'
```

#### 2. Configure Concourse

Add OIDC configuration to your Concourse deployment:

**Docker Compose Example:**
```yaml
version: '3'
services:
  concourse-web:
    image: concourse/concourse
    command: web
    environment:
      # OIDC Configuration
      CONCOURSE_OIDC_DISPLAY_NAME: "Simple IDM"
      CONCOURSE_OIDC_ISSUER: "https://your-idm-server.com"
      CONCOURSE_OIDC_CLIENT_ID: "concourse_client"
      CONCOURSE_OIDC_CLIENT_SECRET: "your_client_secret"
      CONCOURSE_OIDC_SCOPE: "openid profile email groups"
      CONCOURSE_OIDC_GROUPS_KEY: "groups"
      CONCOURSE_OIDC_USER_NAME_KEY: "email"  
```

#### 3. Team Authorization

Configure teams to use OIDC groups and users. Concourse supports both local users and OIDC-based authentication with role-based access control.

**Basic Team Configuration:**
```bash
fly -t main set-team -n developers \
  --oidc-group "developers" \
  --oidc-group "concourse-users"
```

**Advanced Team Configuration Example:**

You can create teams with mixed authentication methods (local users and OIDC groups) and different role levels:

```bash
# Create a team with both member and owner roles
fly -t main set-team -n mycompany \
  --role member:oidc:engineering \
  --role member:oidc:qa-team \
  --role member:local:john.doe \
  --role member:local:jane.smith \
  --role member:local:bob.wilson \
  --role owner:local:admin \
  --role owner:oidc:devops-leads
```

This configuration creates a team called "mycompany" with:

**Member Role:**
- **OIDC Groups**: `engineering`, `qa-team`
- **Local Users**: `john.doe`, `jane.smith`, `bob.wilson`

**Owner Role:**
- **Local Users**: `admin`
- **OIDC Groups**: `devops-leads`

**Interactive Team Setup:**
When you run the command, Concourse will show a confirmation prompt:
```
setting team: mycompany

role member:
  users:
  - local:john.doe
  - local:jane.smith
  - local:bob.wilson

  groups:
  - oidc:engineering
  - oidc:qa-team

role owner:
  users:
  - local:admin

  groups:
  - oidc:devops-leads

apply team configuration? [yN]: y
team updated
```

**Role Permissions:**
- **Members**: Can view and trigger pipelines, but cannot modify team configuration
- **Owners**: Full administrative access including team management and pipeline configuration

**Managing Teams:**
```bash
# List all teams
fly -t main teams

# View team configuration
fly -t main get-team -n mycompany

# Update team configuration
fly -t main set-team -n mycompany --role member:oidc:new-group

# Delete a team
fly -t main destroy-team -n mycompany
```

### ArgoCD Integration

ArgoCD supports OIDC for single sign-on and RBAC integration.

#### 1. Register ArgoCD Client

**Via Web Interface:**
- **Client ID**: `argocd_client`
- **Client Name**: `Argo CD`
- **Client Type**: `Confidential`
- **Redirect URIs**: `https://argocd.example.com/auth/callback`
- **Scope**: `openid profile email groups`

**Via API:**
```bash
curl -X POST https://your-idm-server.com/api/oauth2client/ \
  -H "Authorization: Bearer YOUR_ADMIN_TOKEN" \
  -H "Content-Type: application/json" \
  -d '{
    "client_id": "argocd_client",
    "client_name": "Argo CD",
    "client_type": "confidential",
    "redirect_uris": ["https://argocd.example.com/auth/callback"],
    "grant_types": ["authorization_code"],
    "response_types": ["code"],
    "scope": "openid profile email groups"
  }'
```

#### 2. Configure ArgoCD

Add OIDC configuration to ArgoCD's `argocd-cm` ConfigMap:

```yaml
apiVersion: v1
kind: ConfigMap
metadata:
  name: argocd-cm
  namespace: argocd
data:
  # OIDC Configuration
  oidc.config: |
    name: Simple IDM
    issuer: https://your-idm-server.com
    clientId: argocd_client
    clientSecret: $oidc.simple-idm.clientSecret
    requestedScopes:
      - openid
      - profile
      - email
      - groups 
```

Create the client secret using a proper Secret manifest:

```yaml
apiVersion: v1
kind: Secret
metadata:
  name: argocd-oidc-secret
  namespace: argocd
  labels:
    app.kubernetes.io/name: argocd-oidc-secret
    app.kubernetes.io/part-of: argocd
type: Opaque
stringData:
  # OIDC client credentials - stored securely in a Secret instead of ConfigMap
  client-id: argocd_client
  client-secret: "your_client_secret_here"
```

Apply the secret:
```bash
kubectl apply -f argocd-oidc-secret.yaml
```

#### 3. RBAC Configuration

Configure role-based access control using groups:

```yaml
# In argocd-rbac-cm ConfigMap
apiVersion: v1
kind: ConfigMap
metadata:
  name: argocd-rbac-cm
  namespace: argocd
data:
  policy.csv: |
    # Admin role - full access
    p, role:admin, applications, *, */*, allow
    p, role:admin, clusters, *, *, allow
    p, role:admin, repositories, *, *, allow
    p, role:admin, certificates, *, *, allow
    p, role:admin, projects, *, *, allow
    
    # Developer role - limited access
    p, role:developer, applications, get, */*, allow
    p, role:developer, applications, sync, */*, allow
    p, role:developer, repositories, get, *, allow
    
    # Group mappings
    g, argocd-admins, role:admin
    g, developers, role:developer
    g, devops, role:admin
  
  policy.default: role:readonly
```

## Configuration Reference

### Client Registration Parameters

| Parameter | Required | Description | Example |
|-----------|----------|-------------|---------|
| `client_id` | Yes | Unique client identifier | `my-app-client` |
| `client_name` | Yes | Human-readable name | `My Application` |
| `client_type` | No | Client type (default: `confidential`) | `confidential` |
| `redirect_uris` | Yes | Array of valid redirect URIs | `["https://app.com/callback"]` |
| `grant_types` | No | OAuth2 grant types (default: `["authorization_code"]`) | `["authorization_code"]` |
| `response_types` | No | OAuth2 response types (default: `["code"]`) | `["code"]` |
| `scope` | No | Space-separated scopes | `openid profile email groups` |

### Available Scopes

| Scope | Description | Claims Included |
|-------|-------------|-----------------|
| `openid` | OpenID Connect | `sub`, `iss`, `aud`, `exp`, `iat` |
| `profile` | User profile information | `name`, `preferred_username`, `given_name`, `family_name` |
| `email` | Email address | `email`, `email_verified` |
| `groups` | User group memberships | `groups` |

### Standard OAuth2 Endpoints

| Endpoint | URL | Description |
|----------|-----|-------------|
| Authorization | `/api/idm/oauth2/authorize` | OAuth2 authorization endpoint |
| Token | `/api/idm/oauth2/token` | Token exchange endpoint |
| UserInfo | `/api/idm/oauth2/userinfo` | OIDC UserInfo endpoint |
| JWKS | `/api/idm/oauth2/jwks` | JSON Web Key Set |
| Discovery | `/.well-known/openid_configuration` | OIDC Discovery document |

## Troubleshooting

### Common Issues

#### 1. Invalid Redirect URI

**Error**: `invalid_request: redirect_uri is not registered`

**Solution**: Ensure the redirect URI in your application exactly matches the one registered in simple-idm:
- Check for trailing slashes
- Verify the protocol (http vs https)
- Confirm the port number if specified

#### 2. Invalid Client Credentials

**Error**: `invalid_client: client authentication failed`

**Solution**: 
- Verify the client ID and secret are correct
- Ensure the client secret hasn't been regenerated
- Check that you're using the correct authentication method

#### 3. Insufficient Scope

**Error**: `invalid_scope: requested scope is invalid`

**Solution**: 
- Verify the requested scopes are registered for your client
- Check that the scopes are space-separated, not comma-separated
- Ensure you're requesting valid scopes (`openid`, `profile`, `email`, `groups`)

#### 4. Token Validation Errors

**Error**: Token signature verification failed

**Solution**:
- Verify you're using the correct JWKS endpoint
- Check that your application is validating tokens against the correct issuer
- Ensure system clocks are synchronized (JWT tokens are time-sensitive)

### Debug Steps

1. **Check OIDC Discovery Document**:
   ```bash
   curl https://your-idm-server.com/.well-known/openid_configuration
   ```

2. **Verify Client Registration**:
   ```bash
   curl -H "Authorization: Bearer YOUR_TOKEN" \
        https://your-idm-server.com/api/oauth2client/your-client-id
   ```

3. **Test Authorization Flow**:
   - Navigate to the authorization URL manually
   - Check browser developer tools for redirect errors
   - Verify the authorization code is received

4. **Validate Token Exchange**:
   ```bash
   curl -X POST https://your-idm-server.com/api/idm/oauth2/token \
     -H "Content-Type: application/x-www-form-urlencoded" \
     -d "grant_type=authorization_code&code=YOUR_CODE&client_id=YOUR_CLIENT_ID&client_secret=YOUR_SECRET&redirect_uri=YOUR_REDIRECT_URI"
   ```
