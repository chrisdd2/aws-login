# AWS Login Application

A web-based AWS role assumption portal that provides secure AWS credential and console access through OAuth authentication.

## Features

- **Multi-Provider Authentication**: GitHub, Google, and Keycloak OAuth/OIDC support
- **AWS Role Assumption**: Assume IAM roles across multiple AWS accounts
- **Temporary Credentials**: Generate AWS console links or temporary credentials
- **User/Role Management**: Manage users, AWS accounts, IAM roles, and policies
- **Keycloak Sync**: Optional user synchronization from Keycloak
- **Dual Storage Backends**: File-based or PostgreSQL storage
- **Prometheus Metrics**: Built-in metrics endpoint

## Configuration

The application uses a layered configuration system with the following priority (highest to lowest):

1. **Defaults** - Built-in default values
2. **Environment Variables** - `APP_*` prefixed variables
3. **YAML Config File** - Specified via `-config-file` flag (default: `app.conf.yml`)

### Command-Line Flags

| Flag | Default | Description |
|------|---------|-------------|
| `-config-file` | `app.conf.yml` | Path to configuration file |

### Environment Variables

Environment variables use the prefix `APP_` followed by the config path with `__` separators. For example:
- `storage.postgres.host` → `APP_STORAGE__POSTGRES__HOST`
- `auth.github.client_id` → `APP_AUTH__GITHUB__CLIENT_ID`

#### Application Settings

| Variable | Default | Description |
|----------|---------|-------------|
| `APP_NAME` | - | Application name |
| `APP_ENVIRONMENT` | `"development"` | Environment mode (`development` or `production`) |
| `APP_LISTEN_ADDR` | `"localhost:8090"` | HTTP server address |
| `APP_METRICS_ADDR` | `"localhost:8099"` | Prometheus metrics server address |
| `APP_DEVELOPMENT_MODE` | `false` | Enable debug logging |
| `APP_ROOT_URL` | - | Base URL for OAuth redirects |
| `APP_CONFIG_FILE` | `"app.conf.yml"` | Config file path |

#### Storage Configuration

| Variable | Default | Description |
|----------|---------|-------------|
| `APP_STORAGE__TYPE` | `"file"` | Storage backend (`file` or `postgres`) |
| `APP_STORAGE__DIRECTORY` | `".config"` | File storage directory |
| `APP_STORAGE__POSTGRES__HOST` | - | PostgreSQL host |
| `APP_STORAGE__POSTGRES__PORT` | - | PostgreSQL port |
| `APP_STORAGE__POSTGRES__DATABASE` | - | PostgreSQL database name |
| `APP_STORAGE__POSTGRES__USERNAME` | - | PostgreSQL username |
| `APP_STORAGE__POSTGRES__PASSWORD` | - | PostgreSQL password |
| `APP_STORAGE__SYNC__KEYCLOAK__BASE_URL` | - | Keycloak server URL |
| `APP_STORAGE__SYNC__KEYCLOAK__REALM` | - | Keycloak realm |
| `APP_STORAGE__SYNC__KEYCLOAK__USERNAME` | - | Keycloak admin username |
| `APP_STORAGE__SYNC__KEYCLOAK__PASSWORD` | - | Keycloak admin password |

#### Authentication Configuration

| Variable | Default | Description |
|----------|---------|-------------|
| `APP_AUTH__ADMIN_USERNAME` | - | Admin panel username |
| `APP_AUTH__ADMIN_PASSWORD` | - | Admin panel password |
| `APP_AUTH__SIGN_KEY` | - | JWT signing key (keep secure) |
| `APP_AUTH__GITHUB__CLIENT_ID` | - | GitHub OAuth client ID |
| `APP_AUTH__GITHUB__CLIENT_SECRET` | - | GitHub OAuth client secret |
| `APP_AUTH__GITHUB__REDIRECT_URL` | - | GitHub OAuth callback URL |
| `APP_AUTH__GOOGLE__CLIENT_ID` | - | Google OAuth client ID |
| `APP_AUTH__GOOGLE__CLIENT_SECRET` | - | Google OAuth client secret |
| `APP_AUTH__GOOGLE__PROVIDER_URL` | - | Google OIDC provider URL |
| `APP_AUTH__GOOGLE__REDIRECT_URL` | - | Google OAuth callback URL |
| `APP_AUTH__KEYCLOAK__CLIENT_ID` | - | Keycloak client ID |
| `APP_AUTH__KEYCLOAK__CLIENT_SECRET` | - | Keycloak client secret |
| `APP_AUTH__KEYCLOAK__PROVIDER_URL` | - | Keycloak OIDC provider URL |
| `APP_AUTH__KEYCLOAK__REDIRECT_URL` | - | Keycloak OAuth callback URL |
| `APP_AUTH__GOOGLE_WORKSPACES` | - | Comma-separated allowed Google Workspace domains |

### AWS Credentials

The application uses AWS SDK environment variables with custom prefixes for assuming roles:

| Prefix | Variables |
|--------|-----------|
| `ASSUMER_AWS_*` | AWS credentials for assuming roles |
| `S3_AWS_*` | AWS credentials for S3 operations |

Example:
```bash
export ASSUMER_AWS_ACCESS_KEY_ID=AKIA...
export ASSUMER_AWS_SECRET_ACCESS_KEY=...
export ASSUMER_AWS_REGION=us-east-1
```

### YAML Configuration File

#### Example Configuration

```yaml
name: Aws Login
root_url: http://localhost:8090
listen_addr: 0.0.0.0:8090
metrics_addr: localhost:8099

storage:
  type: postgres
  postgres:
    host: localhost
    database: postgres
    username: postgres
    password: postgres
  sync:
    keycloak:
      base_url: http://localhost:8180
      realm: master
      username: admin
      password: admin

auth:
  admin_username: admin
  admin_password: admin
  github:
    client_id: your-github-client-id
    client_secret: your-github-client-secret
    redirect_url: http://localhost:8090/oauth2/github/idpresponse
  google:
    client_id: your-google-client-id
    client_secret: your-google-client-secret
    provider_url: https://accounts.google.com
    redirect_url: https://localhost:9000/oauth2/google/idpresponse
  google_workspaces:
    - example.com
  keycloak:
    client_secret: your-keycloak-secret
    provider_url: http://localhost:8080/realms/grafana
    redirect_url: http://localhost:8090/oauth2/keycloak/idpresponse

development_mode: true
```

#### File Storage Structure

When using file-based storage (`storage.type: file`), the following directory structure is used:

```
.config/
├── accounts.yml
├── roles.yml
├── policies.yml
├── users.yml
├── role_account_attachments.yml
├── role_policy_attachments.yml
└── role_user_attachments.yml
```

## OAuth Provider Setup

### GitHub OAuth App

1. Go to GitHub Settings > Developer settings > OAuth Apps
2. Create a new OAuth App
3. Set the callback URL to: `http://your-domain/oauth2/github/idpresponse`
4. Copy Client ID and Client Secret to configuration

### Google OAuth

1. Go to Google Cloud Console > APIs & Services > Credentials
2. Create an OAuth 2.0 Client ID
3. Set the callback URL to: `http://your-domain/oauth2/google/idpresponse`
4. Copy Client ID and Client Secret to configuration

### Keycloak

1. Create a new client in your Keycloak realm
2. Set Client Protocol to `openid-connect`
3. Set Valid Redirect URIs to your application URL
4. Copy the client secret and realm details to configuration

## Storage Backends

### File Storage (Default)

Simple YAML file-based storage. Suitable for development and small deployments.

```yaml
storage:
  type: file
  dir: .config
```

### PostgreSQL

Recommended for production use with better performance and concurrency.

```yaml
storage:
  type: postgres
  postgres:
    host: localhost
    database: postgres
    username: postgres
    password: postgres
```

## Development

```bash
# Build
go build -o aws-login .

# Run with custom config
./aws-login -config-file app.conf.yml
```

## Production Considerations

1. Set `APP_ENVIRONMENT=production` in production
2. Disable `development_mode`
3. Use a strong `sign_key` for JWT tokens
4. Use PostgreSQL for storage
5. Configure TLS/HTTPS
6. Set secure passwords for all admin accounts
7. Store sensitive credentials in secrets management


#### This readme was totally gene.. created by a human