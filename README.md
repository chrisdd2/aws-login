# AWS Login

A small web portal that lets users assume AWS IAM roles through OIDC single
sign-on, without ever holding long-lived AWS keys.

Flow: user logs in via an OIDC provider (e.g. Keycloak) → their ID token
groups/claims are matched against a static role config → they get either an
AWS console federation link or exported shell credentials for the roles
they're entitled to.

## Commands

```bash
# One-time per AWS account: create the bootstrap role aws-login uses to
# create/update IAM roles in that account.
aws-login bootstrap --principal <arn-of-the-identity-running-"web">

# Run the web server.
aws-login web [--address :8080]
```

`web` also syncs the IAM roles/policies described in the config into every
account referenced there before it starts listening.

## Configuration

### Role config

`CONFIG_FILE` (default `config`) points to a YAML or JSON file, or a
directory of them, each shaped like:

```yaml
roles:
  - name: readonly
    account_id: "111111111111"
    managed_policies:
      - arn:aws:iam::aws:policy/ReadOnlyAccess
    policies:               # optional inline policies, name -> JSON document
    tags:
      production: "true"
    claim:                  # OIDC group/claim values that may assume this role
      - developers
    max_session_duration: 8h  # optional, defaults to 8h
    no_boundary: false         # optional, skip the IAM permission boundary
```

See [example.yaml](example.yaml).

### Environment variables

| Variable | Default | Description |
|----------|---------|--------------|
| `CONFIG_FILE` | `config` | Path to the role config file or directory |
| `OIDC_ISSUER_URL` | — (required) | OIDC provider issuer URL |
| `OIDC_REDIRECT_URL` | — (required) | OAuth2 callback URL, e.g. `https://host/oauth2/callback` |
| `OIDC_CLIENT_ID` | — (required) | OIDC client ID |
| `OIDC_SECRET` | — (required) | OIDC client secret |
| `OIDC_LOGOUT_URL` | discovered from `.well-known/openid-configuration` | End-session endpoint override |
| `OIDC_SCOPES` | — | Extra comma-separated scopes (`openid email profile` are always included) |
| `OIDC_GROUP_CLAIMSPATH` | `groups` | Dotted path to the groups/roles claim in the ID token |
| `OIDC_USERNAME_CLAIMSPATH` | `username` | Dotted path to the username claim |
| `OIDC_DISPLAYNAME_CLAIMSPATH` | `preferred_name` | Dotted path to the display-name claim |
| `OIDC_SECURE_COOKIES` | `false` | Set `true` to mark cookies `Secure` (needs HTTPS) |
| `ENCRYPTION_KEY` | — (required) | Key used to sign the session JWT cookie |
| `BASE_URL` | `/` | Path to redirect to after login/logout |
| `APP_TITLE` | `aws-login` | Title shown in the UI |

AWS credentials/region are picked up the standard way via the AWS SDK
(env vars, shared config, instance/task role, etc.) — used both to run
`bootstrap`/`web` and, per target account, via `sts:AssumeRole` on the
bootstrap role created there.

## Local development

`docker-compose.yml` starts a bare Keycloak instance for testing OIDC login
against:

```bash
docker compose up -d
# Keycloak admin console: http://localhost:8180 (admin/admin)
```

Point `OIDC_ISSUER_URL` at the realm you create there, add role entries to
`sample.yaml` (or your own config file) matching your Keycloak groups, then:

```bash
go build -o aws-login ./cmd/cli
CONFIG_FILE=sample.yaml OIDC_ISSUER_URL=... OIDC_REDIRECT_URL=... \
  OIDC_CLIENT_ID=... OIDC_SECRET=... ENCRYPTION_KEY=... ./aws-login web
```

## How role assumption works

For every AWS account referenced in the role config, `aws-login` (via the
identity running `web`) assumes a per-account `aws-login-bootstrap` role
(created by the `bootstrap` command) and uses it to create/update:

- one IAM role per config entry, trusted to be assumed by that same identity
- a shared permission boundary policy, attached to every role it manages,
  that prevents those roles from being used to escalate IAM permissions
  outside of what aws-login itself grants

At request time, the web app itself calls `sts:AssumeRole` directly on the
target role (not through the bootstrap role) using the caller identity the
server is running as.
