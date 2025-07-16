# decapcms-oauth-proxy

A Cloudflare Worker Github & Gitlab OAuth proxy for Decap CMS.

## Environments

| Key                 | Value                                                                                                                                                                |
| ------------------- | -------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| SECRET              | A random string used to encrypt token.                                                                                                                               |
| ALLOW_SITE_ID_LIST  | List of Decap CMS hostname allowed to login, separated by "`,`" for each hostname. If you want to allow localhost login, please add `demo.dacapcms.org` to the list. |
| GITHUB_OAUTH_ID     | GitHub OAuth App Client ID.                                                                                                                                          |
| GITHUB_OAUTH_SECRET | GitHub OAuth App Client Secrets.                                                                                                                                     |
| GITLAB_BASE_URL     | Gitlab Base Url. Default: `https://gitlab.com`                                                                                                                       |
| GITLAB_OAUTH_ID     | Gitlab OAuth App Client ID.                                                                                                                                          |
| GITLAB_OAUTH_SECRET | GitHub OAuth App Client Secrets.                                                                                                                                     |

## Endpoints

| URL                          | Usage                                                                                   |
| ---------------------------- | --------------------------------------------------------------------------------------- |
| https://[my.domain.com]/auth | Oauth Authorization & Callback Endpoint (`auth_endpoint` value in Decap Backend config) |
