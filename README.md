# decapcms-oauth-proxy

A Cloudflare Worker Github & Gitlab OAuth proxy for [Decap CMS](https://github.com/decaporg/decap-cms) ([Sveltia CMS](https://github.com/sveltia/sveltia-cms) compatible).

## Environments

| Key                 | Value                                                                                            |
| ------------------- | ------------------------------------------------------------------------------------------------ |
| SECRET              | A random string used to encrypt token.                                                           |
| TRUST_ORIGINS       | Space-separated list of origins (`<scheme>://<hostname>:<port>`) allowed to log in to Decap CMS. |
| GITHUB_OAUTH_ID     | GitHub OAuth App Client ID.                                                                      |
| GITHUB_OAUTH_SECRET | GitHub OAuth App Client Secrets.                                                                 |
| GITLAB_BASE_URL     | Gitlab Base Url. Default: `https://gitlab.com`                                                   |
| GITLAB_OAUTH_ID     | Gitlab OAuth App Client ID.                                                                      |
| GITLAB_OAUTH_SECRET | GitHub OAuth App Client Secrets.                                                                 |

**Important:**
When using **Decap CMS** with the hostname `localhost`, you must set the environment variable `ALLOW_DECAP_LOCALHOST_LOGIN=true`. Because Decap CMS uses `demo.decapcms.org` as the `site_id` when the site is accessed via `localhost`.

This setting is **not** required when using **Sveltia CMS**, which handles `localhost` differently.

## Endpoints

| URL                          | Usage                                                                                   |
| ---------------------------- | --------------------------------------------------------------------------------------- |
| https://[my.domain.com]/auth | Oauth Authorization & Callback Endpoint (`auth_endpoint` value in Decap Backend config) |
