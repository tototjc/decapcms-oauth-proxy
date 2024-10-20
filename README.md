# decapcms-github-oauth-proxy

A Cloudflare Worker Github OAuth proxy for Decap CMS.

## Environments

| Key                 | Value                                                                                                                                                                |
| ------------------- | -------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| ALLOW_SITE_ID_LIST  | List of Decap CMS hostname allowed to login, separated by "`,`" for each hostname. If you want to allow localhost login, please add `demo.dacapcms.org` to the list. |
| GITHUB_OAUTH_ID     | Your GitHub OAuth App Client ID                                                                                                                                      |
| GITHUB_OAUTH_SECRET | Your GitHub OAuth App Client Secrets                                                                                                                                 |


## Endpoints

| URL                              | Usage                                                                      |
| -------------------------------- | -------------------------------------------------------------------------- |
| https://[my.domain.com]/auth     | Oauth Authorization Endpoint (`auth_endpoint` value in Decap `config.yml`) |
| https://[my.domain.com]/callback | Oauth Callback Endpoint                                                    |
