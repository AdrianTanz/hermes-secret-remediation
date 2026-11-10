"""Rotation and git-history advice. Text only. Nothing here runs a command."""

from __future__ import annotations

BOUNDARY = (
    "This plugin does not call a revoke API, does not rewrite git history, "
    "and does not push. The steps below are for you to run, or not."
)

GIT_HISTORY = """\
Git history
If the credential was committed, rotating it comes first. Rewriting history does not un-leak a value that was already cloned or fetched.
After the issuer has revoked it, clean the history yourself with a tool you choose. git-filter-repo and BFG Repo-Cleaner are the usual ones. Read their docs and decide the rewrite on a fresh clone.
A rewrite changes every commit hash after the bad commit. Anyone else with the repo has to re-clone or reset onto the new history. Agree that before the remote is updated.
Publishing a rewritten branch replaces remote history. This plugin will not do that step.
GitHub secret scanning and push protection, or the equivalent on your host, reject the old value if someone pushes it again. Turn that on after rotation.
Forks, CI caches, chat logs and Hermes transcripts are outside the git objects. Treat those as leaked too."""

_ROTATION: dict[str, str] = {
    "github_pat": "GitHub: Settings, Developer settings, Personal access tokens. Revoke the classic token and issue a replacement only after the old one is dead. Update CI and local secret stores. Do not paste the new token into chat.",
    "github_fine_grained": "GitHub: Settings, Developer settings, Fine-grained personal access tokens. Revoke that token. Review the repositories it could access. Store the replacement outside the chat transcript.",
    "github_oauth": "GitHub: Settings, Applications, Authorized OAuth Apps. Revoke the app's grant, then sign in again if you still need it.",
    "github_user_to_server": "GitHub: this is a user-to-server token. Revoke the authorizing OAuth app or GitHub App installation, then authorize again.",
    "github_server": "GitHub: this is a server-to-server or installation token. It expires, but you should revoke the GitHub App installation or rotate the app's credentials if the value was copied into a file or a log.",
    "github_refresh": "GitHub: this is a refresh token. Revoke the OAuth app grant so the refresh token dies with it.",
    "aws_access_key_id": "AWS IAM: find the user or role for this access key id, deactivate the key, create a replacement, update consumers, then delete the old key. Check CloudTrail for use.",
    "aws_temp_access_key_id": "AWS: this is a temporary key (ASIA). Revoke the session if it is still valid, then rotate the underlying long-lived credential that minted it.",
    "aws_secret_access_key": "AWS IAM: the secret access key is shown once. Deactivate and delete that access key, create a new pair, and update every consumer. The old secret cannot be recovered from AWS.",
    "anthropic": "Anthropic console: API keys. Delete the leaked key and create a new one. Update the Hermes secret store or the process environment, not the chat.",
    "openai": "OpenAI platform: API keys. Revoke the leaked key and create a new one. Check usage for unexpected calls.",
    "openai_project": "OpenAI platform: project API keys. Revoke the leaked project key. Confirm which project it belonged to.",
    "openrouter": "OpenRouter: Keys. Revoke the leaked key and create a replacement.",
    "slack_token": "Slack: the app's OAuth token page, or api.slack.com/apps. Revoke or rotate the bot, user or app token. Reinstall the app if Slack requires it.",
    "slack_webhook": "Slack: the incoming webhook on the app configuration. Delete that webhook and create a new one. The URL is the secret.",
    "gitlab_pat": "GitLab: Preferences, Access Tokens. Revoke the personal, project or group token and create a replacement with the same scopes only if you still need them.",
    "huggingface": "Hugging Face: Settings, Access Tokens. Revoke the token. Fine-grained tokens should be recreated with the smallest scope.",
    "stripe_live": "Stripe dashboard: Developers, API keys. Roll the live secret key. Treat any live charge or refund since the leak as suspect.",
    "stripe_restricted": "Stripe dashboard: Developers, API keys, restricted keys. Roll that restricted key and review the last requests it made.",
    "stripe_test": "Stripe dashboard: Developers, API keys. Roll the test secret key. Test keys still grant access to test-mode data.",
    "sendgrid": "SendGrid: Settings, API Keys. Delete the leaked key and create a new one with the same permissions only if you still need them.",
    "pypi": "PyPI: Account settings, API tokens. Revoke the token. Upload a replacement to the CI secret store, not into the repo.",
    "npm": "npm: Access Tokens. Revoke the token and create a granular replacement. Check recent publishes of your packages.",
    "google_api": "Google Cloud console: APIs and Services, Credentials. Delete the API key, create a new one, and restrict it by API and by referrer or IP.",
    "jwt": "A JWT is a bearer credential. Revoke the session or rotate the signing key at the issuer. Do not decode it into a log. Anyone who holds the token can replay it until it expires or the signature dies.",
    "private_key": "Remove the private key from disk and from history after you have a replacement. Generate a new key pair. Remove the old public key from authorized_keys, deploy keys, CI and the host that trusted it. The old private key stays valid until every copy of the public key is gone.",
}

GENERIC = (
    "Revoke this credential at the service that issued it, then create a replacement "
    "and store that replacement outside chat, shell history and git."
)


def advice_for(kind: str | None = None) -> str:
    rotation = _ROTATION.get(kind or "", GENERIC)
    title = f"Rotation ({kind})" if kind else "Rotation"
    return f"{title}\n{rotation}\n\n{GIT_HISTORY}\n\n{BOUNDARY}"


def kinds() -> list[str]:
    return sorted(_ROTATION)
