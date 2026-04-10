package testsecrets

import "strings"

func AWSAccessKey() string {
	return "AKIA" + "IOSFODNN7EXAMPLE"
}

func GitHubPAT() string {
	return "ghp_" + "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghij"
}

func GitHubFineGrainedPAT() string {
	return "github_pat_" + strings.Repeat("a", 82)
}

func GitHubPATWithBody(body string) string {
	return "ghp_" + body
}

func SlackBotToken() string {
	return "xoxb-" + "1234567890-1234567890123-AbCdEfGhIjKlMnOpQrStUvWx"
}

func StripeLiveKey() string {
	return "sk_" + "live_" + "ABCDEFGHIJKLMNOPQRSTUVWXYZab"
}

func StripeLiveKeyAlt() string {
	return "sk_" + "live_" + "1234567890abcdef12345678"
}

func GoogleAPIKey() string {
	return "AIza" + "SyA1234567890abcdefghijklmnopqrstuvw"
}

func OpenAIKey() string {
	return "sk-" + "abcdefghijklmnopqrstuvwxyz1234567890"
}

func OpenAIProjectKey() string {
	return "sk-" + "proj-" + "abcdefghijklmnopqrstuvwxyz1234"
}

func RSAHeader() string {
	return "-----BEGIN " + "RSA PRIVATE KEY-----"
}

func OpenSSHHeader() string {
	return "-----BEGIN " + "OPENSSH PRIVATE KEY-----"
}
