package classify

import "strings"

func IsGitPush(cmd string) bool {
	return GitSubcommandIs(cmd, "push")
}

func IsGitCommit(cmd string) bool {
	return GitSubcommandIs(cmd, "commit")
}

func GitSubcommandIs(cmd, subcmd string) bool {
	parts := strings.Fields(cmd)
	if len(parts) < 2 || parts[0] != "git" {
		return false
	}
	valuedFlags := map[string]bool{
		"-c": true, "-C": true,
		"--git-dir": true, "--work-tree": true,
		"--namespace": true, "--config-env": true,
		"--exec-path": true, "--html-path": true,
	}
	for i := 1; i < len(parts); i++ {
		p := parts[i]
		if strings.HasPrefix(p, "-") {
			if strings.Contains(p, "=") {
				continue
			}
			if valuedFlags[p] && i+1 < len(parts) {
				i++
				for i+1 < len(parts) {
					next := parts[i+1]
					if strings.HasPrefix(next, "-") {
						break
					}
					if !strings.ContainsAny(next, `"'`) && !strings.Contains(parts[i], `"`) && !strings.Contains(parts[i], `'`) {
						break
					}
					i++
					if strings.HasSuffix(next, `"`) || strings.HasSuffix(next, `'`) {
						break
					}
				}
			}
			continue
		}
		return p == subcmd
	}
	return false
}

func IsEnvCommand(cmd string) bool {
	lower := strings.ToLower(strings.TrimSpace(cmd))
	for _, p := range []string{"env", "printenv"} {
		if lower == p || strings.HasPrefix(lower, p+" ") || strings.HasPrefix(lower, p+"\t") {
			return true
		}
	}
	if lower == "set" {
		return true
	}
	if strings.HasPrefix(lower, "echo $") || strings.HasPrefix(lower, "echo \"$") || strings.HasPrefix(lower, "echo '$") {
		secretVarNames := []string{
			"aws_secret", "aws_access_key", "database_url", "db_password",
			"api_key", "api_secret", "secret_key", "private_key",
			"token", "auth_token", "access_token", "refresh_token",
			"password", "passwd", "credentials",
			"stripe_secret", "github_token", "npm_token",
		}
		for _, v := range secretVarNames {
			if strings.Contains(lower, v) {
				return true
			}
		}
	}
	return false
}

func IsPersistenceCommand(cmd string) bool {
	lower := strings.ToLower(strings.TrimSpace(cmd))
	persistPrefixes := []string{
		"crontab ", "crontab\t",
		"at ", "at\t",
		"launchctl load ", "launchctl submit ",
		"systemctl enable ", "systemctl start ",
	}
	for _, p := range persistPrefixes {
		if strings.HasPrefix(lower, p) {
			return true
		}
	}
	return lower == "crontab"
}

func IsSudoCommand(cmd string) bool {
	lower := strings.ToLower(strings.TrimSpace(cmd))
	return strings.HasPrefix(lower, "sudo ") || strings.HasPrefix(lower, "sudo\t")
}
