//go:build !unix

package session

func pidAlive(pid int) bool {
	return false
}
