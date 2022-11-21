package sshx

type sentinelError string

func (s sentinelError) Error() string { return string(s) }
