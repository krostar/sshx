[![License](https://img.shields.io/badge/license-MIT-blue)](https://choosealicense.com/licenses/mit/)
![go.mod Go version](https://img.shields.io/github/go-mod/go-version/krostar/sshx?label=go)
[![GoDoc](https://img.shields.io/badge/godoc-reference-blue.svg)](https://pkg.go.dev/github.com/krostar/sshx)
[![Latest tag](https://img.shields.io/github/v/tag/krostar/sshx)](https://github.com/krostar/sshx/tags)
[![Go Report](https://goreportcard.com/badge/github.com/krostar/sshx)](https://goreportcard.com/report/github.com/krostar/sshx)

# "standard" SSH package eXtended (sshx)

This package mainly contains helpers around the standard ssh package (`golang.org/x/crypto/ssh`) with some added functionalities.

## Why is it useful ?

Here are some of the things this package provide.
Feel free to walk around the code (or the godoc) to get a more complete view of what can be done.

### Public keys / Private keys

There are some helpers to initialize keys from a variety of inputs (pem bytes, files, ...).
Those helpers return a custom type (with the possibility to get the underlying type easily) to:
- avoid passing parameters as type `any` (there is no type for private keys) which help for clarity
- define a unique type for private and public key (it handles the same types `ssh.NewPublicKey` is able to handle)
- add some useful utility like `Equal` method that is able to compare two keys to know if they are equal

### Client

It helps to create ssh client with the ability to go through multiple bridges before reaching the target server.

Example:

```go
func getTargetHostname() {
	config := &ClientConfig{
		Addr:            "bridge.addr",
		SSHClientConfig: ssh.ClientConfig{User: "bridge-user"},
		Bridge: &ClientConfig{
			Addr:            "target.addr",
			SSHClientConfig: ssh.ClientConfig{User: "target-user"},
		},
	}

	// initiate a connection between your host and the bridge's ssh server
	// then a connection is established from that bridged ssh server to the target ssh server
	// useful if the target is not reachable from your host
	client, _ := NewClient(config)

	// using the standard ssh library from now one
	session, _ := client.NewSession()
	output, _ := session.Output("hostname -f")
	fmt.Println(output) // will contain the hostname of target ssh server's host
}
```

## Contribution

This project is using nix, which mean by using `nix develop` you can have the same development environment than me or GitHub Action.
It contains everything needed to develop, lint, and test.

You can also use `act` to run the same steps GitHub Action is using during pull requests, but locally.

Feel free to open issues and pull requests!