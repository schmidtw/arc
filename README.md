# arc

[![Build Status](https://github.com/schmidtw/arc/actions/workflows/ci.yml/badge.svg)](https://github.com/schmidtw/arc/actions/workflows/ci.yml)
[![codecov](https://codecov.io/gh/schmidtw/arc/graph/badge.svg?token=yPskgmUW6Z)](https://codecov.io/gh/schmidtw/arc)
[![Go Report Card](https://goreportcard.com/badge/github.com/schmidtw/arc)](https://goreportcard.com/report/github.com/schmidtw/arc)
[![Apache V2 License](http://img.shields.io/badge/license-Apache%20V2-blue.svg)](https://github.com/schmidtw/arc/blob/main/LICENSE)
[![GitHub Release](https://img.shields.io/github/release/schmidtw/arc.svg)](https://github.com/schmidtw/arc/releases)
[![GoDoc](https://pkg.go.dev/badge/github.com/schmidtw/arc)](https://pkg.go.dev/github.com/schmidtw/arc)

Go implementation of [RFC 8617](https://datatracker.ietf.org/doc/html/rfc8617), the Authenticated Received Chain (ARC) protocol.

ARC provides an authenticated "chain of custody" for email messages, allowing each entity that handles a message to see what entities handled it before and what the message's authentication assessment was at each step.

## Install

```
go get github.com/schmidtw/arc
```

## Usage

### Validating an ARC chain

```go
import (
    "context"
    "io"
    "github.com/schmidtw/arc"
)

func validateMessage(message io.Reader) error {
    v := arc.NewValidator() // uses net.DefaultResolver
    present, err := v.Validate(context.Background(), message)
    if err != nil {
        return err // chain validation failed
    }
    if !present {
        // No ARC headers present
    }
    // ARC chain validated successfully
    return nil
}
```

### Signing a message

```go
import (
    "context"
    "crypto"
    "github.com/schmidtw/arc"
)

func signMessage(message []byte, privateKey crypto.Signer) ([]byte, error) {
    signer, err := arc.NewSigner(privateKey, "sel._domainkey.example.org")
    if err != nil {
        return nil, err
    }

    return signer.SignBytes(context.Background(), message, "spf=pass; dkim=pass")
}
```

`Sign` validates any existing ARC chain before adding a new set. If validation succeeds the new set is marked as passing; if validation fails it is marked as failing. Signing is refused if the most recent set was already marked as failing.

## Custom Resolver

Both `NewValidator` and `NewSigner` accept `WithResolver` to supply a custom DNS resolver. This is useful for testing or environments where `net.DefaultResolver` is not appropriate.

```go
v := arc.NewValidator(arc.WithResolver(myResolver))

s, err := arc.NewSigner(key, domainKey,
    arc.WithValidator(v),
    arc.WithResolver(myResolver))
```

Any type that implements `LookupTXT(ctx context.Context, name string) ([]string, error)` satisfies the `Resolver` interface. The standard library's `*net.Resolver` works out of the box.

## Supported Algorithms

- RSA-SHA256 (`rsa-sha256`)
- Ed25519-SHA256 (`ed25519-sha256`)

## License

[Apache-2.0](LICENSE)
