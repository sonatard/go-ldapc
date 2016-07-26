`go-ldapc` is a LDAP Authentication client module with only one API.
===============================

[![GoDoc](https://godoc.org/github.com/sona-tar/go-ldapc?status.svg)](https://godoc.org/github.com/sona-tar/go-ldapc)

## Example

You can provide LDAP based authentication on your web page easily.

- Code:
```go
import (
    "github.com/sona-tar/ldapc"
)

func main() {
	ldapclient := &ldapc.Client{
		Protocol:  ldapc.LDAP,
		Host:      "localhost",
		Port:      389,
		TLSConfig: nil,
		Bind: &ldapc.AuthBind{
			BindDN:       "uid=user1,ou=People,dc=test,dc=com",
			BindPassword: "admin",
			BaseDN:       "dc=test,dc=com",
			Filter:       "(&(objectClass=posixAccount)(uid=%s))",
		},
	}

	username := "user2"
	password := "user2"

	entry, err := ldapclient.Authenticate(username, password)
	if err != nil {
		fmt.Printf("LDAP Authenticate failed: %v\n", err)
	}

	// Print all entry
	fmt.Printf("%+v\n")

	// username and mail
	fmt.Printf("username: %v\n", entry.GetAttributeValue("uid"))
	fmt.Printf("mail: %v\n", entry.GetAttributeValue("mail"))
}
```

- Output:
```text
username: user2
mail: user2@test.com
```

In other cases Anonymous Bind, Direct Bind or Active Directory, example code [ldapc_test.go](./ldapc_test.go).


## Demo
- Create OpenLDAP Server
 - See [docker-ldapc](https://github.com/sona-tar/docker-ldapc)

- Client
```shell
$ go get -v github.com/sona-tar/go-ldapc
$ cd ${GOPATH}/src/github.com/sona-tar/go-ldapc/example
$ go run main.go
username: user2
mail: user2@test.com
```

## Reference
- Use [(gogs/gogs - /gogs/modules/auth/ldap)](https://github.com/gogits/gogs/tree/master/modules/auth/ldap) implementation as a reference. Thanks gogs developers!!
