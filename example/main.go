package main

import (
	"fmt"

	ldapc "github.com/sona-tar/go-ldapc"
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
	// fmt.Printf("%+v\n", entry)

	// username and mail
	fmt.Printf("username: %v\n", entry.GetAttributeValue("uid"))
	fmt.Printf("mail: %v\n", entry.GetAttributeValue("mail"))
}
