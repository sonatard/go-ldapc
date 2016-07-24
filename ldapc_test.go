package ldapc_test

import (
	"fmt"

	"github.com/sona-tar/go-ldapc"
)

// User Authentication shows how a typical application can verify a login attempt
// Set ldapc.AuthBind to ldapc.Clinet.Bind
func ExampleClient_Authenticate() {
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
	// fmt.Printf("%+v\n")

	// username and mail
	fmt.Printf("username: %v\n", entry.GetAttributeValue("uid"))
	fmt.Printf("mail: %v\n", entry.GetAttributeValue("mail"))
	// Output:
	// username: user2
	// mail: user2@test.com
}

// Anonymous Bind Example.
// Set ldapc.AuthBind to ldapc.Clinet.Bind. BindDN and BindPassword are empty.
func Example_AnonymousBind() {
	ldapclient := &ldapc.Client{
		Protocol:  ldapc.LDAP,
		Host:      "localhost",
		Port:      389,
		TLSConfig: nil,
		Bind: &ldapc.AuthBind{
			BindDN:       "", // empty
			BindPassword: "", // empty
			BaseDN:       "dc=test,dc=com",
			Filter:       "(&(objectClass=posixAccount)(uid=%s))",
		},
	}

	username := "user2"
	password := "user2"

	_, err := ldapclient.Authenticate(username, password)
	if err != nil {
		fmt.Printf("LDAP Authenticate failed: %v\n", err)
	}
}

// Direct Bind Example.
// Set ldapc.DirectBind to ldapc.Clinet.Bind.
func Example_DirectBind() {
	ldapclient := &ldapc.Client{
		Protocol:  ldapc.LDAP,
		Host:      "localhost",
		Port:      389,
		TLSConfig: nil,
		Bind: &ldapc.DirectBind{ // DirectBind
			UserDN: "uid=%s,ou=People,dc=test,dc=com", // DirectBind dosen't search UserDN.
			Filter: "(&(objectClass=posixAccount)(uid=%s))",
		},
	}

	username := "user2"
	password := "user2"

	_, err := ldapclient.Authenticate(username, password)
	if err != nil {
		fmt.Printf("LDAP Authenticate failed: %v\n", err)
	}
}

// LDAPS Protocol Example.
// Set ldapc.LDAPS to ldapc.Clinet.Protocol.
// Set 636 to ldapc.Clinet.Port.
func Example_LDAPS() {
	ldapclient := &ldapc.Client{
		Protocol:  ldapc.LDAPS, // LDAPS
		Host:      "localhost",
		Port:      636, // LDAPS basic port
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

	_, err := ldapclient.Authenticate(username, password)
	if err != nil {
		fmt.Printf("LDAP Authenticate failed: %v\n", err)
	}
}

// LDAP TLS Protocol Example.
// Set ldapc.START_TLS to ldapc.Clinet.Protocol.
// Set 389 to ldapc.Clinet.Port.
func Example_START_TLS() {
	ldapclient := &ldapc.Client{
		Protocol:  ldapc.START_TLS, // START_TLS
		Host:      "localhost",
		Port:      389, // START_TLS port is same as normal LDAP
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

	_, err := ldapclient.Authenticate(username, password)
	if err != nil {
		fmt.Printf("LDAP Authenticate failed: %v\n", err)
	}
}

// Example ActiveDirectory .
// Set "(&(objectClass=user)(sAMAccountName=%s))" to Filter
func Example_ActiveDirectory() {
	ldapclient := &ldapc.Client{
		Protocol:  ldapc.LDAP,
		Host:      "localhost",
		Port:      389,
		TLSConfig: nil,
		Bind: &ldapc.AuthBind{
			BindDN:       "uid=user1,ou=People,dc=test,dc=com",
			BindPassword: "admin",
			BaseDN:       "dc=test,dc=com",
			Filter:       "(&(objectClass=user)(sAMAccountName=%s))", // Active Directory
		},
	}

	username := "user2"
	password := "user2"

	_, err := ldapclient.Authenticate(username, password)
	if err != nil {
		fmt.Printf("LDAP Authenticate failed: %v\n", err)
	}
}
