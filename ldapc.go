// Package ldapc provides easy LDAP v3 authentication.
// Set LDAPC_DEBUG=yes to environment value then print debug log
package ldapc

import (
	"crypto/tls"
	"errors"
	"fmt"
	"log"
	"os"

	"gopkg.in/ldap.v2"
)

func debug(format string, args ...interface{}) {
	if os.Getenv("LDAPC_DEBUG") != "" {
		log.Printf(format, args...)
	}
}

// Protocol:  LDAP, LDAPS and START_TLS
type Protocol int

const (
	LDAP      Protocol = iota // No encrypted protocol
	LDAPS                     // SSL protocol
	START_TLS                 // TLS protocol
)

// Client is a LDAP Client.
// Protocol, Host, Prot, Bind are required parameter.
// TLSConfig uses only Protocol is LDAPS or START_TLS
type Client struct {
	Protocol  Protocol    // Security protocol. LDAP, LDAPS and START_TLS
	Host      string      // LDAP Server host
	Port      int         // Port number
	TLSConfig *tls.Config // TLSConfig used only LDAPS or START_TLS
	Bind      Bind        // Bind Information
}

// LDAP authentication by username, password and Bind information.
// Do user authentication and return authenticated user's entry.
func (c *Client) Authenticate(username, password string) (*ldap.Entry, error) {
	conn, err := c.dial()
	if err != nil {
		return nil, err
	}
	defer conn.Close()

	if c.Bind == nil {
		return nil, errors.New("Bind is nil")
	}

	return c.Bind.auth(conn, username, password)
}

func (c *Client) dial() (*ldap.Conn, error) {
	if c.Protocol == LDAPS {
		debug("LDAP Auth : Start LDAPS Protocol\n")
		return ldap.DialTLS("tcp", fmt.Sprintf("%s:%d", c.Host, c.Port), c.TLSConfig)
	}

	conn, err := ldap.Dial("tcp", fmt.Sprintf("%s:%d", c.Host, c.Port))
	if err != nil {
		return nil, fmt.Errorf("Dial: %v", err)
	}

	if c.Protocol == START_TLS {
		if err = conn.StartTLS(c.TLSConfig); err != nil {
			debug("LDAP Auth : Start TLS Protocol\n")
			conn.Close()
			return nil, fmt.Errorf("StartTLS: %v", err)
		}
	}

	debug("LDAP Auth : Start LDAP Protocol\n")

	return conn, nil
}
