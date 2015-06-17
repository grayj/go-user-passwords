# go-user-passwords
Simple password authentication, suitable for website logins against a database

[![Godoc](http://img.shields.io/badge/godoc-reference-blue.svg?style=flat)](https://godoc.org/github.com/grayj/go-user-passwords)

This package provides simple Hash(password) and Verify(password, token) functions for user logins.

It considers out-of-scope anything beyond that, as those aspects will depend on your service architecture and requirements. You will still need to implement things like password resets, sessions, login attempt logging, and so forth.

### Installation

You can do the usual:

    go get github.com/grayj/go-user-passwords

### Usage

    import "github.com/grayj/go-user-passwords"

* When a user creates a new password record, run `Hash()` and store the resulting token in your database.

* When a user tries to log in, look up the token which matches the provided username or email. Then do `Verify()` with the provided password and that token.

Both methods can return errors, which should be handled rather than blanked.

* **ErrTokenWrongVersion** Your token doesn't match the current software. Should only happen if you're mixing hashing functions and call the wrong one for a given token, and will only be thrown by Verify().
* **ErrPasswordLength** If someone feeds you a >1KB password, it's refused as a denial of service safeguard. Can by thrown by both Hash() and Verify(). You may want to return an actionable user-facing error.
* **ErrUnexpectedEOF** or other IO-related errors can be thrown if /dev/urandom or the local equivalent is exhausted, this should be considered a transitory error (retrying will usually fix it).

It's also possible to get scrypt-related errors if you override the parameters with invalid choices, but these will trigger a log.Fatal() instead of an error.
 
P.S. Make sure that you use HTTPS for login requests (and any other sensitive interactions). If you're making users send passwords to you in the clear, you already have a giant hole in your security. Yes, this actually needs repeating.
