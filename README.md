# go-user-passwords
Simple password authentication, suitable for website logins against a database

This package provides simple `Hash(password)` and `Verify(password, token)` functions for user logins.

It considers out-of-scope anything beyond that, as those aspects will depend on your service architecture and requirements. You will still need to implement things like password resets, sessions, login attempt logging, and so forth.

### Installation

You can do the usual:

    go get github.com/grayj/go-user-passwords

Plus or minus "you should use godep" and possibly vendoring.

### Usage

    import "github.com/grayj/go-user-passwords"

When a user creates a new password record, run `Hash()` and store the resulting token in your database.

When a user tries to log in, look up the token which matches the provided username or email. Then do `Verify()` with the provided password and that token.

Both methods can return errors. You should likely return a user-facing error for `ErrPasswordLength` on the off chance that someone tries to feed you a >1KB password. These are blocked as a denial-of-service safeguard. Any other `err != nil` state should be safe to respond to with an HTTP 5XX.

If you're seeing `ErrTokenInvalid` at all, you're doing something funny with your tokens. This won't happen if a user merely provides an invalid passsword, it requries the token to be egregriously wrong (empty, mangled, fake, inconsistent version header).

P.S. Make sure that you use HTTPS for login requests (and any other sensitive interactions). If you're making users send passwords to you in the clear, you already have a giant hole in your security. Yes, this actually needs repeating.
