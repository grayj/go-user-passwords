# go-user-passwords
Simple password authentication, suitable for website logins against a database

### Installation

You can do the usual:

    go get github.com/grayj/go-user-passwords

Plus or minus "you should use godep" and possibly vendoring.

### Usage

    import "github.com/grayj/go-user-passwords"

There are only two methods you need to be aware of, `Hash(password)` and `Verify(password, token)`.

* When a user creates a new password record, run `Hash()` and store the resulting token in your database.
* When a user tries to log in, look up the token which matches the provided username or email. Then do `Verify()` with the provided password and that token.

That's it.

Both methods can also return errors. You may want to return a user-facing error for `ErrPasswordLength` on the off chance that someone tries to feed you a >1KB password. These are blocked as a denial-of-service safeguard.

P.S. Make sure that you use HTTPS for login requests (and any other sensitive interactions). If you're making users send passwords to you in the clear, you already have a giant hole in your security. Yes, this actually needs repeating.
