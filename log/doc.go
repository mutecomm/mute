/*
Package log implements the Mute logging framework.

See https://github.com/cihub/seelog/wiki/Log-levels for an introduction to the
different logging levels.

We want to log all error conditions in Mute, but want to avoid logging them
multiple times. Therefore, we log them once as early as possible: When calling
external packages that create an error, we wrap that error in a log.Error()
call. If we create our own errors, we use log.Error[f]() to do that. If we call
panic() we create the error for that with log.Critical[f](). In server packages
we might wrap and create errors with log.Warn[f]() instead of log.Error[f](),
because the server doesn't handle the error himself and passes it on to a
client. On the client the error is wrapped with log.Error(), because it comes
from an external source.
*/
package log
