// Copyright (c) 2015 Mute Communications Ltd.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package log

import (
	"errors"
	"fmt"
	"io"
	"os"
	"path"
	"runtime"

	"github.com/cihub/seelog"
)

var logger seelog.LoggerInterface

// Options defines logging command-line options.
//
// TODO: remove
type Options struct {
	LogLevel   string `long:"loglevel" description:"Logging level {trace, debug, info, warn, error, critical}" default:"info"`
	LogDir     string `long:"logdir" description:"Directory to log output"`
	LogConsole bool   `long:"logconsole" description:"Enable logging to console"`
}

func init() {
	// disable logger by default
	logger = seelog.Disabled
}

// Init initializes the Mute logging framework to the given logging level.
// If logDir is not nil logging is done to a logfile in the directory.
// If logToConsole is true the console logging is activated.
// cmdPrefix must be a 5 character long command prefix.
// If the given level is invalid or the initialization fails, an
// error is returned.
func Init(logLevel, cmdPrefix, logDir string, logToConsole bool) error {
	// check level string
	_, found := seelog.LogLevelFromString(logLevel)
	if !found {
		return fmt.Errorf("log: level '%s' is invalid", logLevel)
	}
	// check cmdPrefix
	if len(cmdPrefix) != 5 {
		return fmt.Errorf("len(cmdPrefix) must be 5: \"%s\"", cmdPrefix)
	}
	// create logger
	console := "<console />"
	if !logToConsole {
		console = ""
	}
	var file string
	if logDir != "" {
		file = fmt.Sprintf("<rollingfile type=\"size\" filename=\"%s\" maxsize=\"10485760\" maxrolls=\"3\" />",
			path.Join(logDir, os.Args[0]+".log"))
	}
	config := `
<seelog type="adaptive" mininterval="2000000" maxinterval="100000000"
	critmsgcount="500" minlevel="%s">
	<outputs formatid="all">
		%s
		%s
	</outputs>
	<formats>
		<format id="all" format="%%UTCDate %%UTCTime [%s] [%%LEV] %%Msg%%n" />
	</formats>
</seelog>`
	config = fmt.Sprintf(config, logLevel, console, file, cmdPrefix)
	logger, err := seelog.LoggerFromConfigAsString(config)
	if err != nil {
		return err
	}
	logger.SetAdditionalStackDepth(1)
	// replace logger
	UseLogger(logger)
	// log info about running binary
	Infof("%s started (built with %s %s for %s/%s)", os.Args[0], runtime.Compiler, runtime.Version(), runtime.GOOS, runtime.GOARCH)
	return nil
}

// InitOpts initializes the Mute logging framework to the given logging level and
// logfile. If the given level is invalid or the initialization fails, an
// error is returned.
func InitOpts(opts *Options, cmdPrefix string) error {
	return Init(opts.LogLevel, cmdPrefix, opts.LogDir, opts.LogConsole)
}

// Flush flushes all the messages in the logger.
func Flush() {
	Infof("%s stopping", os.Args[0])
	logger.Flush()
}

// Critical formats message using the default formats for its operands and
// writes to default logger with log level = Critical.
func Critical(v ...interface{}) error {
	if len(v) == 1 {
		err, ok := v[0].(error)
		if ok {
			logger.Critical(err)
			return err
		}
	}
	return logger.Critical(v...)
}

// Criticalf formats message according to format specifier and writes to
// default logger with log level = Critical.
func Criticalf(format string, params ...interface{}) error {
	return logger.Criticalf(format, params...)
}

// Error formats message using the default formats for its operands and writes
// to default logger with log level = Error.
func Error(v ...interface{}) error {
	if len(v) == 1 {
		err, ok := v[0].(error)
		if ok {
			logger.Error(err)
			return err
		}
	}
	return logger.Error(v...)
}

// Errorf formats message according to format specifier and writes to default
// logger with log level = Error.
func Errorf(format string, params ...interface{}) error {
	return logger.Errorf(format, params...)
}

// Warn formats message using the default formats for its operands and writes
// to default logger with log level = Warn.
func Warn(v ...interface{}) error {
	if len(v) == 1 {
		err, ok := v[0].(error)
		if ok {
			logger.Warn(err)
			return err
		}
	}
	return logger.Warn(v...)
}

// Warnf formats message according to format specifier and writes to default
// logger with log level = Warn.
func Warnf(format string, params ...interface{}) error {
	return logger.Warnf(format, params...)
}

// Info formats message using the default formats for its operands and writes
// to default logger with log level = Info.
func Info(v ...interface{}) {
	logger.Info(v...)
}

// Infof formats message according to format specifier and writes to default
// logger with log level = Info.
func Infof(format string, params ...interface{}) {
	logger.Infof(format, params...)
}

// Debug formats message using the default formats for its operands and writes
// to default logger with log level = Debug.
func Debug(v ...interface{}) {
	logger.Debug(v...)
}

// Debugf formats message according to format specifier and writes to default
// logger with log level = Debug.
func Debugf(format string, params ...interface{}) {
	logger.Debugf(format, params...)
}

// Trace formats message using the default formats for its operands and writes
// to default logger with log level = Trace.
func Trace(v ...interface{}) {
	logger.Trace(v...)
}

// Tracef formats message according to format specifier and writes to default
// logger with log level = Trace.
func Tracef(format string, params ...interface{}) {
	logger.Tracef(format, params...)
}

// UseLogger uses a specified seelog.LoggerInterface to output library log.
// Use this func if you are using Seelog logging system in your app.
func UseLogger(newLogger seelog.LoggerInterface) {
	logger = newLogger
}

// SetLogWriter uses a specified io.Writer to output library log.
// Use this func if you are not using Seelog logging system in your app.
func SetLogWriter(writer io.Writer) error {
	if writer == nil {
		return errors.New("Nil writer")
	}

	newLogger, err := seelog.LoggerFromWriterWithMinLevel(writer, seelog.TraceLvl)
	if err != nil {
		return err
	}

	UseLogger(newLogger)
	return nil
}
