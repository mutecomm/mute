package ctrlengine

import (
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"io/ioutil"
	"os"
	"os/exec"
	"path"
	"time"

	"github.com/codegangsta/cli"
	"github.com/mutecomm/mute/def"
	"github.com/mutecomm/mute/log"
	mixclient "github.com/mutecomm/mute/mix/client"
	"github.com/mutecomm/mute/msgdb"
	"github.com/mutecomm/mute/release"
	"github.com/mutecomm/mute/uid/identity"
	"github.com/mutecomm/mute/util"
	"github.com/mutecomm/mute/util/git"
	"github.com/mutecomm/mute/util/gotool"
	"github.com/mutecomm/mute/util/times"
)

type getPastExecution func(mappedID string) (int64, error)

func checkExecution(
	mappedID, period string,
	getPast getPastExecution,
) (bool, int64, error) {
	duration, err := time.ParseDuration(period)
	if err != nil {
		return false, 0, err
	}
	now := time.Now().UTC()
	if duration == 0 {
		// always execution for 0 duration
		return true, now.Unix(), nil
	}
	past, err := getPast(mappedID)
	if err != nil {
		return false, 0, err
	}
	if past != 0 {
		if time.Unix(past, 0).Add(duration).After(now) {
			return false, 0, err
		}
	}
	return true, now.Unix(), nil
}

func (ce *CtrlEngine) upkeepAll(
	c *cli.Context,
	unmappedID,
	period string,
	statfp io.Writer,
) error {
	mappedID, err := identity.Map(unmappedID)
	if err != nil {
		return err
	}

	exec, now, err := checkExecution(mappedID, period,
		func(mappedID string) (int64, error) {
			return ce.msgDB.GetUpkeepAll(mappedID)
		})
	if err != nil {
		return err
	}
	if !exec {
		log.Info(statfp, "ctrlengine: upkeep all not due")
		fmt.Fprintf(statfp, "ctrlengine: upkeep all not due\n")
		return nil
	}

	// `upkeep accounts`
	if err := ce.upkeepAccounts(unmappedID, period, "2160h", statfp); err != nil {
		return err
	}

	// TODO: call all upkeep tasks in mutecrypt

	// record time of execution
	if err := ce.msgDB.SetUpkeepAll(mappedID, now); err != nil {
		return err
	}
	return nil
}

func writeConfigFile(homedir, domain string, config []byte) error {
	configdir := path.Join(homedir, "config")
	if err := os.MkdirAll(configdir, 0700); err != nil {
		return log.Error(err)
	}
	tmpfile := path.Join(configdir, domain+".new")
	os.Remove(tmpfile) // ignore error
	if err := ioutil.WriteFile(tmpfile, config, 0700); err != nil {
		return log.Error(err)
	}
	return os.Rename(tmpfile, path.Join(configdir, domain))
}

func (ce *CtrlEngine) upkeepFetchconf(
	msgDB *msgdb.MsgDB,
	homedir string,
	show bool,
	outfp, statfp io.Writer,
) error {
	log.Infof("fetch config for domain '%s'", def.DefaultDomain)
	fmt.Fprintf(statfp, "fetch config for domain '%s'\n", def.DefaultDomain)
	publicKey, _ := hex.DecodeString(def.PubkeyStr)
	ce.config.PublicKey = publicKey
	ce.config.URLList = "10," + def.ConfigURL
	ce.config.Timeout = 0 // use default timeout
	err := ce.config.Update()
	if err != nil {
		return log.Error(err)
	}
	jsn, err := json.Marshal(ce.config)
	if err != nil {
		return log.Error(err)
	}
	if err := msgDB.AddValue(def.DefaultDomain, string(jsn)); err != nil {
		return err
	}
	// apply new configuration
	if err := def.InitMute(&ce.config); err != nil {
		return err
	}
	// write new configuration file
	if err := writeConfigFile(homedir, def.DefaultDomain, jsn); err != nil {
		return err
	}
	// show new configuration
	if show {
		jsn, err := json.MarshalIndent(ce.config, "", "  ")
		if err != nil {
			return log.Error(err)
		}
		fmt.Fprintf(outfp, string(jsn)+"\n")
	}
	return nil
}

func updateMuteFromSource(outfp, statfp io.Writer, commit string) error {
	fmt.Fprintf(statfp, "updating Mute from source...\n")
	dir, err := exec.LookPath(os.Args[0])
	if err != nil {
		return err
	}
	// TODO: change path when release was done on github.com
	dir = path.Join(dir, "..", "..")

	// git status --porcelain
	fmt.Fprintf(statfp, "$ git status --porcelain\n")
	if err := git.Status(dir, statfp); err != nil {
		return log.Error(err)
	}

	// git checkout master
	fmt.Fprintf(statfp, "$ git checkout master\n")
	if err := git.Checkout(dir, "master", outfp, statfp); err != nil {
		return log.Error(err)
	}

	// git pull
	fmt.Fprintf(statfp, "$ git pull\n")
	if err := git.Pull(dir, outfp, statfp); err != nil {
		return err
	}

	// get current HEAD
	head, _, err := git.GetHead(dir, statfp)
	if err != nil {
		return log.Error(err)
	}

	// git checkout, if necessary
	var detached bool
	if head != commit {
		fmt.Fprintf(statfp, "$ git checkout\n")
		if err := git.Checkout(dir, commit, outfp, statfp); err != nil {
			return log.Error(err)
		}
		detached = true
	}

	// go generate -v mute/util/release
	fmt.Fprintf(statfp, "$ go generate -v mute/util/release\n")
	err = gotool.Generate(dir, "mute/util/release", outfp, statfp)
	if err != nil {
		return log.Error(err)
	}

	// go install -v mute/cmd/...
	fmt.Fprintf(statfp, "$ go install -v mute/cmd/...\n")
	if err := gotool.Install(dir, "mute/cmd/...", outfp, statfp); err != nil {
		return log.Error(err)
	}

	// go back to master, if necessary
	if detached {
		fmt.Fprintf(statfp, "$ git checkout master\n")
		if err := git.Checkout(dir, "master", outfp, statfp); err != nil {
			return log.Error(err)
		}
	}

	fmt.Fprintf(statfp, "Mute updated (restart it, if necessary)\n")
	return nil
}

func updateMuteBinaries(outfp, statfp io.Writer) error {
	fmt.Fprintf(statfp, "updating Mute binaries...\n")

	// "release.mutectrl.linux.amd64.hash": "SHA256 hash",
	// "release.mutectrl.linux.amd64.url": "https://mute.berlin/releases/...",

	// - find out which release to download (mutectrl, mutecrypt, and muteproto)
	// - download files
	// - compare hashes
	// - move binaries in place (os.Rename())

	// TODO: implement
	return nil
}

func (ce *CtrlEngine) upkeepUpdate(
	homedir string,
	/* source, binary bool, */
	outfp, statfp io.Writer,
) error {
	// make sure we have the most current config
	if err := ce.upkeepFetchconf(ce.msgDB, homedir, false, outfp, statfp); err != nil {
		return err
	}
	commit := ce.config.Map["release.Commit"]
	if release.Commit == commit {
		fmt.Fprintf(statfp, "Mute is up-to-date\n")
		return nil
	}
	// parse release date
	tRelease, err := time.Parse(git.Date, ce.config.Map["release.Date"])
	if err != nil {
		return err
	}
	// parse binary date
	tBinary, err := time.Parse(git.Date, release.Date)
	if err != nil {
		return err
	}
	// switch to UTC
	tRelease = tRelease.UTC()
	tBinary = tBinary.UTC()
	// compare dates
	if tBinary.After(tRelease) {
		fmt.Fprintf(statfp, "commits differ, but binary is newer than release date\n")
		fmt.Fprintf(statfp, "are you running a developer version?\n")
		return nil
	}
	/*
		// commits differ and release date is more current than binary -> update
		if !source && !binary {
			// try to determine update mode via mutegenerate
			// (should only exist for source releases)
			dir, err := exec.LookPath(os.Args[0])
			if err != nil {
				return err
			}
			dir = path.Join(dir, "..")
			cmd := exec.Command(path.Join(dir, "mutegenerate"), "-t")
			if err := cmd.Run(); err != nil {
				binary = true
			} else {
				source = true
			}
		}
		if source {
	*/
	if err := updateMuteFromSource(outfp, statfp, commit); err != nil {
		return err
	}
	/*
		} else {
			if err := updateMuteBinaries(outfp, statfp); err != nil {
				return err
			}
		}
	*/
	return nil
}

func (ce *CtrlEngine) upkeepAccounts(
	unmappedID, period, remaining string,
	statfp io.Writer,
) error {
	mappedID, err := identity.Map(unmappedID)
	if err != nil {
		return err
	}

	exec, now, err := checkExecution(mappedID, period,
		func(mappedID string) (int64, error) {
			return ce.msgDB.GetUpkeepAccounts(mappedID)
		})
	if err != nil {
		return err
	}
	if !exec {
		log.Info(statfp, "ctrlengine: upkeep accounts not due")
		fmt.Fprintf(statfp, "ctrlengine: upkeep accounts not due\n")
		return nil
	}

	remain, err := time.ParseDuration(remaining)
	if err != nil {
		return err
	}

	contacts, err := ce.msgDB.GetAccounts(mappedID)
	if err != nil {
		return err
	}

	for _, contact := range contacts {
		privkey, server, _, _, err := ce.msgDB.GetAccount(mappedID, contact)
		if err != nil {
			return err
		}
		last, err := ce.msgDB.GetAccountTime(mappedID, contact)
		if err != nil {
			return err
		}
		if last == 0 {
			last, err = mixclient.AccountStat(privkey, server, def.CACert)
			if err != nil {
				return err
			}
			err := ce.msgDB.SetAccountTime(mappedID, contact, last)
			if err != nil {
				return err
			}
		}
		if times.Now()+int64(remain.Seconds()) >= last {
			token, err := util.WalletGetToken(ce.client, def.AccdUsage, def.AccdOwner)
			if err != nil {
				return err
			}
			_, err = mixclient.PayAccount(privkey, token.Token, server, def.CACert)
			if err != nil {
				ce.client.UnlockToken(token.Hash)
				return log.Error(err)
			}
			ce.client.DelToken(token.Hash)
			last, err = mixclient.AccountStat(privkey, server, def.CACert)
			if err != nil {
				return err
			}
			err = ce.msgDB.SetAccountTime(mappedID, contact, last)
			if err != nil {
				return err
			}
		}
	}

	// record time of execution
	if err := ce.msgDB.SetUpkeepAccounts(mappedID, now); err != nil {
		return err
	}

	return nil
}