package roundrobin

import (
	"math/rand"
	"strconv"
	"strings"
	"time"
)

func init() {
	rand.Seed(time.Now().UnixNano())
}

type server struct {
	prio int
	url  string
}

type serverList []server

func ParseServers(servers string) serverList {
	serversF := strings.Fields(strings.Replace(servers, ";", " ", -1))
	allserv := make(serverList, 0, len(serversF))
	for _, x := range serversF {
		z := strings.Fields(strings.Replace(x, ",", " ", -1))
		if len(z) > 1 {
			prio, _ := strconv.Atoi(z[0])
			ru := "http://" + z[1]
			allserv = append(allserv, server{prio: prio, url: ru})
		}
	}
	return allserv
}

func (sl serverList) MakeStrings() []string {
	slice := make([]string, len(sl))
	for i, s := range sl {
		slice[i] = s.url
	}
	return slice
}

func randomize(s []string) []string {
	x := rand.Perm(len(s))
	ret := make([]string, len(s))
	for i, str := range s {
		ret[x[i]] = str
	}
	return ret
}

func (sl serverList) Order() []string {
	var ret [][]string
	var cur, val []string
	var prio int
	for _, s := range sl {
		if prio == s.prio {
			cur = append(cur, s.url)
		} else {
			if cur != nil {
				ret = append(ret, randomize(cur))
			}
			cur = make([]string, 0)
			prio = s.prio
			cur = append(cur, s.url)
		}
	}
	if cur != nil {
		ret = append(ret, randomize(cur))
	}
	for _, r := range ret {
		val = append(val, r...)
	}
	return val
}

func (sl serverList) Len() int {
	return len(sl)
}

func (sl serverList) Swap(i, j int) {
	sl[i], sl[j] = sl[j], sl[i]
}

func (sl serverList) Less(i, j int) bool {
	return sl[i].prio < sl[j].prio
}
