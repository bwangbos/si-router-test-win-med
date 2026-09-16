package state_test

import (
	"testing"

	"router/internal/state"
)

func TestParseRoutesNormalizesDefault(t *testing.T) {
	in := `[{"dst":"default","gateway":"192.0.2.1","dev":"eth0","metric":1000}]`
	rs, err := state.ParseRoutes(in)
	if err != nil {
		t.Fatal(err)
	}
	if len(rs) != 1 || rs[0].Dst != "0.0.0.0/0" || rs[0].Metric != 1000 {
		t.Fatalf("got %+v", rs)
	}
}

func TestParseRoutesComment(t *testing.T) {
	in := `[{"dst":"10.0.0.0/8","dev":"lo","comment":"routerd"}]`
	rs, err := state.ParseRoutes(in)
	if err != nil {
		t.Fatal(err)
	}
	if len(rs) != 1 || rs[0].Comment != "routerd" {
		t.Fatalf("got %+v", rs)
	}
}

func TestParseLinksAndAddrs(t *testing.T) {
	links := `[{"ifname":"eth0","link_type":"ether","mtu":1500,"flags":["BROADCAST","UP","RUNNING"],"txqlen":1000,"operstate":"UP"}]`
	ls, err := state.ParseLinks(links)
	if err != nil || len(ls) != 1 || !ls[0].Up || ls[0].MTU != 1500 {
		t.Fatalf("links: %v %+v", err, ls)
	}
	addrs := `[{"ifname":"br0","addr_info":[{"family":"inet","local":"10.0.0.1","prefixlen":24}]}]`
	as, err := state.ParseAddrs(addrs)
	if err != nil || len(as) != 1 || len(as[0].Addrs) != 1 || as[0].Addrs[0] != "10.0.0.1/24" {
		t.Fatalf("addrs: %v %+v", err, as)
	}
}
