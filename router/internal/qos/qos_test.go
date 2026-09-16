package qos

import (
	"reflect"
	"testing"

	"router/pkg/models"
)

func TestPlanUpCake(t *testing.T) {
	tp := models.TrafficPolicy{Name: "w1", Interface: "eth0", UpMbps: 40, SQM: true, Qdisc: "cake"}
	ops, err := Plan(tp)
	if err != nil {
		t.Fatal(err)
	}
	want := []string{
		"tc qdisc replace dev eth0 root handle 1: cake bandwidth 40mbit",
	}
	if !reflect.DeepEqual(ops, want) {
		t.Fatalf("got %#v", ops)
	}
}

func TestPlanUpTBF(t *testing.T) {
	tp := models.TrafficPolicy{Name: "w1", Interface: "eth0", UpMbps: 100, Qdisc: "tbf"}
	ops, _ := Plan(tp)
	want := "tc qdisc replace dev eth0 root handle 1: tbf rate 100mbit burst 32kbit latency 400ms"
	if !reflect.DeepEqual(ops, []string{want}) {
		t.Fatalf("got %#v", ops)
	}
}

func TestPlanDownPolice(t *testing.T) {
	tp := models.TrafficPolicy{Name: "w1", Interface: "eth0", DownMbps: 940, Qdisc: "cake"}
	ops, _ := Plan(tp)
	want := []string{
		"tc qdisc replace dev eth0 clsact",
		"tc filter replace dev eth0 ingress protocol all prio 1 u32 match u32 0 0 action police rate 940mbit burst 10mbit drop",
	}
	if !reflect.DeepEqual(ops, want) {
		t.Fatalf("got %#v", ops)
	}
}

func TestPlanEmpty(t *testing.T) {
	ops, err := Plan(models.TrafficPolicy{Name: "x", Interface: "eth0"})
	if err != nil || len(ops) != 0 {
		t.Fatalf("expected no-op, got %v %v", ops, err)
	}
}

func TestPlanBoth(t *testing.T) {
	tp := models.TrafficPolicy{Name: "w1", Interface: "eth0", UpMbps: 20, DownMbps: 100}
	ops, _ := Plan(tp)
	if len(ops) != 3 {
		t.Fatalf("expected up+down ops, got %#v", ops)
	}
}

func TestPlanDefaultQdiscIsCakeWhenSQM(t *testing.T) {
	tp := models.TrafficPolicy{Name: "w1", Interface: "eth0", UpMbps: 20, SQM: true}
	ops, _ := Plan(tp)
	if ops[0] != "tc qdisc replace dev eth0 root handle 1: cake bandwidth 20mbit" {
		t.Fatalf("got %#v", ops)
	}
}

func TestPlanFqCodel(t *testing.T) {
	tp := models.TrafficPolicy{Name: "w1", Interface: "eth0", UpMbps: 20, Qdisc: "fq_codel"}
	ops, _ := Plan(tp)
	if ops[0] != "tc qdisc replace dev eth0 root handle 1: fq_codel limit 10240" {
		t.Fatalf("got %#v", ops)
	}
}

func TestPlanDelete(t *testing.T) {
	if got := Delete("eth0"); got != "tc qdisc del dev eth0 root" {
		t.Fatalf("got %q", got)
	}
}
