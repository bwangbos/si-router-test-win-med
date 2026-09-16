// Package qos translates declarative bandwidth policies into tc commands.
package qos

import (
	"fmt"

	"router/pkg/models"
)

// Plan returns ordered tc command lines (argv joined by spaces) for a policy.
func Plan(tp models.TrafficPolicy) ([]string, error) {
	var ops []string
	q := tp.Qdisc
	if q == "" {
		if tp.SQM {
			q = "cake"
		} else {
			q = "tbf"
		}
	}
	if tp.UpMbps > 0 {
		switch q {
		case "cake", "fq_codel":
			if q == "cake" {
				ops = append(ops, fmt.Sprintf("tc qdisc replace dev %s root handle 1: cake bandwidth %dmbit", tp.Interface, tp.UpMbps))
			} else {
				ops = append(ops, fmt.Sprintf("tc qdisc replace dev %s root handle 1: fq_codel limit 10240", tp.Interface))
			}
		case "tbf":
			ops = append(ops, fmt.Sprintf("tc qdisc replace dev %s root handle 1: tbf rate %dmbit burst 32kbit latency 400ms", tp.Interface, tp.UpMbps))
		}
	}
	if tp.DownMbps > 0 {
		burst := (tp.DownMbps + 99) / 100
		if burst < 1 {
			burst = 1
		}
		ops = append(ops,
			fmt.Sprintf("tc qdisc replace dev %s clsact", tp.Interface),
			fmt.Sprintf("tc filter replace dev %s ingress protocol all prio 1 u32 match u32 0 0 action police rate %dmbit burst %dmbit drop", tp.Interface, tp.DownMbps, burst),
		)
	}
	return ops, nil
}

// Delete returns the command removing a shaped root qdisc.
func Delete(iface string) string {
	return fmt.Sprintf("tc qdisc del dev %s root", iface)
}
