// SPDX-License-Identifier: Apache-2.0

package metrics

import (
	"github.com/prometheus/client_golang/prometheus"
)

var (
	collectorsNamespace = "smb"
)

func (sme *smbMetricsExporter) register() error {
	cols := []prometheus.Collector{
		sme.newSmbVersionsCollector(),
		sme.newSmbSharesCollector(),
		sme.newSmbLocksCollector(),
	}
	for _, c := range cols {
		if err := sme.reg.Register(c); err != nil {
			sme.log.Error(err, "failed to register collector")
			return err
		}
	}
	return nil
}

type smbCollector struct {
	// nolint:structcheck
	sme *smbMetricsExporter
	dsc []*prometheus.Desc
}

func (col *smbCollector) Describe(ch chan<- *prometheus.Desc) {
	for _, d := range col.dsc {
		ch <- d
	}
}

type smbVersionsCollector struct {
	smbCollector
	clnt *kclient
}

func (col *smbVersionsCollector) Collect(ch chan<- prometheus.Metric) {
	status := 0
	vers, err := ResolveVersions(col.clnt)
	if err != nil {
		status = 1
	}
	ch <- prometheus.MustNewConstMetric(
		col.dsc[0],
		prometheus.GaugeValue,
		float64(status),
		vers.Version,
		vers.CommitID,
		vers.SambaImage,
		vers.SambaVersion,
		vers.CtdbVersion,
	)
}

func (sme *smbMetricsExporter) newSmbVersionsCollector() prometheus.Collector {
	col := &smbVersionsCollector{}
	col.sme = sme
	col.clnt, _ = newKClient()
	col.dsc = []*prometheus.Desc{
		prometheus.NewDesc(
			collectorName("metrics", "status"),
			"Current metrics-collector status versions",
			[]string{
				"version",
				"commitid",
				"sambaimage",
				"sambavers",
				"ctdbvers",
			}, nil),
	}
	return col
}

type smbSharesCollector struct {
	smbCollector
}

func (col *smbSharesCollector) Collect(ch chan<- prometheus.Metric) {
	sharesTotal := 0
	sharesMap, _ := SMBStatusSharesByMachine()
	for machine, share := range sharesMap {
		sharesCount := len(share)
		ch <- prometheus.MustNewConstMetric(col.dsc[0],
			prometheus.GaugeValue, float64(sharesCount), machine)
		sharesTotal += sharesCount
	}

	ch <- prometheus.MustNewConstMetric(col.dsc[1],
		prometheus.GaugeValue, float64(sharesTotal))
}

func (sme *smbMetricsExporter) newSmbSharesCollector() prometheus.Collector {
	col := &smbSharesCollector{}
	col.sme = sme
	col.dsc = []*prometheus.Desc{
		prometheus.NewDesc(
			collectorName("shares", "machine"),
			"Number of shares by host-machine ip",
			[]string{"machine"}, nil),

		prometheus.NewDesc(
			collectorName("shares", "total"),
			"Total number of active shares",
			[]string{}, nil),
	}
	return col
}

type smbLocksCollector struct {
	smbCollector
}

func (col *smbLocksCollector) Collect(ch chan<- prometheus.Metric) {
	locks, _ := RunSMBStatusLocks()
	ch <- prometheus.MustNewConstMetric(col.dsc[0],
		prometheus.GaugeValue, float64(len(locks)))
}

func (sme *smbMetricsExporter) newSmbLocksCollector() prometheus.Collector {
	col := &smbLocksCollector{}
	col.sme = sme
	col.dsc = []*prometheus.Desc{
		prometheus.NewDesc(
			collectorName("locks", "total"),
			"Total number of active locks",
			[]string{}, nil),
	}
	return col
}

func collectorName(subsystem, name string) string {
	return prometheus.BuildFQName(collectorsNamespace, subsystem, name)
}
