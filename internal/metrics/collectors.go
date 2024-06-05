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
		sme.newSMBVersionsCollector(),
		sme.newSMBActivityCollector(),
		sme.newSMBServicesCollector(),
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

func (sme *smbMetricsExporter) newSMBVersionsCollector() prometheus.Collector {
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

type smbActivityCollector struct {
	smbCollector
}

func (col *smbActivityCollector) Collect(ch chan<- prometheus.Metric) {
	totalSessions := 0
	totalTreeCons := 0
	totalConnectedUsers := 0
	totalOpenFiles := 0
	totalOpenFilesOpens := 0
	totalOpenFilesAccessRW := 0
	smbInfo, err := NewUpdatedSMBInfo()
	if err == nil {
		totalSessions = smbInfo.TotalSessions()
		totalTreeCons = smbInfo.TotalTreeCons()
		totalConnectedUsers = smbInfo.TotalConnectedUsers()
		totalOpenFiles = smbInfo.TotalOpenFiles()
		totalOpenFilesOpens = smbInfo.TotalOpenFilesOpens()
		totalOpenFilesAccessRW = smbInfo.TotalOpenFilesAccessRW()
	}
	ch <- prometheus.MustNewConstMetric(col.dsc[0],
		prometheus.GaugeValue, float64(totalSessions))

	ch <- prometheus.MustNewConstMetric(col.dsc[1],
		prometheus.GaugeValue, float64(totalTreeCons))

	ch <- prometheus.MustNewConstMetric(col.dsc[2],
		prometheus.GaugeValue, float64(totalConnectedUsers))

	ch <- prometheus.MustNewConstMetric(col.dsc[3],
		prometheus.GaugeValue, float64(totalOpenFiles))

	ch <- prometheus.MustNewConstMetric(col.dsc[4],
		prometheus.GaugeValue, float64(totalOpenFilesOpens))

	ch <- prometheus.MustNewConstMetric(col.dsc[5],
		prometheus.GaugeValue, float64(totalOpenFilesAccessRW))
}

func (sme *smbMetricsExporter) newSMBActivityCollector() prometheus.Collector {
	col := &smbActivityCollector{}
	col.sme = sme
	col.dsc = []*prometheus.Desc{
		prometheus.NewDesc(
			collectorName("sessions", "total"),
			"Number of currently active SMB sessions",
			[]string{}, nil),

		prometheus.NewDesc(
			collectorName("tcon", "total"),
			"Number of currently active SMB tree-connections",
			[]string{}, nil),

		prometheus.NewDesc(
			collectorName("users", "total"),
			"Number of currently active SMB users",
			[]string{}, nil),

		prometheus.NewDesc(
			collectorName("openfiles", "total"),
			"Number of currently open files",
			[]string{}, nil),

		prometheus.NewDesc(
			collectorName("openfiles", "opens"),
			"Number of open file-handles",
			[]string{}, nil),

		prometheus.NewDesc(
			collectorName("openfiles", "access_rw"),
			"Number of open files with read-write access mode",
			[]string{}, nil),
	}
	return col
}

type smbServicesCollector struct {
	smbCollector
}

func (col *smbServicesCollector) Collect(ch chan<- prometheus.Metric) {
	smbInfo, _ := NewUpdatedSMBInfo()
	serviceToMachine := smbInfo.MapServiceToMachines()
	for service, machines := range serviceToMachine {
		ch <- prometheus.MustNewConstMetric(col.dsc[0],
			prometheus.GaugeValue,
			float64(len(machines)),
			service)
	}
	machineToServices := smbInfo.MapMachineToServies()
	for machine, services := range machineToServices {
		ch <- prometheus.MustNewConstMetric(col.dsc[1],
			prometheus.GaugeValue,
			float64(len(services)),
			machine)

	}
}

func (sme *smbMetricsExporter) newSMBServicesCollector() prometheus.Collector {
	col := &smbServicesCollector{}
	col.sme = sme
	col.dsc = []*prometheus.Desc{
		prometheus.NewDesc(
			collectorName("service", "remote"),
			"Number of remote machines connected to service",
			[]string{"service"}, nil),

		prometheus.NewDesc(
			collectorName("remote", "service"),
			"Number of services provided to remote machine",
			[]string{"machine"}, nil),
	}
	return col
}

func collectorName(subsystem, name string) string {
	return prometheus.BuildFQName(collectorsNamespace, subsystem, name)
}
