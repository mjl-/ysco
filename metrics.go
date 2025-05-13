package main

import (
	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/promauto"
)

var (
	metricTlogSecurityError = promauto.NewCounter(
		prometheus.CounterOpts{
			Name: "ysco_tlog_security_errors_total",
			Help: "Number of tlog security errors, any number > 0 is bad.",
		},
	)
	metricMonitorError = promauto.NewCounter(
		prometheus.CounterOpts{
			Name: "ysco_monitor_errors_total",
			Help: "Number of errors encountered while looking for latest versions of module or toolchain.",
		},
	)
	metricDownloadError = promauto.NewCounter(
		prometheus.CounterOpts{
			Name: "ysco_download_errors_total",
			Help: "Number of errors encountered while downloading a new binary.",
		},
	)
	metricUpdateError = promauto.NewCounter(
		prometheus.CounterOpts{
			Name: "ysco_update_errors_total",
			Help: "Number of errors encountered while trying to update to a new version.",
		},
	)
	metricUpdatesPaused = promauto.NewGauge(
		prometheus.GaugeOpts{
			Name: "ysco_updates_paused",
			Help: "Whether automated updates are paused. Manual updates are still possible.",
		},
	)
	metricSvcUpdateAvailable = promauto.NewGauge(
		prometheus.GaugeOpts{
			Name: "ysco_service_update_available",
			Help: "Whether updates for the managed service that match the policies are available for installation.",
		},
	)
	metricSvcVersionAvailable = promauto.NewGauge(
		prometheus.GaugeOpts{
			Name: "ysco_service_newer_version_available",
			Help: "Whether a newer version for the managed service is available, regardless of goversion or policies.",
		},
	)
	metricSvcGoVersionAvailable = promauto.NewGauge(
		prometheus.GaugeOpts{
			Name: "ysco_service_newer_goversion_available",
			Help: "Whether a newer go version for the managed service is available, regardless of version or policies.",
		},
	)
	metricSvcUpdateScheduled = promauto.NewGauge(
		prometheus.GaugeOpts{
			Name: "ysco_service_update_scheduled",
			Help: "Whether updates for managed service are scheduled.",
		},
	)
	metricSvcUpdateRollback = promauto.NewCounter(
		prometheus.CounterOpts{
			Name: "ysco_service_update_rollback_total",
			Help: "Number of rollbacks after attempting to update.",
		},
	)
	metricSelfUpdateAvailable = promauto.NewGauge(
		prometheus.GaugeOpts{
			Name: "ysco_self_update_available",
			Help: "Whether updates for ysco that match the policies are available for installation.",
		},
	)
	metricSelfVersionAvailable = promauto.NewGauge(
		prometheus.GaugeOpts{
			Name: "ysco_self_newer_version_available",
			Help: "Whether a newer version for ysco is available, regardless of goversion or policies.",
		},
	)
	metricSelfGoVersionAvailable = promauto.NewGauge(
		prometheus.GaugeOpts{
			Name: "ysco_self_newer_goversion_available",
			Help: "Whether a newer go version for ysco is available, regardless of version or policies.",
		},
	)
	metricSelfUpdateScheduled = promauto.NewGauge(
		prometheus.GaugeOpts{
			Name: "ysco_self_update_scheduled",
			Help: "Whether for ysco updates are scheduled.",
		},
	)
	metricSvcVersion = promauto.NewGaugeVec(
		prometheus.GaugeOpts{
			Name: "ysco_service_version",
			Help: "Current of version of managed service.",
		},
		[]string{"version"},
	)
	metricSvcGoVersion = promauto.NewGaugeVec(
		prometheus.GaugeOpts{
			Name: "ysco_service_goversion",
			Help: "Current of go version of managed service.",
		},
		[]string{"version"},
	)
	metricSvcModPath = promauto.NewGaugeVec(
		prometheus.GaugeOpts{
			Name: "ysco_service_module_path",
			Help: "Module path of managed service.",
		},
		[]string{"path"},
	)
	metricSelfVersion = promauto.NewGaugeVec(
		prometheus.GaugeOpts{
			Name: "ysco_self_version",
			Help: "Current of version of ysco.",
		},
		[]string{"version"},
	)
)
