package telemetry

import (
	"strconv"
	"time"
)

// The OTLP/HTTP JSON shapes the exporter writes: an ExportLogsServiceRequest
// with one resource and one scope. Only the fields used are declared.

type attribute struct {
	Key   string `json:"key"`
	Value value  `json:"value"`
}

type value struct {
	StringValue *string `json:"stringValue,omitempty"`
	IntValue    *string `json:"intValue,omitempty"` // proto3 JSON writes int64 as a string
}

func strAttr(k, v string) attribute { return attribute{Key: k, Value: value{StringValue: &v}} }

func intAttr(k string, v uint64) attribute {
	s := strconv.FormatUint(v, 10)
	return attribute{Key: k, Value: value{IntValue: &s}}
}

type logRecord struct {
	TimeUnixNano         string      `json:"timeUnixNano"`
	ObservedTimeUnixNano string      `json:"observedTimeUnixNano"`
	SeverityNumber       int         `json:"severityNumber"`
	SeverityText         string      `json:"severityText"`
	EventName            string      `json:"eventName"`
	Attributes           []attribute `json:"attributes"`
}

type scopeLogs struct {
	Scope struct {
		Name    string `json:"name"`
		Version string `json:"version"`
	} `json:"scope"`
	LogRecords []logRecord `json:"logRecords"`
}

type resourceLogs struct {
	Resource struct {
		Attributes []attribute `json:"attributes"`
	} `json:"resource"`
	ScopeLogs []scopeLogs `json:"scopeLogs"`
}

type exportRequest struct {
	ResourceLogs []resourceLogs `json:"resourceLogs"`
}

// OTLP severity numbers.
const (
	severityInfo = 9
	severityWarn = 13
)

// payload encodes batch, and a loss record when loss is set.
func (e *Exporter) payload(batch []event, loss bool, dropped, failed uint64) exportRequest {
	records := make([]logRecord, 0, len(batch)+1)
	for _, ev := range batch {
		records = append(records, e.record(ev))
	}
	if loss {
		records = append(records, lossRecord(time.Now().UnixNano(), dropped, failed))
	}
	var sl scopeLogs
	sl.Scope.Name = ScopeName
	sl.Scope.Version = strconv.Itoa(SchemaVersion)
	sl.LogRecords = records
	var rl resourceLogs
	rl.Resource.Attributes = e.resource
	rl.ScopeLogs = []scopeLogs{sl}
	return exportRequest{ResourceLogs: []resourceLogs{rl}}
}

// record encodes one event. It copies only the closed-set fields and the
// lineage pseudonym, by name; nothing else an event holds is written.
func (e *Exporter) record(ev event) logRecord {
	attrs := []attribute{strAttr("barmkin.event", ev.name)}
	severity := severityInfo
	switch ev.name {
	case EventRegister:
		attrs = append(attrs,
			strAttr("barmkin.host", string(ev.host)),
			strAttr("barmkin.lineage", lineageID(e.key, ev.uid, ev.host, ev.root)))
	case EventRaise:
		attrs = append(attrs,
			strAttr("barmkin.host", string(ev.host)),
			strAttr("barmkin.lineage", lineageID(e.key, ev.uid, ev.host, ev.root)),
			strAttr("barmkin.leg", string(ev.leg)),
			strAttr("barmkin.source", string(ev.source)))
	case EventStart:
		attrs = append(attrs, strAttr("barmkin.recovery", string(ev.recovery)))
		if ev.recovery != RecoveryClean {
			severity = severityWarn
		}
	case EventDegraded:
		severity = severityWarn
	}
	return newRecord(ev.name, ev.at.UnixNano(), severity, attrs)
}

func lossRecord(now int64, dropped, failed uint64) logRecord {
	return newRecord(EventLoss, now, severityWarn, []attribute{
		strAttr("barmkin.event", EventLoss),
		intAttr("barmkin.export.dropped", dropped),
		intAttr("barmkin.export.failed", failed),
	})
}

func newRecord(name string, at int64, severity int, attrs []attribute) logRecord {
	ts := strconv.FormatInt(at, 10)
	text := "INFO"
	if severity == severityWarn {
		text = "WARN"
	}
	return logRecord{
		TimeUnixNano:         ts,
		ObservedTimeUnixNano: strconv.FormatInt(time.Now().UnixNano(), 10),
		SeverityNumber:       severity,
		SeverityText:         text,
		EventName:            name,
		Attributes:           attrs,
	}
}
