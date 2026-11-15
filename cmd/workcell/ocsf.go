// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Omkhar Arasaratnam

package main

import (
	"encoding/json"
	"time"

	"github.com/omkhar/workcell/v2/internal/audit"
)

// ocsfEvent is one audit record as an OCSF 1.3.0 event. Its fields are those of the record and a
// constant per kind, so the same record gives the same bytes, and, as the record holds no secret
// value, neither does the event.
type ocsfEvent struct {
	ActivityID   int           `json:"activity_id"`
	ActivityName string        `json:"activity_name,omitempty"`
	CategoryUID  int           `json:"category_uid"`
	ClassUID     int           `json:"class_uid"`
	TypeUID      int           `json:"type_uid"` // class_uid*100 + activity_id
	Time         int64         `json:"time"`     // milliseconds since the epoch
	SeverityID   int           `json:"severity_id"`
	StatusID     int           `json:"status_id"` // 1 success, 2 failure
	StatusDetail string        `json:"status_detail,omitempty"`
	Message      string        `json:"message"`
	ActionID     int           `json:"action_id,omitempty"` // 1 allowed, 2 denied
	App          *ocsfApp      `json:"app,omitempty"`
	Dst          *ocsfEndpoint `json:"dst_endpoint,omitempty"`
	Metadata     ocsfMetadata  `json:"metadata"`
	Unmapped     *ocsfUnmapped `json:"unmapped,omitempty"`
}

type ocsfApp struct {
	Name string `json:"name"`
}

type ocsfEndpoint struct {
	Hostname string `json:"hostname,omitempty"`
	Port     uint16 `json:"port,omitempty"`
}

type ocsfMetadata struct {
	Version string  `json:"version"`
	Product ocsfApp `json:"product"`
}

type ocsfUnmapped struct {
	Event  string `json:"event,omitempty"`
	Name   string `json:"name,omitempty"`
	Header string `json:"header,omitempty"`
}

// ocsfLine is the event for d, as one line of JSON with no newline. A host is shown as SafeHost
// shows it, as in the text form.
func ocsfLine(d audit.Record) []byte {
	ev := ocsfEvent{
		Message:  d.Event,
		StatusID: 1,
		Metadata: ocsfMetadata{Version: "1.3.0", Product: ocsfApp{Name: "workcell"}},
	}
	if t, err := time.Parse(time.RFC3339Nano, d.Time); err == nil {
		ev.Time = t.UnixMilli()
	}
	host := audit.SafeHost(d.Host)
	switch d.Event {
	case audit.SessionStart, audit.SessionEnd: // Application Lifecycle: Start, Stop
		ev.CategoryUID, ev.ClassUID, ev.ActivityID, ev.App = 6, 6002, 3, &ocsfApp{Name: "workcell"}
		if d.Event == audit.SessionEnd {
			ev.ActivityID = 4
		}
	case audit.Connect: // Network Activity: Open, or Refuse
		ev.CategoryUID, ev.ClassUID, ev.ActivityID, ev.ActionID = 4, 4001, 1, 1
		ev.Dst = &ocsfEndpoint{Hostname: host, Port: d.Port}
		if d.Result != audit.Allowed {
			ev.ActivityID, ev.ActionID, ev.StatusID, ev.StatusDetail = 5, 2, 2, d.Result
		}
	case audit.Secret: // API Activity: Other, the broker's use of a secret for a host
		ev.CategoryUID, ev.ClassUID, ev.ActivityID, ev.ActivityName = 6, 6003, 99, "secret_use"
		ev.Dst, ev.StatusDetail = &ocsfEndpoint{Hostname: host}, d.Result
		ev.Unmapped = &ocsfUnmapped{Name: d.Name, Header: d.Header}
		switch d.Result {
		case "granted", "refresh_granted", "signed_in", "refreshed":
		default:
			ev.StatusID = 2
		}
	default: // Base Event: the log_full marker
		ev.Unmapped = &ocsfUnmapped{Event: d.Event}
	}
	ev.TypeUID = ev.ClassUID*100 + ev.ActivityID
	line, _ := json.Marshal(ev)
	return line
}
