package api

import (
	"strings"
	"testing"

	"github.com/lonelyman0108/cfst-ddns/internal/store"
)

func TestNodeValidationTaskSettings(t *testing.T) {
	d := DefaultTask()
	if d.NodeValidation.Enabled || d.NodeValidation.TimeoutMs != 8000 || d.NodeValidation.MaxCandidates != 20 {
		t.Fatal("new validation must be opt-in with bounded defaults", d.NodeValidation)
	}
	for _, tc := range []struct {
		change func(*store.Task)
		want   string
	}{
		{func(t *store.Task) { t.NodeValidation.NodeFile = "" }, "节点文件路径"},
		{func(t *store.Task) { t.NodeValidation.TestURL = "http://example.com" }, "HTTPS"},
		{func(t *store.Task) { t.NodeValidation.ExpectedStatus = 403 }, "200-299"},
		{func(t *store.Task) { t.Update.RecordCount = 2; t.NodeValidation.MaxCandidates = 1 }, "不能少于"},
		{func(t *store.Task) { t.Targets[0].Proxied = true }, "灰云"},
	} {
		task := DefaultTask()
		task.Name = "validation"
		task.NodeValidation.Enabled = true
		task.NodeValidation.NodeFile = "/data/node.json"
		task.Targets = []store.Target{{Domain: "example.com", RR: "best"}}
		tc.change(&task)
		if err := normalizeTaskIn(nil, &task); err == nil || !strings.Contains(err.Error(), tc.want) {
			t.Errorf("invalid validation setting not rejected: %v, want %s", err, tc.want)
		}
	}
}
