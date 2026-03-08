package server

import (
	"encoding/base64"
	"encoding/json"
	"testing"
)

func TestApplyNodeStrategyMergeDedupeRenamesConflicts(t *testing.T) {
	config := &StrategyConfig{
		StrategyMode:        strategyModeMergeDedupe,
		ManualNodesPriority: defaultManualNodesPriority,
		RenameSuffixFormat:  defaultStrategyRenameSuffix,
	}
	sources := []strategySource{
		{
			Key:      "upstream:1",
			Label:    "up-a",
			Priority: 10,
			Order:    0,
			Nodes: []string{
				"vless://uuid@example.com:443?encryption=none#HK-01",
				"ss://YWVzLTI1Ni1nY206cGFzc0BleGFtcGxlLmNvbTo0NDM=#JP-02",
			},
		},
		{
			Key:      "upstream:2",
			Label:    "up-b",
			Priority: 20,
			Order:    1,
			Nodes: []string{
				"trojan://password@example.net:443#HK-01",
				"ss://YWVzLTI1Ni1nY206cGFzc0BleGFtcGxlLmNvbTo0NDM=#JP-02",
			},
		},
	}

	result := applyNodeStrategy(sources, config)

	if got, want := result.Summary.InputNodes, 4; got != want {
		t.Fatalf("input nodes = %d, want %d", got, want)
	}
	if got, want := result.Summary.DedupedNodes, 1; got != want {
		t.Fatalf("deduped nodes = %d, want %d", got, want)
	}
	if got, want := result.Summary.RenamedNodes, 1; got != want {
		t.Fatalf("renamed nodes = %d, want %d", got, want)
	}
	if got, want := result.Summary.ConflictGroups, 1; got != want {
		t.Fatalf("conflict groups = %d, want %d", got, want)
	}
	if got, want := len(result.Nodes), 3; got != want {
		t.Fatalf("output nodes = %d, want %d", got, want)
	}

	foundRenamed := false
	for _, item := range result.PreviewNodes {
		if item == "HK-01 [up-b]" {
			foundRenamed = true
			break
		}
	}
	if !foundRenamed {
		t.Fatalf("preview nodes missing renamed conflict: %#v", result.PreviewNodes)
	}
}

func TestApplyNodeStrategyPriorityOverrideUsesPriority(t *testing.T) {
	config := &StrategyConfig{
		StrategyMode:        strategyModePriorityOverride,
		ManualNodesPriority: 0,
		RenameSuffixFormat:  defaultStrategyRenameSuffix,
	}
	sources := []strategySource{
		{
			Key:      "upstream:1",
			Label:    "airport-a",
			Priority: 10,
			Order:    0,
			Nodes:    []string{"vless://uuid@example.com:443?encryption=none#SG-01"},
		},
		{
			Key:      "manual:1",
			Label:    defaultManualStrategySourceName,
			Priority: 0,
			Order:    1,
			Nodes:    []string{"trojan://password@example.net:443#SG-01"},
		},
	}

	result := applyNodeStrategy(sources, config)

	if got, want := len(result.Nodes), 1; got != want {
		t.Fatalf("output nodes = %d, want %d", got, want)
	}
	if got, want := result.Summary.DroppedNodes, 1; got != want {
		t.Fatalf("dropped nodes = %d, want %d", got, want)
	}
	if got, want := result.Conflicts[0].WinnerSource, defaultManualStrategySourceName; got != want {
		t.Fatalf("winner source = %s, want %s", got, want)
	}
	if got, want := result.PreviewNodes[0], "SG-01"; got != want {
		t.Fatalf("preview node = %s, want %s", got, want)
	}
}

func TestNodeDisplayNameAndRenameVmess(t *testing.T) {
	payload, err := json.Marshal(map[string]string{
		"v":  "2",
		"ps": "Tokyo-01",
		"add": "example.com",
	})
	if err != nil {
		t.Fatalf("marshal vmess payload: %v", err)
	}
	uri := "vmess://" + base64.StdEncoding.EncodeToString(payload)

	if got, want := nodeDisplayName(uri), "Tokyo-01"; got != want {
		t.Fatalf("display name = %s, want %s", got, want)
	}
	renamed, ok := renameNodeURI(uri, "Tokyo-02")
	if !ok {
		t.Fatalf("rename vmess uri failed")
	}
	if got, want := nodeDisplayName(renamed), "Tokyo-02"; got != want {
		t.Fatalf("renamed display name = %s, want %s", got, want)
	}
}
