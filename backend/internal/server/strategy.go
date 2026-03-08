package server

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"sort"
	"strconv"
	"strings"
)

const (
	strategyModeMergeDedupe     = "merge_dedupe"
	strategyModePriorityOverride = "priority_override"
	strategyModeKeepBothRename  = "keep_both_rename"

	defaultStrategyMode             = strategyModeMergeDedupe
	defaultStrategyRenameSuffix     = "[{source}]"
	defaultManualNodesPriority      = 0
	defaultUpstreamPriorityStep     = 10
	maxStrategyPreviewNodes         = 30
	defaultManualStrategySourceName = "manual"

	settingStrategyMode         = "strategy_mode"
	settingManualNodesPriority  = "manual_nodes_priority"
	settingRenameSuffixFormat   = "rename_suffix_format"
	settingUpstreamPriorities   = "upstream_priorities"
)

type StrategyConfig struct {
	StrategyMode        string             `json:"strategy_mode"`
	ManualNodesPriority int                `json:"manual_nodes_priority"`
	RenameSuffixFormat  string             `json:"rename_suffix_format"`
	Upstreams           []StrategyUpstream `json:"upstreams"`
}

type StrategyUpstream struct {
	ID       int    `json:"id"`
	Name     string `json:"name,omitempty"`
	Priority int    `json:"priority"`
}

type StrategyPreview struct {
	StrategyMode string             `json:"strategy_mode"`
	Summary      StrategySummary    `json:"summary"`
	Conflicts    []StrategyConflict `json:"conflicts"`
	PreviewNodes []string           `json:"preview_nodes"`
}

type StrategySummary struct {
	SourceCount    int `json:"source_count"`
	InputNodes     int `json:"input_nodes"`
	OutputNodes    int `json:"output_nodes"`
	DedupedNodes   int `json:"deduped_nodes"`
	RenamedNodes   int `json:"renamed_nodes"`
	DroppedNodes   int `json:"dropped_nodes"`
	ConflictGroups int `json:"conflict_groups"`
}

type StrategyConflict struct {
	Name           string   `json:"name"`
	Resolution     string   `json:"resolution"`
	WinnerSource   string   `json:"winner_source,omitempty"`
	DroppedSources []string `json:"dropped_sources,omitempty"`
	RenamedSources []string `json:"renamed_sources,omitempty"`
}

type strategySource struct {
	Key      string
	Label    string
	Priority int
	Order    int
	Nodes    []string
}

type strategyNode struct {
	URI         string
	DisplayName string
	SourceKey   string
	SourceLabel string
	Priority    int
	SourceOrder int
	NodeOrder   int
	InputIndex  int
	Renamed     bool
}

type strategyResult struct {
	Nodes        []string
	Summary      StrategySummary
	Conflicts    []StrategyConflict
	PreviewNodes []string
}

type strategyRequest struct {
	StrategyMode        *string            `json:"strategy_mode"`
	ManualNodesPriority *int               `json:"manual_nodes_priority"`
	RenameSuffixFormat  *string            `json:"rename_suffix_format"`
	Upstreams           []StrategyUpstream `json:"upstreams"`
}

func (s *Server) handleGetStrategy(w http.ResponseWriter, r *http.Request) {
	config, err := s.getStrategyConfig(r.Context())
	if err != nil {
		writeError(w, http.StatusInternalServerError, "failed to get strategy")
		return
	}
	writeJSON(w, http.StatusOK, config)
}

func (s *Server) handleUpdateStrategy(w http.ResponseWriter, r *http.Request) {
	config, err := s.decodeStrategyRequest(r.Context(), r)
	if err != nil {
		writeError(w, http.StatusBadRequest, err.Error())
		return
	}
	if err := s.saveStrategyConfig(r.Context(), config); err != nil {
		writeError(w, http.StatusInternalServerError, "failed to save strategy")
		return
	}

	result, err := s.evaluateStrategyFromStore(r.Context(), config)
	if err != nil {
		s.logger.Printf("evaluate strategy after update failed: %v", err)
		result = strategyResult{}
	}
	if s.metrics != nil {
		s.metrics.observeStrategyApply(config.StrategyMode, result.Summary)
	}

	detail := fmt.Sprintf(
		"strategy_mode=%s manual_nodes_priority=%d rename_suffix_format=%s upstreams=%d source_count=%d input_nodes=%d output_nodes=%d deduped_nodes=%d renamed_nodes=%d dropped_nodes=%d conflict_groups=%d",
		config.StrategyMode,
		config.ManualNodesPriority,
		config.RenameSuffixFormat,
		len(config.Upstreams),
		result.Summary.SourceCount,
		result.Summary.InputNodes,
		result.Summary.OutputNodes,
		result.Summary.DedupedNodes,
		result.Summary.RenamedNodes,
		result.Summary.DroppedNodes,
		result.Summary.ConflictGroups,
	)
	if err != nil {
		detail += fmt.Sprintf(" summary_error=%s", err.Error())
	}
	s.writeSystemLog(
		r.Context(),
		"info",
		"strategy",
		"update_strategy",
		detail,
	)
	settings, _ := s.getSettings(r.Context())
	if settings != nil && settings.CacheMode {
		_, _ = s.refreshCache(r.Context())
	}
	writeJSON(w, http.StatusOK, config)
}

func (s *Server) handlePreviewStrategy(w http.ResponseWriter, r *http.Request) {
	config, err := s.decodeStrategyRequest(r.Context(), r)
	if err != nil {
		writeError(w, http.StatusBadRequest, err.Error())
		return
	}
	result, err := s.evaluateStrategyFromStore(r.Context(), config)
	if err != nil {
		writeError(w, http.StatusInternalServerError, fmt.Sprintf("collect strategy sources failed: %v", err))
		return
	}
	if s.metrics != nil {
		s.metrics.observeStrategyPreview(config.StrategyMode, result.Summary)
	}
	s.writeSystemLog(
		r.Context(),
		"info",
		"strategy",
		"preview_strategy",
		fmt.Sprintf("strategy_mode=%s source_count=%d input_nodes=%d output_nodes=%d deduped_nodes=%d renamed_nodes=%d dropped_nodes=%d conflict_groups=%d", config.StrategyMode, result.Summary.SourceCount, result.Summary.InputNodes, result.Summary.OutputNodes, result.Summary.DedupedNodes, result.Summary.RenamedNodes, result.Summary.DroppedNodes, result.Summary.ConflictGroups),
	)
	writeJSON(w, http.StatusOK, StrategyPreview{
		StrategyMode: config.StrategyMode,
		Summary:      result.Summary,
		Conflicts:    result.Conflicts,
		PreviewNodes: result.PreviewNodes,
	})
}

func (s *Server) evaluateStrategyFromStore(ctx context.Context, config *StrategyConfig) (strategyResult, error) {
	sources, err := s.collectStrategySourcesFromStore(ctx, config)
	if err != nil {
		return strategyResult{}, err
	}
	return applyNodeStrategy(sources, config), nil
}

func (s *Server) decodeStrategyRequest(ctx context.Context, r *http.Request) (*StrategyConfig, error) {
	current, err := s.getStrategyConfig(ctx)
	if err != nil {
		return nil, fmt.Errorf("load current strategy: %w", err)
	}

	var req strategyRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil && err != io.EOF {
		return nil, fmt.Errorf("invalid request body")
	}

	if req.StrategyMode != nil {
		current.StrategyMode = strings.TrimSpace(*req.StrategyMode)
	}
	if req.ManualNodesPriority != nil {
		current.ManualNodesPriority = *req.ManualNodesPriority
	}
	if req.RenameSuffixFormat != nil {
		current.RenameSuffixFormat = strings.TrimSpace(*req.RenameSuffixFormat)
	}
	if req.Upstreams != nil {
		updated, err := mergeStrategyUpstreams(current.Upstreams, req.Upstreams)
		if err != nil {
			return nil, err
		}
		current.Upstreams = updated
	}

	if err := normalizeStrategyConfig(current); err != nil {
		return nil, err
	}
	return current, nil
}

func (s *Server) getStrategyConfig(ctx context.Context) (*StrategyConfig, error) {
	config := &StrategyConfig{
		StrategyMode:        defaultStrategyMode,
		ManualNodesPriority: defaultManualNodesPriority,
		RenameSuffixFormat:  defaultStrategyRenameSuffix,
	}

	rows, err := s.db.QueryContext(ctx, `SELECT key, value FROM settings WHERE key IN (?, ?, ?, ?)`, settingStrategyMode, settingManualNodesPriority, settingRenameSuffixFormat, settingUpstreamPriorities)
	if err != nil {
		return nil, fmt.Errorf("query strategy settings: %w", err)
	}
	defer rows.Close()

	priorityMap := make(map[int]int)
	for rows.Next() {
		var key string
		var value string
		if err := rows.Scan(&key, &value); err != nil {
			return nil, fmt.Errorf("scan strategy setting: %w", err)
		}
		switch key {
		case settingStrategyMode:
			config.StrategyMode = strings.TrimSpace(value)
		case settingManualNodesPriority:
			parsed, err := strconv.Atoi(strings.TrimSpace(value))
			if err == nil {
				config.ManualNodesPriority = parsed
			}
		case settingRenameSuffixFormat:
			config.RenameSuffixFormat = strings.TrimSpace(value)
		case settingUpstreamPriorities:
			priorityMap = parseUpstreamPriorityMap(value)
		}
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("iterate strategy settings: %w", err)
	}

	upstreams, err := s.listStrategyUpstreams(ctx, priorityMap)
	if err != nil {
		return nil, err
	}
	config.Upstreams = upstreams
	if err := normalizeStrategyConfig(config); err != nil {
		return nil, err
	}
	return config, nil
}

func (s *Server) listStrategyUpstreams(ctx context.Context, priorityMap map[int]int) ([]StrategyUpstream, error) {
	rows, err := s.db.QueryContext(ctx, `SELECT id, name FROM upstreams ORDER BY id ASC`)
	if err != nil {
		return nil, fmt.Errorf("query strategy upstreams: %w", err)
	}
	defer rows.Close()

	items := make([]StrategyUpstream, 0)
	index := 0
	for rows.Next() {
		var item StrategyUpstream
		if err := rows.Scan(&item.ID, &item.Name); err != nil {
			return nil, fmt.Errorf("scan strategy upstream: %w", err)
		}
		item.Name = normalizeStrategySourceLabel(item.Name, fmt.Sprintf("upstream-%d", item.ID))
		item.Priority = defaultUpstreamPriority(index)
		if configured, ok := priorityMap[item.ID]; ok {
			item.Priority = configured
		}
		items = append(items, item)
		index++
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("iterate strategy upstreams: %w", err)
	}
	return items, nil
}

func (s *Server) saveStrategyConfig(ctx context.Context, config *StrategyConfig) error {
	if err := normalizeStrategyConfig(config); err != nil {
		return err
	}
	if err := s.setSetting(ctx, settingStrategyMode, config.StrategyMode); err != nil {
		return err
	}
	if err := s.setSetting(ctx, settingManualNodesPriority, strconv.Itoa(config.ManualNodesPriority)); err != nil {
		return err
	}
	if err := s.setSetting(ctx, settingRenameSuffixFormat, config.RenameSuffixFormat); err != nil {
		return err
	}
	if err := s.setSetting(ctx, settingUpstreamPriorities, stringifyUpstreamPriorityMap(config.Upstreams)); err != nil {
		return err
	}
	return nil
}

func normalizeStrategyConfig(config *StrategyConfig) error {
	if config == nil {
		return fmt.Errorf("strategy config is required")
	}
	mode := strings.TrimSpace(strings.ToLower(config.StrategyMode))
	if mode == "" {
		mode = defaultStrategyMode
	}
	switch mode {
	case strategyModeMergeDedupe, strategyModePriorityOverride, strategyModeKeepBothRename:
		config.StrategyMode = mode
	default:
		return fmt.Errorf("invalid strategy_mode")
	}
	config.RenameSuffixFormat = strings.TrimSpace(config.RenameSuffixFormat)
	if config.RenameSuffixFormat == "" {
		config.RenameSuffixFormat = defaultStrategyRenameSuffix
	}
	sort.Slice(config.Upstreams, func(i, j int) bool {
		return config.Upstreams[i].ID < config.Upstreams[j].ID
	})
	for index := range config.Upstreams {
		config.Upstreams[index].Name = normalizeStrategySourceLabel(config.Upstreams[index].Name, fmt.Sprintf("upstream-%d", config.Upstreams[index].ID))
		if config.Upstreams[index].Priority == 0 {
			config.Upstreams[index].Priority = defaultUpstreamPriority(index)
		}
	}
	return nil
}

func mergeStrategyUpstreams(current []StrategyUpstream, updates []StrategyUpstream) ([]StrategyUpstream, error) {
	merged := append([]StrategyUpstream(nil), current...)
	indexByID := make(map[int]int, len(merged))
	for index, item := range merged {
		indexByID[item.ID] = index
	}
	for _, update := range updates {
		index, ok := indexByID[update.ID]
		if !ok {
			return nil, fmt.Errorf("unknown upstream id: %d", update.ID)
		}
		if update.Priority == 0 {
			return nil, fmt.Errorf("priority must not be zero for upstream %d", update.ID)
		}
		merged[index].Priority = update.Priority
	}
	return merged, nil
}

func parseUpstreamPriorityMap(raw string) map[int]int {
	raw = strings.TrimSpace(raw)
	if raw == "" {
		return make(map[int]int)
	}
	var decoded map[string]int
	if err := json.Unmarshal([]byte(raw), &decoded); err != nil {
		return make(map[int]int)
	}
	result := make(map[int]int, len(decoded))
	for key, value := range decoded {
		id, err := strconv.Atoi(strings.TrimSpace(key))
		if err != nil || id <= 0 {
			continue
		}
		result[id] = value
	}
	return result
}

func stringifyUpstreamPriorityMap(upstreams []StrategyUpstream) string {
	encoded := make(map[string]int, len(upstreams))
	for _, item := range upstreams {
		encoded[strconv.Itoa(item.ID)] = item.Priority
	}
	payload, err := json.Marshal(encoded)
	if err != nil {
		return "{}"
	}
	return string(payload)
}

func defaultUpstreamPriority(index int) int {
	if index < 0 {
		index = 0
	}
	return (index + 1) * defaultUpstreamPriorityStep
}

func normalizeStrategySourceLabel(value, fallback string) string {
	value = strings.TrimSpace(value)
	if value == "" {
		return fallback
	}
	return value
}

func (s *Server) collectStrategySourcesFromStore(ctx context.Context, config *StrategyConfig) ([]strategySource, error) {
	priorityMap := strategyPriorityMap(config)
	sources := make([]strategySource, 0)
	order := 0

	rows, err := s.db.QueryContext(ctx, `SELECT id, name, cached_content FROM upstreams WHERE enabled = 1 ORDER BY id ASC`)
	if err != nil {
		return nil, fmt.Errorf("query upstream cache: %w", err)
	}
	defer rows.Close()
	for rows.Next() {
		var id int
		var name string
		var cached string
		if err := rows.Scan(&id, &name, &cached); err != nil {
			return nil, fmt.Errorf("scan upstream cache: %w", err)
		}
		nodes := splitNodes(cached)
		if len(nodes) == 0 {
			continue
		}
		sources = append(sources, strategySource{
			Key:      fmt.Sprintf("upstream:%d", id),
			Label:    normalizeStrategySourceLabel(name, fmt.Sprintf("upstream-%d", id)),
			Priority: priorityMap[id],
			Order:    order,
			Nodes:    nodes,
		})
		order++
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("iterate upstream cache: %w", err)
	}

	manualRows, err := s.db.QueryContext(ctx, `SELECT id, raw_uri FROM manual_nodes WHERE enabled = 1 ORDER BY id ASC`)
	if err != nil {
		return nil, fmt.Errorf("query manual nodes: %w", err)
	}
	defer manualRows.Close()
	for manualRows.Next() {
		var id int
		var raw string
		if err := manualRows.Scan(&id, &raw); err != nil {
			return nil, fmt.Errorf("scan manual node: %w", err)
		}
		raw = strings.TrimSpace(raw)
		if raw == "" || !isNodeURI(raw) {
			continue
		}
		sources = append(sources, strategySource{
			Key:      fmt.Sprintf("manual:%d", id),
			Label:    defaultManualStrategySourceName,
			Priority: config.ManualNodesPriority,
			Order:    order,
			Nodes:    []string{raw},
		})
		order++
	}
	if err := manualRows.Err(); err != nil {
		return nil, fmt.Errorf("iterate manual nodes: %w", err)
	}
	return sources, nil
}

func (s *Server) collectStrategySourcesRealtime(ctx context.Context, config *StrategyConfig) ([]strategySource, error) {
	priorityMap := strategyPriorityMap(config)
	sources := make([]strategySource, 0)
	order := 0

	rows, err := s.db.QueryContext(ctx, `SELECT id, name, url, enabled, cached_content, last_status FROM upstreams ORDER BY id ASC`)
	if err != nil {
		return nil, fmt.Errorf("query upstreams: %w", err)
	}
	defer rows.Close()
	for rows.Next() {
		var id int
		var name string
		var upstreamURL string
		var enabledInt int
		var cachedContent string
		var lastStatus string
		if err := rows.Scan(&id, &name, &upstreamURL, &enabledInt, &cachedContent, &lastStatus); err != nil {
			return nil, fmt.Errorf("scan upstream: %w", err)
		}
		if enabledInt != 1 {
			continue
		}
		nodes := splitNodes(cachedContent)
		if !strings.HasPrefix(strings.ToLower(strings.TrimSpace(lastStatus)), "manual raw import") {
			fetched, fetchErr := s.fetchUpstreamNodes(ctx, strings.TrimSpace(upstreamURL))
			if fetchErr == nil {
				nodes = fetched
			} else {
				s.logger.Printf("realtime fetch upstream %d failed: %v", id, fetchErr)
			}
		}
		if len(nodes) == 0 {
			continue
		}
		sources = append(sources, strategySource{
			Key:      fmt.Sprintf("upstream:%d", id),
			Label:    normalizeStrategySourceLabel(name, fmt.Sprintf("upstream-%d", id)),
			Priority: priorityMap[id],
			Order:    order,
			Nodes:    nodes,
		})
		order++
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("iterate upstreams: %w", err)
	}

	manualRows, err := s.db.QueryContext(ctx, `SELECT id, raw_uri FROM manual_nodes WHERE enabled = 1 ORDER BY id ASC`)
	if err != nil {
		return nil, fmt.Errorf("query manual nodes: %w", err)
	}
	defer manualRows.Close()
	for manualRows.Next() {
		var id int
		var raw string
		if err := manualRows.Scan(&id, &raw); err != nil {
			return nil, fmt.Errorf("scan manual node: %w", err)
		}
		raw = strings.TrimSpace(raw)
		if raw == "" || !isNodeURI(raw) {
			continue
		}
		sources = append(sources, strategySource{
			Key:      fmt.Sprintf("manual:%d", id),
			Label:    defaultManualStrategySourceName,
			Priority: config.ManualNodesPriority,
			Order:    order,
			Nodes:    []string{raw},
		})
		order++
	}
	if err := manualRows.Err(); err != nil {
		return nil, fmt.Errorf("iterate manual nodes: %w", err)
	}
	return sources, nil
}

func strategyPriorityMap(config *StrategyConfig) map[int]int {
	result := make(map[int]int, len(config.Upstreams))
	for index, item := range config.Upstreams {
		priority := item.Priority
		if priority == 0 {
			priority = defaultUpstreamPriority(index)
		}
		result[item.ID] = priority
	}
	return result
}

func applyNodeStrategy(sources []strategySource, config *StrategyConfig) strategyResult {
	flattened := flattenStrategyNodes(sources)
	result := strategyResult{}
	result.Summary.SourceCount = len(sources)
	result.Summary.InputNodes = len(flattened)

	if len(flattened) == 0 {
		return result
	}

	exactDeduped := dedupeStrategyNodes(flattened)
	result.Summary.DedupedNodes = len(flattened) - len(exactDeduped)

	grouped := groupStrategyNodesByName(exactDeduped)
	finalNodes := make([]strategyNode, 0, len(exactDeduped))
	usedNames := make(map[string]struct{})
	for _, item := range exactDeduped {
		if item.DisplayName != "" {
			usedNames[strings.ToLower(item.DisplayName)] = struct{}{}
		}
	}

	for _, group := range grouped {
		if len(group) == 0 {
			continue
		}
		if len(group) == 1 || group[0].DisplayName == "" {
			finalNodes = append(finalNodes, group...)
			continue
		}

		result.Summary.ConflictGroups++
		sortStrategyNodes(group)
		primary := group[0]
		finalNodes = append(finalNodes, primary)
		switch config.StrategyMode {
		case strategyModePriorityOverride:
			dropped := make([]string, 0, len(group)-1)
			for _, item := range group[1:] {
				dropped = append(dropped, item.SourceLabel)
			}
			result.Summary.DroppedNodes += len(group) - 1
			result.Conflicts = append(result.Conflicts, StrategyConflict{
				Name:           primary.DisplayName,
				Resolution:     "kept_higher_priority",
				WinnerSource:   primary.SourceLabel,
				DroppedSources: uniqueStrings(dropped),
			})
		default:
			renamedSources := make([]string, 0, len(group)-1)
			localNames := map[string]struct{}{strings.ToLower(primary.DisplayName): {}}
			for _, item := range group[1:] {
				candidateName := makeRenamedNodeName(item.DisplayName, config.RenameSuffixFormat, item.SourceLabel)
				candidateName = makeUniqueNodeName(candidateName, localNames)
				rawNameKey := strings.ToLower(candidateName)
				localNames[rawNameKey] = struct{}{}
				usedNames[rawNameKey] = struct{}{}
				renamedURI, ok := renameNodeURI(item.URI, candidateName)
				if ok {
					item.URI = renamedURI
					item.DisplayName = candidateName
					item.Renamed = true
					result.Summary.RenamedNodes++
				}
				renamedSources = append(renamedSources, item.SourceLabel)
				finalNodes = append(finalNodes, item)
			}
			result.Conflicts = append(result.Conflicts, StrategyConflict{
				Name:           primary.DisplayName,
				Resolution:     "renamed_conflicts",
				WinnerSource:   primary.SourceLabel,
				RenamedSources: uniqueStrings(renamedSources),
			})
		}
	}

	sort.Slice(finalNodes, func(i, j int) bool {
		if finalNodes[i].DisplayName != finalNodes[j].DisplayName {
			return finalNodes[i].DisplayName < finalNodes[j].DisplayName
		}
		return finalNodes[i].URI < finalNodes[j].URI
	})

	result.Nodes = make([]string, 0, len(finalNodes))
	preview := make([]string, 0, len(finalNodes))
	for _, item := range finalNodes {
		result.Nodes = append(result.Nodes, item.URI)
		name := strings.TrimSpace(item.DisplayName)
		if name == "" {
			name = item.URI
		}
		preview = append(preview, name)
	}
	if len(preview) > maxStrategyPreviewNodes {
		preview = preview[:maxStrategyPreviewNodes]
	}
	result.PreviewNodes = preview
	result.Summary.OutputNodes = len(result.Nodes)
	return result
}

func flattenStrategyNodes(sources []strategySource) []strategyNode {
	items := make([]strategyNode, 0)
	inputIndex := 0
	for _, source := range sources {
		for nodeOrder, raw := range source.Nodes {
			uri := strings.TrimSpace(raw)
			if uri == "" {
				continue
			}
			items = append(items, strategyNode{
				URI:         uri,
				DisplayName: nodeDisplayName(uri),
				SourceKey:   source.Key,
				SourceLabel: source.Label,
				Priority:    source.Priority,
				SourceOrder: source.Order,
				NodeOrder:   nodeOrder,
				InputIndex:  inputIndex,
			})
			inputIndex++
		}
	}
	return items
}

func dedupeStrategyNodes(items []strategyNode) []strategyNode {
	chosen := make(map[string]strategyNode, len(items))
	for _, item := range items {
		key := strings.TrimSpace(item.URI)
		if key == "" {
			continue
		}
		current, ok := chosen[key]
		if !ok || preferStrategyNode(item, current) {
			chosen[key] = item
		}
	}
	result := make([]strategyNode, 0, len(chosen))
	for _, item := range chosen {
		result = append(result, item)
	}
	sortStrategyNodes(result)
	return result
}

func groupStrategyNodesByName(items []strategyNode) [][]strategyNode {
	groupsByName := make(map[string][]strategyNode)
	order := make([]string, 0)
	standalone := make([][]strategyNode, 0)
	for _, item := range items {
		name := strings.TrimSpace(item.DisplayName)
		if name == "" {
			standalone = append(standalone, []strategyNode{item})
			continue
		}
		key := strings.ToLower(name)
		if _, ok := groupsByName[key]; !ok {
			order = append(order, key)
		}
		groupsByName[key] = append(groupsByName[key], item)
	}
	groups := make([][]strategyNode, 0, len(order)+len(standalone))
	for _, key := range order {
		groups = append(groups, groupsByName[key])
	}
	groups = append(groups, standalone...)
	return groups
}

func preferStrategyNode(candidate, current strategyNode) bool {
	if candidate.Priority != current.Priority {
		return candidate.Priority < current.Priority
	}
	if candidate.SourceOrder != current.SourceOrder {
		return candidate.SourceOrder < current.SourceOrder
	}
	if candidate.NodeOrder != current.NodeOrder {
		return candidate.NodeOrder < current.NodeOrder
	}
	return candidate.URI < current.URI
}

func sortStrategyNodes(items []strategyNode) {
	sort.Slice(items, func(i, j int) bool {
		if items[i].Priority != items[j].Priority {
			return items[i].Priority < items[j].Priority
		}
		if items[i].DisplayName != items[j].DisplayName {
			return items[i].DisplayName < items[j].DisplayName
		}
		if items[i].SourceOrder != items[j].SourceOrder {
			return items[i].SourceOrder < items[j].SourceOrder
		}
		if items[i].NodeOrder != items[j].NodeOrder {
			return items[i].NodeOrder < items[j].NodeOrder
		}
		return items[i].URI < items[j].URI
	})
}

func nodeDisplayName(uri string) string {
	trimmed := strings.TrimSpace(uri)
	if trimmed == "" {
		return ""
	}
	if strings.HasPrefix(strings.ToLower(trimmed), "vmess://") {
		if name := decodeVmessName(trimmed); name != "" {
			return name
		}
	}
	if index := strings.Index(trimmed, "#"); index >= 0 && index+1 < len(trimmed) {
		fragment := trimmed[index+1:]
		decoded, err := url.QueryUnescape(fragment)
		if err == nil {
			fragment = decoded
		}
		return strings.TrimSpace(fragment)
	}
	return ""
}

func renameNodeURI(uri, newName string) (string, bool) {
	trimmed := strings.TrimSpace(uri)
	newName = strings.TrimSpace(newName)
	if trimmed == "" || newName == "" {
		return trimmed, false
	}
	if strings.HasPrefix(strings.ToLower(trimmed), "vmess://") {
		renamed, ok := renameVmessURI(trimmed, newName)
		if ok {
			return renamed, true
		}
	}
	base := trimmed
	if index := strings.Index(base, "#"); index >= 0 {
		base = base[:index]
	}
	return base + "#" + url.QueryEscape(newName), true
}

func decodeVmessName(uri string) string {
	payload, _, ok := decodeVmessPayload(uri)
	if !ok {
		return ""
	}
	var raw map[string]any
	if err := json.Unmarshal(payload, &raw); err != nil {
		return ""
	}
	value, _ := raw["ps"].(string)
	return strings.TrimSpace(value)
}

func renameVmessURI(uri, newName string) (string, bool) {
	payload, useRaw, ok := decodeVmessPayload(uri)
	if !ok {
		return uri, false
	}
	var raw map[string]any
	if err := json.Unmarshal(payload, &raw); err != nil {
		return uri, false
	}
	raw["ps"] = newName
	encodedPayload, err := json.Marshal(raw)
	if err != nil {
		return uri, false
	}
	if useRaw {
		return "vmess://" + base64.RawStdEncoding.EncodeToString(encodedPayload), true
	}
	return "vmess://" + base64.StdEncoding.EncodeToString(encodedPayload), true
}

func decodeVmessPayload(uri string) ([]byte, bool, bool) {
	trimmed := strings.TrimSpace(uri)
	if !strings.HasPrefix(strings.ToLower(trimmed), "vmess://") {
		return nil, false, false
	}
	payload := strings.TrimSpace(trimmed[len("vmess://"):])
	decoded, err := base64.StdEncoding.DecodeString(payload)
	if err == nil {
		return decoded, false, true
	}
	decoded, err = base64.RawStdEncoding.DecodeString(payload)
	if err == nil {
		return decoded, true, true
	}
	return nil, false, false
}

func makeRenamedNodeName(name, suffixFormat, sourceLabel string) string {
	suffix := strings.TrimSpace(strings.ReplaceAll(suffixFormat, "{source}", strings.TrimSpace(sourceLabel)))
	if suffix == "" {
		suffix = strings.TrimSpace(sourceLabel)
	}
	name = strings.TrimSpace(name)
	if name == "" {
		return suffix
	}
	return strings.TrimSpace(name + " " + suffix)
}

func makeUniqueNodeName(base string, existing map[string]struct{}) string {
	base = strings.TrimSpace(base)
	if base == "" {
		base = "node"
	}
	if _, ok := existing[strings.ToLower(base)]; !ok {
		return base
	}
	for index := 2; ; index++ {
		candidate := fmt.Sprintf("%s (%d)", base, index)
		if _, ok := existing[strings.ToLower(candidate)]; !ok {
			return candidate
		}
	}
}

func uniqueStrings(items []string) []string {
	seen := make(map[string]struct{}, len(items))
	result := make([]string, 0, len(items))
	for _, item := range items {
		item = strings.TrimSpace(item)
		if item == "" {
			continue
		}
		if _, ok := seen[item]; ok {
			continue
		}
		seen[item] = struct{}{}
		result = append(result, item)
	}
	sort.Strings(result)
	return result
}
