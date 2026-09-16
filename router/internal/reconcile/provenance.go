package reconcile

import (
	"encoding/json"

	"router/internal/platform"
	"router/internal/state"
)

// RouteProvenance tracks which routes routerd installed. iproute2 builds
// differ in `comment` support, so provenance lives in routerd's own state
// directory instead of kernel route attributes.
type RouteProvenance interface {
	Load() []state.Route
	Save(routes []state.Route) error
}

// MemoryProvenance is a volatile implementation (tests).
type MemoryProvenance struct{ routes []state.Route }

// NewMemoryProvenance returns a volatile provenance store.
func NewMemoryProvenance() *MemoryProvenance { return &MemoryProvenance{} }

// Load returns the managed routes.
func (m *MemoryProvenance) Load() []state.Route { return m.routes }

// Save replaces the managed routes.
func (m *MemoryProvenance) Save(r []state.Route) error { m.routes = r; return nil }

// FileProvenance persists managed routes via the platform executor, so it
// works against both the real filesystem and the simulated backend.
type FileProvenance struct {
	ex   platform.Executor
	path string
}

// NewFileProvenance creates a file-backed provenance at path.
func NewFileProvenance(ex platform.Executor, path string) *FileProvenance {
	return &FileProvenance{ex: ex, path: path}
}

// Load returns the managed routes (empty when the file is missing).
func (f *FileProvenance) Load() []state.Route {
	b, ok := f.ex.File(f.path)
	if !ok {
		return nil
	}
	var out []state.Route
	if err := json.Unmarshal(b, &out); err != nil {
		return nil
	}
	return out
}

// Save atomically replaces the managed routes.
func (f *FileProvenance) Save(r []state.Route) error {
	b, err := json.MarshalIndent(r, "", "  ")
	if err != nil {
		return err
	}
	return f.ex.WriteFile(f.path, b)
}
