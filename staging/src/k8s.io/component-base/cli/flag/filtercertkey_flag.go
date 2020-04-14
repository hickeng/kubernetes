package flag

import (
	"errors"
	"flag"
	"fmt"
	"sort"
	"strings"
)

// FilterCertKey is a flag value parsing "certfile,keyfile" and "certfile,keyfile:filter,filter,filter".
type FilterCertKey struct {
	CertFile, KeyFile string
	Filters           map[string][]string
}

var _ flag.Value = &FilterCertKey{}

// String returns a normalized (sorted) string representation of the filters
func (fkc *FilterCertKey) String() string {
	sortedKeys := make([]string, 0, len(fkc.Filters))
	for k := range fkc.Filters {
		sortedKeys = append(sortedKeys, k)
	}
	sort.Strings(sortedKeys)

	s := fkc.CertFile + "," + fkc.KeyFile

	first := true
	for _, f := range sortedKeys {
		v := fkc.Filters[f]
		sort.Strings(v)

		if first {
			s = s + ":"
			first = false
		} else {
			s = s + ","
		}
		s = s + f

		vfirst := true
		for _, e := range v {
			if vfirst {
				s = s + "="
				vfirst = false
			} else {
				s = s + "+"
			}
			s = s + e
		}
	}

	return s
}

func (fkc *FilterCertKey) Set(value string) error {
	cs := strings.SplitN(strings.TrimSpace(value), ":", 2)
	if len(cs) != 2 || len(cs[1]) == 0 {
		return errors.New("cert, key and filter list are required")
	}

	ck := strings.Split(strings.TrimSpace(cs[0]), ",")
	if len(ck) != 2 {
		return errors.New("expected comma separated certificate and key file paths")
	}
	fkc.CertFile = strings.TrimSpace(ck[0])
	fkc.KeyFile = strings.TrimSpace(ck[1])

	fkc.Filters = make(map[string][]string)
	fs := strings.Split(strings.TrimSpace(cs[1]), ",")
	for _, ft := range fs {
		fv := strings.SplitN(ft, "=", 2)
		f := strings.TrimSpace(fv[0])
		if len(fv) != 2 {
			return fmt.Errorf("Filter %s must be of the form name=detail", f)
		}

		fkc.Filters[f] = append(fkc.Filters[f], strings.Split(fv[1], "+")...)
	}

	return nil
}

func (*FilterCertKey) Type() string {
	return "FilterCertKey"
}

// FilterCertKeyArray is a flag value parsing FilterCertKeys, each passed with its own
// flag instance (in contrast to comma separated slices).
type FilterCertKeyArray struct {
	value   *[]FilterCertKey
	changed bool
}

var _ flag.Value = &FilterCertKey{}

// NewNamedKeyCertArray creates a new FilterCertKeyArray with the internal value
// pointing to p.
func NewFilterCertKeyArray(p *[]FilterCertKey) *FilterCertKeyArray {
	return &FilterCertKeyArray{
		value: p,
	}
}

func (a *FilterCertKeyArray) Set(val string) error {
	fkc := FilterCertKey{}
	err := fkc.Set(val)
	if err != nil {
		return err
	}
	if !a.changed {
		*a.value = []FilterCertKey{fkc}
		a.changed = true
	} else {
		*a.value = append(*a.value, fkc)
	}
	return nil
}

func (a *FilterCertKeyArray) Type() string {
	return "FilterCertKey"
}

func (a *FilterCertKeyArray) String() string {
	fkcs := make([]string, 0, len(*a.value))
	for i := range *a.value {
		fkcs = append(fkcs, (*a.value)[i].String())
	}
	return "[" + strings.Join(fkcs, ";") + "]"
}
