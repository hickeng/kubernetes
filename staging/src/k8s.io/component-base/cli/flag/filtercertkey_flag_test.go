package flag

import (
	"fmt"
	"reflect"
	"strings"
	"testing"

	"github.com/spf13/pflag"
)

func TestFilterCertKeyArrayFlag(t *testing.T) {
	tests := []struct {
		args       []string
		def        []FilterCertKey
		expected   []FilterCertKey
		parseError string
	}{
		{
			args:     []string{},
			expected: nil,
		},
		{
			args: []string{"  foo.crt , foo.key   :intf=all "},
			expected: []FilterCertKey{{
				KeyFile:  "foo.key",
				CertFile: "foo.crt",
				Filters:    map[string][]string{
					"intf": []string{"all"},
				},
			}},
		},
		{
			args: []string{"foo.crt,foo.key:intf=abc"},
			expected: []FilterCertKey{{
				KeyFile:  "foo.key",
				CertFile: "foo.crt",
				Filters:    map[string][]string{
					"intf": []string{"abc"},
				},
			}},
		},
		{
			args: []string{"foo.crt,foo.key: abc  "},
			parseError: "Filter abc must be of the form name=detail",
		},
		{
			args:       []string{"foo.crt,foo.key: "},
			parseError: "cert, key and filter list are required",
		},
		{
			args:       []string{"foo.crt,foo.key:"},
			parseError: "cert, key and filter list are required",
		},
		{
			args:       []string{""},
			parseError: "cert, key and filter list are required",
		},
		{
			args:       []string{"   "},
			parseError: "cert, key and filter list are required",
		},
		{
			args:       []string{"a,b,c:f=v"},
			parseError: "expected comma separated certificate and key file paths",
		},
		{
			args: []string{"foo.crt,foo.key:interface=abc+def+ghi"},
			expected: []FilterCertKey{{
				KeyFile:  "foo.key",
				CertFile: "foo.crt",
				Filters:    map[string][]string{
					"interface": []string{"abc","def","ghi"},
				},
			}},
		},
		{
			args: []string{"foo.crt,foo.key:exclude-cidrs=10.0.0.0/8"},
			expected: []FilterCertKey{{
				KeyFile:  "foo.key",
				CertFile: "foo.crt",
				Filters:    map[string][]string{
					"exclude-cidrs": []string{"10.0.0.0/8"},
				},
			}},
		},
		{
			args: []string{"foo.crt,foo.key:exclude-cidrs=10.0.0.0/8+20.10.0.0/16"},
			expected: []FilterCertKey{{
				KeyFile:  "foo.key",
				CertFile: "foo.crt",
				Filters:    map[string][]string{
					"exclude-cidrs": []string{"10.0.0.0/8", "20.10.0.0/16"},
				},
			}},
		},
		{
			args: []string{"foo.crt,foo.key:interface=abc,exclude-cidrs=10.0.0.0/8+20.10.0.0/16"},
			expected: []FilterCertKey{{
				KeyFile:  "foo.key",
				CertFile: "foo.crt",
				Filters:    map[string][]string{
					"interface": []string{"abc"},
					"exclude-cidrs": []string{"10.0.0.0/8", "20.10.0.0/16"},
				},
			}},
		},
		{
			args: []string{"foo.crt,foo.key:hello=world", "bar.crt,bar.key:goodbye=all"},
			expected: []FilterCertKey{{
				KeyFile:  "foo.key",
				CertFile: "foo.crt",
				Filters:    map[string][]string{
					"hello": []string{"world"},
				},
			}, {
				KeyFile:  "bar.key",
				CertFile: "bar.crt",
				Filters:    map[string][]string{
					"goodbye": []string{"all"},
				},
			}},
		},
	}
	for i, test := range tests {
		fs := pflag.NewFlagSet("testFilterCertKeyArray", pflag.ContinueOnError)
		var fkcs []FilterCertKey
		fkcs = append(fkcs, test.def...)

		fs.Var(NewFilterCertKeyArray(&fkcs), "tls-filter-cert-key", "usage")

		args := []string{}
		for _, a := range test.args {
			args = append(args, fmt.Sprintf("--tls-filter-cert-key=%s", a))
		}

		err := fs.Parse(args)
		if test.parseError != "" {
			if err == nil {
				t.Errorf("%d: expected error %q, got nil", i, test.parseError)
			} else if !strings.Contains(err.Error(), test.parseError) {
				t.Errorf("%d: expected error %q, got %q", i, test.parseError, err)
			}
		} else if err != nil {
			t.Errorf("%d: expected nil error, got %v", i, err)
		}
		if !reflect.DeepEqual(fkcs, test.expected) {
			t.Errorf("%d: expected %+v, got %+v", i, test.expected, fkcs)
		}
	}
}