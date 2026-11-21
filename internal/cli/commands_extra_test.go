package cli

import "testing"

func TestParseDiffArgs(t *testing.T) {
	tests := []struct {
		name     string
		args     []string
		wantPath string
		wantJobs int
		wantErr  bool
	}{
		{name: "path only", args: []string{"change.patch"}, wantPath: "change.patch"},
		{name: "jobs before path", args: []string{"--jobs", "2", "change.patch"}, wantPath: "change.patch", wantJobs: 2},
		{name: "jobs after path", args: []string{"change.patch", "--jobs=3"}, wantPath: "change.patch", wantJobs: 3},
		{name: "jobs zero", args: []string{"--jobs", "0", "change.patch"}, wantPath: "change.patch", wantJobs: 0},
		{name: "missing path", args: []string{"--jobs", "2"}, wantErr: true},
		{name: "two paths", args: []string{"a.patch", "b.patch"}, wantErr: true},
		{name: "unknown flag", args: []string{"--nope", "a.patch"}, wantErr: true},
		{name: "bad jobs", args: []string{"--jobs", "-1", "a.patch"}, wantErr: true},
		{name: "jobs without value", args: []string{"--jobs"}, wantErr: true},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			path, jobs, err := parseDiffArgs(tc.args)
			if (err != nil) != tc.wantErr {
				t.Fatalf("parseDiffArgs(%v) err = %v, wantErr %t", tc.args, err, tc.wantErr)
			}
			if tc.wantErr {
				return
			}
			if path != tc.wantPath || jobs != tc.wantJobs {
				t.Fatalf("parseDiffArgs(%v) = %q, %d; want %q, %d", tc.args, path, jobs, tc.wantPath, tc.wantJobs)
			}
		})
	}
}

func TestParseStdinArgs(t *testing.T) {
	tests := []struct {
		args    []string
		want    int
		wantErr bool
	}{
		{args: nil, want: 0},
		{args: []string{"--jobs", "2"}, want: 2},
		{args: []string{"--jobs=4"}, want: 4},
		{args: []string{"--jobs", "-1"}, wantErr: true},
		{args: []string{"--jobs"}, wantErr: true},
		{args: []string{"--jobs=many"}, wantErr: true},
		{args: []string{"extra"}, wantErr: true},
	}
	for _, tc := range tests {
		got, err := parseStdinArgs(tc.args)
		if (err != nil) != tc.wantErr {
			t.Fatalf("parseStdinArgs(%v) err = %v, wantErr %t", tc.args, err, tc.wantErr)
		}
		if !tc.wantErr && got != tc.want {
			t.Fatalf("parseStdinArgs(%v) = %d, want %d", tc.args, got, tc.want)
		}
	}
}
