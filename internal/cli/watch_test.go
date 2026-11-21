package cli

import "testing"

func TestParseWatchOptions(t *testing.T) {
	tests := []struct {
		args    []string
		want    int
		wantErr bool
	}{
		{args: nil, want: 0},
		{args: []string{"--jobs", "3"}, want: 3},
		{args: []string{"--jobs=2"}, want: 2},
		{args: []string{"--jobs", "0"}, want: 0},
		{args: []string{"--jobs", "-1"}, wantErr: true},
		{args: []string{"--jobs"}, wantErr: true},
		{args: []string{"--jobs=many"}, wantErr: true},
		{args: []string{"--interval", "1s"}, wantErr: true},
	}
	for _, tc := range tests {
		got, err := parseWatchOptions(tc.args)
		if (err != nil) != tc.wantErr {
			t.Fatalf("parseWatchOptions(%v) err = %v, wantErr %t", tc.args, err, tc.wantErr)
		}
		if !tc.wantErr && got != tc.want {
			t.Fatalf("parseWatchOptions(%v) = %d, want %d", tc.args, got, tc.want)
		}
	}
}
