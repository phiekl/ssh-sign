// Copyright 2026 Philip Eklöf
//
// SPDX-License-Identifier: MIT

package cli

import (
	"encoding/json"
	"errors"
	"testing"
)

type testData struct {
	Value string `json:"value"`
}

func (d *testData) String() string { return d.Value }

func TestNewResultDropsNils(t *testing.T) {
	var data *testData
	var err *UsageError
	res := NewResult(data, []error{nil, err})
	if res.Data != nil || res.Error != nil {
		t.Errorf("NewResult() = %#v, want empty", res)
	}
}

func TestResultJSON(t *testing.T) {
	tests := []struct {
		res  Result
		want string
	}{
		{NewResult(nil, nil), `{}`},
		{NewResult(&testData{"x"}, nil), `{"result":{"value":"x"}}`},
		{NewResult(&testData{"x"}, []error{errors.New("bad")}), `{"error":["bad"],"result":{"value":"x"}}`},
	}
	for _, tt := range tests {
		got, err := json.Marshal(tt.res)
		if err != nil {
			t.Fatalf("json.Marshal() error = %v", err)
		}
		if string(got) != tt.want {
			t.Errorf("json.Marshal() = %s, want %s", got, tt.want)
		}
	}
}
