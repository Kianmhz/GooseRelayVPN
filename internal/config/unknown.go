package config

import (
	"encoding/json"
	"reflect"
	"sort"
	"strings"
)

func unknownJSONFields(body []byte, schema any) ([]string, error) {
	var raw map[string]json.RawMessage
	if err := json.Unmarshal(body, &raw); err != nil {
		return nil, err
	}
	known := jsonFieldSet(schema)
	var out []string
	for key := range raw {
		if strings.HasPrefix(key, "_comment") {
			continue
		}
		if !known[key] {
			out = append(out, key)
		}
	}
	sort.Strings(out)
	return out, nil
}

func jsonFieldSet(schema any) map[string]bool {
	t := reflect.TypeOf(schema)
	if t.Kind() == reflect.Pointer {
		t = t.Elem()
	}
	out := make(map[string]bool, t.NumField())
	for i := 0; i < t.NumField(); i++ {
		field := t.Field(i)
		tag := field.Tag.Get("json")
		if tag == "" || tag == "-" {
			continue
		}
		name := strings.Split(tag, ",")[0]
		if name != "" && name != "-" {
			out[name] = true
		}
	}
	return out
}
