package store

import "encoding/json"

func isJSON(b []byte) bool {
	if len(b) == 0 {
		return false
	}
	return json.Valid(b)
}

// jsonString wraps arbitrary bytes as a JSON string so they can be stored in a
// jsonb column. Used for dead-lettered payloads, which by definition may be
// anything at all.
func jsonString(s string) []byte {
	b, err := json.Marshal(s)
	if err != nil {
		// json.Marshal of a string cannot fail; invalid UTF-8 is replaced.
		return []byte(`"<unencodable payload>"`)
	}
	return b
}
