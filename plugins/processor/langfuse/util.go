package langfuse

import (
	"encoding/json"
	"fmt"
	"strconv"
	"strings"
	"time"

	"go.opentelemetry.io/collector/pdata/pcommon"
)

// Convert hex string to appropriate byte array based on specified length
func hexToTraceID(hexStr string) ([16]byte, error) {
	var result [16]byte

	if hexStr == "" {
		return result, nil
	}

	// Ensure string length is 32 (16 bytes)
	if len(hexStr) != 32 {
		hexStr = strings.Repeat("0", 32-len(hexStr)) + hexStr
	}

	// Parse byte by byte
	for i := 0; i < 16; i++ {
		start := i * 2
		end := start + 2
		if end > len(hexStr) {
			end = len(hexStr)
		}

		b, err := strconv.ParseUint(hexStr[start:end], 16, 8)
		if err != nil {
			return result, err
		}

		result[i] = byte(b)
	}

	return result, nil
}

func hexToSpanID(hexStr string) ([8]byte, error) {
	var result [8]byte

	if hexStr == "" {
		return result, nil
	}

	// Ensure string length is 16 (8 bytes)
	if len(hexStr) != 16 {
		hexStr = strings.Repeat("0", 16-len(hexStr)) + hexStr
	}

	// Parse byte by byte
	for i := 0; i < 8; i++ {
		start := i * 2
		end := start + 2
		if end > len(hexStr) {
			end = len(hexStr)
		}

		b, err := strconv.ParseUint(hexStr[start:end], 16, 8)
		if err != nil {
			return result, err
		}

		result[i] = byte(b)
	}

	return result, nil
}

// Parse timestamp string to nanosecond timestamp
func parseTimestamp(tsStr string) uint64 {
	if tsStr == "" {
		return uint64(time.Now().UnixNano())
	}

	// Try parsing RFC3339 format
	if t, err := time.Parse(time.RFC3339Nano, tsStr); err == nil {
		return uint64(t.UnixNano())
	}

	// Try parsing scientific notation format
	var ts float64
	if _, err := fmt.Sscanf(tsStr, "%e", &ts); err == nil {
		return uint64(ts)
	}

	// Try parsing integer format
	if ts, err := strconv.ParseUint(tsStr, 10, 64); err == nil {
		// Check if it's a second-level timestamp (less than 10^12)
		if ts < 1_000_000_000_000 {
			return ts * 1_000_000_000 // Convert to nanoseconds
		}
		return ts
	}

	// Default to current time
	return uint64(time.Now().UnixNano())
}

// Add attributes to Span
func addAttributesToSpan(attrs pcommon.Map, values map[string]interface{}) {
	for k, v := range values {
		switch val := v.(type) {
		case string:
			attrs.PutStr(k, val)
		case bool:
			attrs.PutBool(k, val)
		case int:
			attrs.PutInt(k, int64(val))
		case int64:
			attrs.PutInt(k, val)
		case float64:
			attrs.PutDouble(k, val)
		case map[string]interface{}:
			jsonBytes, _ := json.Marshal(val)
			attrs.PutStr(k, string(jsonBytes))
		case []interface{}:
			jsonBytes, _ := json.Marshal(val)
			attrs.PutStr(k, string(jsonBytes))
		default:
			attrs.PutStr(k, fmt.Sprintf("%v", val))
		}
	}
}

// Extract token count from attributes
func getTokenCount(attrs map[string]interface{}, key string) (int64, bool) {
	if val, ok := attrs[key]; ok {
		switch v := val.(type) {
		case float64:
			return int64(v), true
		case int:
			return int64(v), true
		case int64:
			return v, true
		case string:
			if count, err := strconv.ParseInt(v, 10, 64); err == nil {
				return count, true
			}
		}
	}
	return 0, false
}

// Extract latency from attributes
func getLatency(attrs map[string]interface{}, key string) (float64, bool) {
	if val, ok := attrs[key]; ok {
		switch v := val.(type) {
		case float64:
			return v, true
		case int:
			return float64(v), true
		case int64:
			return float64(v), true
		case string:
			if latency, err := strconv.ParseFloat(v, 64); err == nil {
				return latency, true
			}
		}
	}
	return 0, false
}
