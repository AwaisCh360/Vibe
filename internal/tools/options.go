package internal

import "fmt"

// ApplyOptions takes base arguments for a command and appends any extra arguments
// provided in the options map under the "args" key. It also supports tool-specific 
// options like "timeout", "severity", etc., which can be extended in the future.
func ApplyOptions(baseArgs []string, options map[string]interface{}) []string {
	if options == nil {
		return baseArgs
	}
	
	// Generic argument injection
	if extraArgs, ok := options["args"].([]interface{}); ok {
		for _, arg := range extraArgs {
			baseArgs = append(baseArgs, fmt.Sprintf("%v", arg))
		}
	}
	
	return baseArgs
}
