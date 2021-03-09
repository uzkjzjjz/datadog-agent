// +build !linux

package kernel

import "fmt"

// PossibleCPUs returns the max number of CPUs a system may possibly have
// Logical CPU numbers must be of the form 0-n
func PossibleCPUs() (int, error) {
	return 0, fmt.Errorf("unsupported")
}
