package detect

import (
	"os"
	"regexp"
	"testing"
)

// Every file name Scan reads must be in MarkerFiles, or devkit clone would
// detect less than devkit init does on a checkout.
func TestMarkerFilesCoverScan(t *testing.T) {
	src, err := os.ReadFile("detect.go")
	if err != nil {
		t.Fatal(err)
	}
	listed := map[string]bool{}
	for _, m := range MarkerFiles {
		listed[m] = true
	}
	quoted := regexp.MustCompile(`"([.A-Za-z][A-Za-z0-9._-]*\.(?:json|toml|txt|py|lock|lockb|kts|gradle|xml|js|ts|ac|build|mod)|\.[a-z]+-version|rust-toolchain|Gemfile|Pipfile|CMakeLists\.txt)"`)
	for _, m := range quoted.FindAllStringSubmatch(string(src), -1) {
		if !listed[m[1]] {
			t.Errorf("%s is read by Scan but missing from MarkerFiles", m[1])
		}
	}
}
