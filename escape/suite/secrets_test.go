// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Omkhar Arasaratnam

package suite

import (
	"strings"
	"testing"
)

func TestFindSecrets(t *testing.T) {
	a, b := secretPrefix+strings.Repeat("a", secretHex), secretPrefix+strings.Repeat("b", secretHex)
	cases := []struct{ in, want string }{{"", ""}, {secretPrefix, ""}, {a, a}, {"KEY=" + a + "\x00PATH=/bin", a}, {a + "0", ""}, {a[:secretLen-1], ""}, {a[:secretLen-1] + "G", ""}, {a + "-" + b + " " + a, a + " " + b}, {secretPrefix + secretPrefix + a[len(secretPrefix):], a}, {strings.ToUpper(a), ""}} // one hex digit too many: not the secret's shape; one too few; not hex; each once, in order; a prefix inside a prefix; upper-case hex is not what the runner makes
	for _, c := range cases {
		if got := strings.Join(findSecrets([]byte(c.in)), " "); got != c.want {
			t.Errorf("findSecrets(%q) = %q, want %q", c.in, got, c.want)
		}
	}
	if v := NewSecret(withSecret).Value; len(v) != secretLen || len(findSecrets([]byte("x="+v+"\n"))) != 1 {
		t.Errorf("NewSecret made %q, which the probe would not find", v)
	}
}
