// SPDX-License-Identifier: AGPL-3.0-only

package pluginv1

// Hand-written next to the generated code: the messages that carry secret
// material zero it in place, so either side can wipe a message once it has
// been marshalled or consumed.

// WipeSecrets zeroes every field value.
func (x *ReadResponse) WipeSecrets() { wipeFields(x.GetFields()) }

// WipeSecrets zeroes every field value.
func (x *WriteRequest) WipeSecrets() { wipeFields(x.GetFields()) }

// WipeSecrets zeroes every credential value.
func (x *ConfigRequest) WipeSecrets() {
	for _, v := range x.GetSecrets() {
		clear(v)
	}
}

func wipeFields(fs []*Field) {
	for _, f := range fs {
		clear(f.GetValue())
	}
}
