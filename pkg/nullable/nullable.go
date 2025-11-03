package nullable

import (
	"encoding/json"
)

// String represents a string that can be null in JSON
type String struct {
	Value *string
}

// MarshalJSON implements json.Marshaler
func (ns String) MarshalJSON() ([]byte, error) {
	if ns.Value == nil {
		return []byte("null"), nil
	}
	return json.Marshal(*ns.Value)
}

// UnmarshalJSON implements json.Unmarshaler
func (ns *String) UnmarshalJSON(data []byte) error {
	if string(data) == "null" {
		ns.Value = nil
		return nil
	}
	var s string
	if err := json.Unmarshal(data, &s); err != nil {
		return err
	}
	ns.Value = &s
	return nil
}

// Bool represents a boolean that can be null in JSON
type Bool struct {
	Value *bool
}

// MarshalJSON implements json.Marshaler
func (nb Bool) MarshalJSON() ([]byte, error) {
	if nb.Value == nil {
		return []byte("null"), nil
	}
	return json.Marshal(*nb.Value)
}

// UnmarshalJSON implements json.Unmarshaler
func (nb *Bool) UnmarshalJSON(data []byte) error {
	if string(data) == "null" {
		nb.Value = nil
		return nil
	}
	var b bool
	if err := json.Unmarshal(data, &b); err != nil {
		return err
	}
	nb.Value = &b
	return nil
}

// Helper functions

// NewString creates a String from a string
func NewString(s string) String {
	return String{Value: &s}
}

// NewStringPtr creates a String from a string pointer
func NewStringPtr(s *string) String {
	return String{Value: s}
}

// NewBool creates a Bool from a bool
func NewBool(b bool) Bool {
	return Bool{Value: &b}
}

// NewBoolPtr creates a Bool from a bool pointer
func NewBoolPtr(b *bool) Bool {
	return Bool{Value: b}
}
