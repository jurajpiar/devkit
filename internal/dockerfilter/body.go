package dockerfilter

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"reflect"
	"strings"
)

// MaxBody is the largest JSON body the filter reads.
const MaxBody = 4 << 20

// decodeStrict decodes body into v, a pointer to one of the mirror structs,
// as strictly as the filter needs: exactly one JSON value, every object key
// at every level spelt exactly as the daemon's field (Go's decoder, which
// the daemon uses, matches keys case-insensitively and takes the last of
// two duplicates; a key the filter read one way must never be read another
// way by the daemon), no duplicate key in any object, no field the mirror
// does not have, and every value of the field's type.
func decodeStrict(body []byte, v any) error {
	if len(bytes.TrimSpace(body)) == 0 {
		return errors.New("the body is empty")
	}
	dec := json.NewDecoder(bytes.NewReader(body))
	dec.UseNumber()
	w := walker{dec: dec}
	tok, err := dec.Token()
	if err != nil {
		return syntaxError("", err)
	}
	if tok != json.Delim('{') {
		return errors.New("the body must be a JSON object")
	}
	if err := w.valueTok(tok, reflect.TypeOf(v).Elem(), ""); err != nil {
		return err
	}
	if _, err := dec.Token(); err != io.EOF {
		return errors.New("the body holds more than one JSON value")
	}
	strict := json.NewDecoder(bytes.NewReader(body))
	strict.DisallowUnknownFields()
	if err := strict.Decode(v); err != nil {
		return fmt.Errorf("the body does not decode: %v", err)
	}
	return nil
}

type walker struct {
	dec *json.Decoder
}

var (
	unmarshalerType = reflect.TypeOf((*json.Unmarshaler)(nil)).Elem()
	rawMessageType  = reflect.TypeOf(json.RawMessage(nil))
)

func (w *walker) value(t reflect.Type, path string) error {
	tok, err := w.dec.Token()
	if err != nil {
		return syntaxError(path, err)
	}
	return w.valueTok(tok, t, path)
}

func syntaxError(path string, err error) error {
	if path == "" {
		return fmt.Errorf("the body is not valid JSON: %v", err)
	}
	return fmt.Errorf("the body is not valid JSON at %s: %v", path, err)
}

func (w *walker) valueTok(tok json.Token, t reflect.Type, path string) error {
	if tok == nil {
		return nil // null leaves any field at its zero value
	}
	for t.Kind() == reflect.Pointer {
		t = t.Elem()
	}
	if t == rawMessageType || reflect.PointerTo(t).Implements(unmarshalerType) {
		return w.skip(tok, path)
	}
	switch t.Kind() {
	case reflect.Struct:
		if tok != json.Delim('{') {
			return fmt.Errorf("%s must be an object", name(path))
		}
		fields := fieldsOf(t)
		seen := map[string]bool{}
		for w.dec.More() {
			k, err := w.key(path)
			if err != nil {
				return err
			}
			if seen[k] {
				return fmt.Errorf("the key %s appears twice", name(join(path, k)))
			}
			seen[k] = true
			ft, ok := fields[k]
			if !ok {
				return fmt.Errorf("unknown field %s", name(join(path, k)))
			}
			if err := w.value(ft, join(path, k)); err != nil {
				return err
			}
		}
		return w.end(path)
	case reflect.Map:
		if tok != json.Delim('{') {
			return fmt.Errorf("%s must be an object", name(path))
		}
		seen := map[string]bool{}
		for w.dec.More() {
			k, err := w.key(path)
			if err != nil {
				return err
			}
			if seen[k] {
				return fmt.Errorf("the key %s appears twice", name(join(path, k)))
			}
			seen[k] = true
			if err := w.value(t.Elem(), join(path, k)); err != nil {
				return err
			}
		}
		return w.end(path)
	case reflect.Slice, reflect.Array:
		if tok != json.Delim('[') {
			return fmt.Errorf("%s must be a list", name(path))
		}
		for i := 0; w.dec.More(); i++ {
			if err := w.value(t.Elem(), fmt.Sprintf("%s[%d]", path, i)); err != nil {
				return err
			}
		}
		return w.end(path)
	case reflect.Interface:
		return w.skip(tok, path)
	default:
		if _, ok := tok.(json.Delim); ok {
			return fmt.Errorf("%s must be a %s", name(path), t.Kind())
		}
		return nil // the typed decode checks the scalar's type
	}
}

// skip consumes a value the walker does not type, still refusing a
// duplicate key in any object inside it.
func (w *walker) skip(tok json.Token, path string) error {
	switch tok {
	case json.Delim('{'):
		seen := map[string]bool{}
		for w.dec.More() {
			k, err := w.key(path)
			if err != nil {
				return err
			}
			if seen[k] {
				return fmt.Errorf("the key %s appears twice", name(join(path, k)))
			}
			seen[k] = true
			next, err := w.dec.Token()
			if err != nil {
				return syntaxError(join(path, k), err)
			}
			if err := w.skip(next, join(path, k)); err != nil {
				return err
			}
		}
		return w.end(path)
	case json.Delim('['):
		for i := 0; w.dec.More(); i++ {
			next, err := w.dec.Token()
			if err != nil {
				return syntaxError(path, err)
			}
			if err := w.skip(next, fmt.Sprintf("%s[%d]", path, i)); err != nil {
				return err
			}
		}
		return w.end(path)
	}
	return nil
}

func (w *walker) key(path string) (string, error) {
	tok, err := w.dec.Token()
	if err != nil {
		return "", syntaxError(path, err)
	}
	k, ok := tok.(string)
	if !ok {
		return "", syntaxError(path, fmt.Errorf("unexpected %v", tok))
	}
	return k, nil
}

func (w *walker) end(path string) error {
	if _, err := w.dec.Token(); err != nil {
		return syntaxError(path, err)
	}
	return nil
}

func join(path, k string) string {
	if path == "" {
		return k
	}
	return path + "." + k
}

func name(path string) string {
	if path == "" {
		return "the body"
	}
	return path
}

// fieldsOf maps each JSON name of struct type t to its field's type, with
// embedded structs flattened as encoding/json flattens them.
func fieldsOf(t reflect.Type) map[string]reflect.Type {
	out := map[string]reflect.Type{}
	for i := 0; i < t.NumField(); i++ {
		f := t.Field(i)
		tag := f.Tag.Get("json")
		if tag == "-" {
			continue
		}
		n, _, _ := strings.Cut(tag, ",")
		if f.Anonymous && n == "" && f.Type.Kind() == reflect.Struct {
			for k, v := range fieldsOf(f.Type) {
				out[k] = v
			}
			continue
		}
		if !f.IsExported() {
			continue
		}
		if n == "" {
			n = f.Name
		}
		out[n] = f.Type
	}
	return out
}
