package dockerfilter

import (
	"bytes"
	"encoding/json"
)

// Each decoder reads a body strictly into its mirror struct, validates
// it, and returns the struct encoded again: what the daemon receives is
// exactly what was validated.

func decodeCreate(f *Filter, body []byte) ([]byte, error) {
	var r CreateRequest
	if err := decodeStrict(body, &r); err != nil {
		return nil, err
	}
	if err := f.validateCreate(&r); err != nil {
		return nil, err
	}
	return json.Marshal(&r)
}

func decodeExec(f *Filter, body []byte) ([]byte, error) {
	var e ExecConfig
	if err := decodeStrict(body, &e); err != nil {
		return nil, err
	}
	if err := f.validateExec(&e); err != nil {
		return nil, err
	}
	return json.Marshal(&e)
}

func decodeExecStart(_ *Filter, body []byte) ([]byte, error) {
	var e ExecStart
	if err := decodeStrict(body, &e); err != nil {
		return nil, err
	}
	return json.Marshal(&e)
}

func decodeCommit(_ *Filter, body []byte) ([]byte, error) {
	// The client sends null when docker commit sets nothing.
	if string(bytes.TrimSpace(body)) == "null" {
		return []byte("null"), nil
	}
	var c *ContainerConfig
	if err := decodeStrict(body, &c); err != nil {
		return nil, err
	}
	return json.Marshal(c)
}

func decodeNetworkCreate(f *Filter, body []byte) ([]byte, error) {
	var n NetworkCreate
	if err := decodeStrict(body, &n); err != nil {
		return nil, err
	}
	if err := f.validateNetworkCreate(&n); err != nil {
		return nil, err
	}
	return json.Marshal(&n)
}

func decodeNetworkConnect(f *Filter, body []byte) ([]byte, error) {
	var n NetworkConnect
	if err := decodeStrict(body, &n); err != nil {
		return nil, err
	}
	if err := f.validateNetworkConnect(&n); err != nil {
		return nil, err
	}
	return json.Marshal(&n)
}

func decodeNetworkDisconnect(_ *Filter, body []byte) ([]byte, error) {
	var n NetworkDisconnect
	if err := decodeStrict(body, &n); err != nil {
		return nil, err
	}
	return json.Marshal(&n)
}

func decodeVolumeCreate(f *Filter, body []byte) ([]byte, error) {
	var v VolumeCreate
	if err := decodeStrict(body, &v); err != nil {
		return nil, err
	}
	if err := f.validateVolumeCreate(&v); err != nil {
		return nil, err
	}
	return json.Marshal(&v)
}
