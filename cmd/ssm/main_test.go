package main

import (
	"bytes"
	"encoding/json"
	"errors"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"testing"

	"github.com/chrisdd2/aws-login/blob"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestBlob(t *testing.T) {
	f, err := os.CreateTemp("", t.Name()+"*")
	require.NoError(t, err)
	testBinary := filepath.Join("", f.Name())
	if runtime.GOOS == "windows" {
		testBinary += ".exe"
	}
	f.Close()
	t.Logf("testBinary: %s\n", testBinary)

	cmd := exec.Command("go", "build", "-ldflags", "-s -w", "-o", testBinary)
	cmd.Env = append(os.Environ(), "CGO_ENABLED=0")
	require.NoError(t, cmd.Run())
	t.Cleanup(func() {
		os.Remove(testBinary)
	})

	buf, err := os.ReadFile(testBinary)
	require.NoError(t, err)
	params := Parameters{
		Text: "hi man",
	}
	payload, err := json.Marshal(&params)
	require.NoError(t, err)

	outData, err := blob.Patch(buf, string(payload))
	require.NoError(t, err)
	require.NoError(t, os.WriteFile(testBinary, outData, 0755))

	cmd = exec.Command(testBinary)
	outputStream := bytes.Buffer{}
	cmd.Stdout = &outputStream
	err = cmd.Run()
	require.Error(t, err)
	var exitError *exec.ExitError
	require.True(t, errors.As(err, &exitError))
	require.Equal(t, 1, exitError.ExitCode())

	output := outputStream.String()
	t.Logf("Output: %s\n", output)
	assert.Contains(t, output, "hi man")
}
