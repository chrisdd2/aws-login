package embed

import "embed"

//go:embed assets/**
var AssetsFs embed.FS
