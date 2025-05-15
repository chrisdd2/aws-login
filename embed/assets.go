package embed

import "embed"

//go:embed assets/**
var AssetsFs embed.FS

//go:embed cfn/*.template
var CloudFormationFs embed.FS
