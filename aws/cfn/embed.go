package cfn

import "embed"

//go:embed *.template
var CloudFormationFs embed.FS
