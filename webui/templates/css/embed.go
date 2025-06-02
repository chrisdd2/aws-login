package css

import "embed"

//go:embed *.css
var CssFiles embed.FS
