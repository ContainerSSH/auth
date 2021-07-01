module github.com/containerssh/auth/v2

go 1.16

require (
	github.com/containerssh/geoip v1.0.0
	github.com/containerssh/http v1.0.2
	github.com/containerssh/log v1.0.0
	github.com/containerssh/metrics v1.0.0
	github.com/containerssh/service v1.0.0
	github.com/stretchr/testify v1.7.0
)

// Fixes CVE-2019-11254
replace (
	gopkg.in/yaml.v2 v2.2.0 => gopkg.in/yaml.v2 v2.2.8
	gopkg.in/yaml.v2 v2.2.1 => gopkg.in/yaml.v2 v2.2.8
	gopkg.in/yaml.v2 v2.2.2 => gopkg.in/yaml.v2 v2.2.8
	gopkg.in/yaml.v2 v2.2.3 => gopkg.in/yaml.v2 v2.2.8
	gopkg.in/yaml.v2 v2.2.4 => gopkg.in/yaml.v2 v2.2.8
	gopkg.in/yaml.v2 v2.2.5 => gopkg.in/yaml.v2 v2.2.8
	gopkg.in/yaml.v2 v2.2.6 => gopkg.in/yaml.v2 v2.2.8
	gopkg.in/yaml.v2 v2.2.7 => gopkg.in/yaml.v2 v2.2.8
)

replace github.com/containerssh/http v1.0.2 => ../http