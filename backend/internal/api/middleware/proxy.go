package middleware

import (
	"fmt"
	"net/netip"

	"github.com/gin-gonic/gin"
)

// ConfigureTrustedProxies uses Gin's source-address parser with an explicit trust boundary.
func ConfigureTrustedProxies(engine *gin.Engine, proxies []string) error {
	for _, value := range proxies {
		if prefix, err := netip.ParsePrefix(value); err == nil && prefix.Bits() == 0 {
			return fmt.Errorf("trusted proxies must not include all addresses")
		}
	}
	return engine.SetTrustedProxies(proxies)
}
