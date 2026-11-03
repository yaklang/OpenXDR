package temporal

import (
	"github.com/google/uuid"
	"openxdr/server/internal/authfields"
	"strings"
)

const sourceIPPrefix = "asset-source-ip:"

// AssetSourceIPEntity 固定到目标资产，防止相同来源在不同主机或不同组之间凑阈值。
func AssetSourceIPEntity(asset uuid.UUID, ip string) string {
	ip = authfields.CanonicalIP(ip)
	if asset == uuid.Nil || ip == "" {
		return ""
	}
	return sourceIPPrefix + asset.String() + "|" + ip
}

func IsSourceIPEntity(entity string) bool { return strings.HasPrefix(entity, sourceIPPrefix) }
